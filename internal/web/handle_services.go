package web

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"lantern/internal/store"
	"lantern/internal/util"
)

// cfOpTimeout bounds Cloudflare API work triggered by a web request. Deletion
// stays synchronous so the UI can report failure, but it must not hang on a
// slow API.
var cfOpTimeout = 10 * time.Second

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.GetAllServices())
}

type createServiceRequest struct {
	DiscoveredID string // optional: assign from discovered
	Name         string
	Subdomain    string
	Target       string // required if not from discovered
	Category     string
	Tunnel       bool   // route via CF tunnel instead of A record
	DirectOnly   bool   // no subdomain/DNS; link directly to target
	SkipHealth   bool   // skip health check polling
	HostMode     string // "" = auto, "client", "backend"
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	const maxUpload = 5 << 20 // 5 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	if err := r.ParseMultipartForm(maxUpload); err != nil { //nolint:gosec // body bounded by MaxBytesReader above
		if err := r.ParseForm(); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid form data")
			return
		}
	}
	var req createServiceRequest
	req.DiscoveredID = r.FormValue("discovered_id")
	req.Name = r.FormValue("name")
	req.Subdomain = r.FormValue("subdomain")
	req.Target = r.FormValue("target")
	req.Category = r.FormValue("category")
	req.Tunnel = util.ParseFormBool(r.FormValue("tunnel"))
	req.DirectOnly = util.ParseFormBool(r.FormValue("direct_only"))
	req.SkipHealth = util.ParseFormBool(r.FormValue("skip_health"))
	req.HostMode = cleanHostMode(r.FormValue("host_mode"))

	// Read uploaded icon if provided (stored as a file after the service ID is known).
	var uploadedIconData []byte
	if r.MultipartForm != nil {
		if fh := r.MultipartForm.File["icon"]; len(fh) > 0 {
			f, err := fh[0].Open()
			if err == nil {
				defer func() { _ = f.Close() }()
				data, err := io.ReadAll(io.LimitReader(f, 512*1024))
				if err == nil && len(data) > 0 {
					uploadedIconData = data
				}
			}
		}
	}
	req.Subdomain = util.SanitiseSubdomain(req.Subdomain)
	if !req.DirectOnly {
		if req.Subdomain == "" {
			errorResponse(w, http.StatusBadRequest, "subdomain is required")
			return
		}
		if util.IsReservedSubdomain(req.Subdomain) {
			errorResponse(w, http.StatusBadRequest, "subdomain is reserved")
			return
		}
		if s.store.GetServiceBySubdomain(req.Subdomain) != nil {
			errorResponse(w, http.StatusConflict, "subdomain already assigned")
			return
		}
	}

	target := req.Target
	name := req.Name
	source := store.SourceManual
	var containerID string
	var containerName string
	var discoveredIcon string

	if req.DiscoveredID != "" {
		disc := s.store.GetDiscoveredByID(req.DiscoveredID)
		if disc == nil {
			errorResponse(w, http.StatusNotFound, "discovered service not found")
			return
		}
		scheme := "http"
		if util.IsHTTPSPort(disc.Port) {
			scheme = "https"
		}
		target = fmt.Sprintf("%s://%s:%d", scheme, disc.IP, disc.Port)
		if name == "" {
			name = disc.Title
		}
		source = disc.Source
		containerID = disc.ContainerID
		containerName = disc.ContainerName
		discoveredIcon = disc.Icon
	}

	if target == "" {
		errorResponse(w, http.StatusBadRequest, "target is required")
		return
	}
	if name == "" {
		name = req.Subdomain
	}

	svcID := util.NewID()
	subdomain := req.Subdomain
	if req.DirectOnly {
		subdomain = "_direct_" + svcID
	}

	maxOrder := 0
	for _, existing := range s.store.GetAllServices() {
		if existing.Order > maxOrder {
			maxOrder = existing.Order
		}
	}

	// Determine icon source: uploaded file > discovered icon > empty.
	icon := ""
	if len(uploadedIconData) > 0 {
		icon = store.IconFile // written to disk below after svcID is set
	} else if discoveredIcon != "" {
		icon = discoveredIcon
	}

	svc := &store.Service{
		ID:            svcID,
		Name:          name,
		Subdomain:     subdomain,
		Target:        target,
		Icon:          icon,
		Category:      req.Category,
		Source:        source,
		ContainerID:   containerID,
		ContainerName: containerName,
		DirectOnly:    req.DirectOnly,
		SkipHealth:    req.SkipHealth,
		HostMode:      req.HostMode,
		Order:         maxOrder + 1,
		CreatedAt:     time.Now(),
	}

	// Create tunnel route or DNS A record based on per-service choice.
	// reconcileDNS with a zero old state handles creation; direct-only is a no-op.
	want := dnsState{
		Subdomain:  subdomain,
		DirectOnly: req.DirectOnly,
		Tunnel:     req.Tunnel,
	}

	// Bound all Cloudflare work in this request so a slow API cannot hold the
	// form open indefinitely.
	opCtx, cancel := context.WithTimeout(r.Context(), cfOpTimeout)
	defer cancel()

	if !req.DirectOnly && s.cfg.Domain != "" {
		host := subdomain + "." + s.cfg.Domain
		forceTunnel, conflictTarget, err := s.existingCNAME(opCtx, host, req.Tunnel)
		switch {
		case err != nil:
			log.Printf("web: create service %q: %v", subdomain, err) //nolint:gosec // subdomain is sanitised above
			errorResponse(w, http.StatusBadGateway, err.Error())
			return
		case conflictTarget != "":
			errorResponse(w, http.StatusConflict, fmt.Sprintf(
				"%s is already a CNAME to %s; tick Route via Tunnel to take it over, or remove the record in Cloudflare.",
				host, conflictTarget))
			return
		case forceTunnel:
			// The hostname already routes through our tunnel (a leftover from
			// a previous remove/re-add). Adopt it instead of fighting the CNAME
			// with a new A record.
			req.Tunnel = true
			want.Tunnel = true
		}
	}

	dnsID, tunnelRouteID, err := s.reconcileDNS(opCtx, dnsState{DirectOnly: true}, want)
	if err != nil {
		log.Printf("web: create DNS %q: %v", subdomain, err) //nolint:gosec // subdomain is sanitised above
		errorResponse(w, http.StatusBadGateway, fmt.Sprintf("Cloudflare: %v", err))
		return
	}
	svc.DNSRecordID, svc.TunnelRouteID = dnsID, tunnelRouteID

	// Write uploaded icon file now that svcID is known.
	if len(uploadedIconData) > 0 {
		if err := s.store.WriteIcon(svcID, uploadedIconData); err != nil {
			log.Printf("web: write icon %s: %v", svcID, err)
			svc.Icon = "" // don't persist "file" marker if write failed
		}
	}

	s.store.AddService(svc)
	if req.DiscoveredID != "" {
		// Copy icon file from discovered service to new service.
		if discoveredIcon == store.IconFile {
			if data, err := s.store.ReadIcon(req.DiscoveredID); err == nil {
				_ = s.store.WriteIcon(svcID, data)
			}
		}
		s.store.RemoveDiscovered(req.DiscoveredID)
	}
	s.save()

	// Asynchronously fetch favicon if no icon is set yet.
	if svc.Icon == "" {
		go func(id string) { //nolint:gosec,contextcheck // intentional background task with its own timeout; request context would be cancelled before fetch completes
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if !util.FetchAndWriteFavicon(ctx, s.store, id) {
				return
			}
			if existing := s.store.GetServiceByID(id); existing != nil {
				updated := *existing
				updated.Icon = store.IconFile
				s.store.UpdateService(id, &updated)
				s.save()
			}
		}(svc.ID)
	}

	toastTrigger(w, "Service added", "refreshServicesTable", "refreshDiscovered")
	w.WriteHeader(http.StatusNoContent)
}

type updateServiceRequest struct {
	Name       string
	Subdomain  string
	Target     string
	Category   string
	Icon       *string // nil = keep existing; "" = clear; non-empty = set
	Tunnel     *bool   // nil = keep existing; true/false = enable/disable
	SkipHealth *bool   // nil = keep existing; true/false = skip health check
	HostMode   *string // nil = keep existing; "" = auto, "client", "backend"
	DirectOnly *bool   // nil = keep existing; true/false = direct link only
}

// dnsState captures the DNS/tunnel configuration of a service, used as input and output for reconcileDNS.
type dnsState struct {
	Subdomain     string
	DirectOnly    bool
	Tunnel        bool // true when routed via CF tunnel (TunnelRouteID != "")
	DNSRecordID   string
	TunnelRouteID string
}

type dnsMode int

const (
	modeDirect  dnsMode = iota // DirectOnly=true; no DNS record
	modeARecord                // A record pointing to ServerIP
	modeTunnel                 // CNAME routed via Cloudflare tunnel
)

func (d dnsState) mode() dnsMode {
	switch {
	case d.DirectOnly:
		return modeDirect
	case d.Tunnel:
		return modeTunnel
	default:
		return modeARecord
	}
}

type dnsAction int

const (
	dnsNoop          dnsAction = iota
	dnsCreateA                 // create a new A record
	dnsDeleteAll               // remove existing DNS record or tunnel route
	dnsSwapA                   // delete old A record, create new one
	dnsCreateTunnel            // add a new tunnel route
	dnsAToTunnel               // delete A record then add tunnel route
	dnsTunnelToA               // remove tunnel route then create A record
	dnsReplaceTunnel           // replace tunnel route (subdomain changed)
)

// existingCNAME inspects the DNS record already at host before a service is
// created or renamed into A-record mode. It reports forceTunnel when the record
// is a CNAME pointing at this Lantern instance's tunnel (which should be
// adopted even if the form did not ask for tunnel mode), conflictTarget when a
// CNAME points somewhere else and the caller did not explicitly request tunnel
// mode, and an error when the lookup itself fails.
func (s *Server) existingCNAME(ctx context.Context, host string, explicitTunnel bool) (forceTunnel bool, conflictTarget string, err error) {
	if !s.cf.TunnelEnabled() {
		return false, "", nil
	}
	recordID, target, ours, err := s.cf.FindTunnelCNAME(ctx, host)
	if err != nil {
		return false, "", fmt.Errorf("check Cloudflare for %s: %w", host, err)
	}
	if ours {
		return true, "", nil
	}
	if recordID != "" && target != "" && !explicitTunnel {
		return false, target, nil
	}
	return false, "", nil
}

// planDNS is a pure function that maps old and new DNS states to the action needed.
func planDNS(old, want dnsState) dnsAction {
	switch old.mode() {
	case modeDirect:
		switch want.mode() {
		case modeDirect:
			return dnsNoop
		case modeARecord:
			return dnsCreateA
		case modeTunnel:
			return dnsCreateTunnel
		}
	case modeARecord:
		switch want.mode() {
		case modeDirect:
			return dnsDeleteAll
		case modeARecord:
			if want.Subdomain != old.Subdomain {
				return dnsSwapA
			}
			return dnsNoop
		case modeTunnel:
			return dnsAToTunnel
		}
	case modeTunnel:
		switch want.mode() {
		case modeDirect:
			return dnsDeleteAll
		case modeARecord:
			return dnsTunnelToA
		case modeTunnel:
			if want.Subdomain != old.Subdomain {
				return dnsReplaceTunnel
			}
			return dnsNoop
		}
	}
	return dnsNoop
}

// reconcileDNS applies the necessary Cloudflare API calls to transition from old to want.
// It returns the resulting DNSRecordID and TunnelRouteID to store on the service.
// A non-nil error means the transition failed and the caller must not persist
// the new state; the periodic sync will restore the old one.
func (s *Server) reconcileDNS(ctx context.Context, old, want dnsState) (dnsID, tunnelRouteID string, err error) {
	oldHostname := old.Subdomain + "." + s.cfg.Domain
	newHostname := want.Subdomain + "." + s.cfg.Domain

	switch planDNS(old, want) {
	case dnsNoop:
		return old.DNSRecordID, old.TunnelRouteID, nil

	case dnsCreateA:
		if s.cfg.ServerIP == "" {
			return "", "", nil
		}
		id, err := s.cf.UpsertARecord(ctx, newHostname, s.cfg.ServerIP)
		if err != nil {
			return "", "", fmt.Errorf("create DNS record %s: %w", newHostname, err)
		}
		return id, "", nil

	case dnsDeleteAll:
		if old.TunnelRouteID != "" {
			if err := s.cf.RemoveTunnelRoute(ctx, old.TunnelRouteID, old.DNSRecordID); err != nil {
				return "", "", fmt.Errorf("remove tunnel route %s: %w", old.TunnelRouteID, err)
			}
		} else if old.DNSRecordID != "" {
			if err := s.cf.DeleteRecord(ctx, old.DNSRecordID); err != nil {
				return "", "", fmt.Errorf("delete DNS record %s: %w", oldHostname, err)
			}
		}
		return "", "", nil

	case dnsSwapA:
		if old.DNSRecordID != "" {
			if err := s.cf.DeleteRecord(ctx, old.DNSRecordID); err != nil {
				return "", "", fmt.Errorf("delete DNS record %s: %w", oldHostname, err)
			}
		}
		if s.cfg.ServerIP == "" {
			return "", "", nil
		}
		id, err := s.cf.UpsertARecord(ctx, newHostname, s.cfg.ServerIP)
		if err != nil {
			return "", "", fmt.Errorf("create DNS record %s: %w", newHostname, err)
		}
		return id, "", nil

	case dnsCreateTunnel, dnsAToTunnel:
		if !s.cf.TunnelEnabled() {
			return "", "", errors.New("tunnel is not configured")
		}
		// A rename (A record at oldHostname → tunnel at newHostname) must
		// remove the old A record. When only the mode changes, AddTunnelRoute
		// rewrites the existing record at the same hostname in place.
		if oldHostname != newHostname && old.DNSRecordID != "" {
			if err := s.cf.DeleteRecord(ctx, old.DNSRecordID); err != nil {
				return "", "", fmt.Errorf("delete DNS record %s: %w", oldHostname, err)
			}
		}
		id, err := s.cf.AddTunnelRoute(ctx, newHostname)
		if err != nil {
			return "", "", fmt.Errorf("add tunnel route %s: %w", newHostname, err)
		}
		return id, newHostname, nil

	case dnsTunnelToA:
		if err := s.cf.RemoveTunnelRoute(ctx, old.TunnelRouteID, old.DNSRecordID); err != nil {
			return "", "", fmt.Errorf("remove tunnel route %s: %w", old.TunnelRouteID, err)
		}
		if s.cfg.ServerIP == "" {
			return "", "", nil
		}
		id, err := s.cf.UpsertARecord(ctx, newHostname, s.cfg.ServerIP)
		if err != nil {
			return "", "", fmt.Errorf("create DNS record %s: %w", newHostname, err)
		}
		return id, "", nil

	case dnsReplaceTunnel:
		if !s.cf.TunnelEnabled() {
			return "", "", errors.New("tunnel is not configured")
		}
		id, err := s.cf.ReplaceTunnelRoute(ctx, oldHostname, newHostname, old.DNSRecordID)
		if err != nil {
			return "", "", fmt.Errorf("replace tunnel route %s→%s: %w", oldHostname, newHostname, err)
		}
		return id, newHostname, nil
	}

	return "", "", nil
}

func (s *Server) updateService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svc := s.store.GetServiceByID(id)
	if svc == nil {
		errorResponse(w, http.StatusNotFound, "service not found")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid form data")
		return
	}
	var req updateServiceRequest
	req.Name = r.FormValue("name")
	req.Subdomain = r.FormValue("subdomain")
	req.Target = r.FormValue("target")
	req.Category = r.FormValue("category")
	// icon: present in form only when explicitly changed
	if r.FormValue("icon_present") == "1" {
		iconVal := r.FormValue("icon")
		req.Icon = &iconVal
	}
	// tunnel checkbox: only meaningful when the form includes a tunnel_present hidden field
	if r.FormValue("tunnel_present") == "1" {
		v := util.ParseFormBool(r.FormValue("tunnel"))
		req.Tunnel = &v
	}
	// skip_health checkbox: only meaningful when the form includes a skip_health_present hidden field
	if r.FormValue("skip_health_present") == "1" {
		v := util.ParseFormBool(r.FormValue("skip_health"))
		req.SkipHealth = &v
	}
	// host_mode select: only meaningful when the form includes a host_mode_present hidden field
	if r.FormValue("host_mode_present") == "1" {
		v := cleanHostMode(r.FormValue("host_mode"))
		req.HostMode = &v
	}
	// direct_only checkbox: only meaningful when the form includes a direct_only_present hidden field
	if r.FormValue("direct_only_present") == "1" {
		v := util.ParseFormBool(r.FormValue("direct_only"))
		req.DirectOnly = &v
	}

	oldSub := svc.Subdomain
	oldDNSID := svc.DNSRecordID
	oldTunnelRoute := svc.TunnelRouteID

	icon := svc.Icon
	if req.Icon != nil {
		icon = *req.Icon
	}
	skipHealth := svc.SkipHealth
	if req.SkipHealth != nil {
		skipHealth = *req.SkipHealth
	}
	hostMode := svc.HostMode
	if req.HostMode != nil {
		hostMode = *req.HostMode
	}
	directOnly := svc.DirectOnly
	if req.DirectOnly != nil {
		directOnly = *req.DirectOnly
	}
	newTarget := cmp.Or(req.Target, svc.Target)

	// Determine the new subdomain key.
	// When direct-only, use a synthetic key so the store map stays unique.
	// When switching off direct-only, the caller must supply a real subdomain.
	var newSub string
	if directOnly {
		// Preserve existing _direct_ key, or generate one if switching to direct.
		if svc.DirectOnly {
			newSub = oldSub // keep existing synthetic key
		} else {
			newSub = "_direct_" + svc.ID
		}
	} else {
		newSub = util.SanitiseSubdomain(req.Subdomain)
		if newSub == "" {
			newSub = oldSub
		}
		if util.IsReservedSubdomain(newSub) {
			errorResponse(w, http.StatusBadRequest, "subdomain is reserved")
			return
		}
	}

	updated := &store.Service{
		ID:            svc.ID,
		Name:          cmp.Or(req.Name, svc.Name),
		Subdomain:     newSub,
		Target:        newTarget,
		Icon:          icon,
		Category:      req.Category,
		Order:         svc.Order,
		Source:        svc.Source,
		ContainerID:   svc.ContainerID,
		ContainerName: svc.ContainerName,
		SkipHealth:    skipHealth,
		HostMode:      hostMode,
		DirectOnly:    directOnly,
		CreatedAt:     svc.CreatedAt,
	}

	// Reconcile DNS/tunnel state based on old and new configurations.
	wantTunnel := oldTunnelRoute != ""
	if req.Tunnel != nil {
		wantTunnel = *req.Tunnel
	}

	// Bound all Cloudflare work in this request so a slow API cannot hold the
	// form open indefinitely.
	opCtx, cancel := context.WithTimeout(r.Context(), cfOpTimeout)
	defer cancel()

	// A rename (or a direct → A transition) must not collide with a CNAME left
	// at the new hostname. A CNAME at our own tunnel is adopted even when the
	// box was unticked; a foreign one is a conflict. An intentional untick on
	// the same hostname still flows through dnsTunnelToA.
	if !directOnly && !wantTunnel && s.cfg.Domain != "" && newSub != oldSub {
		host := newSub + "." + s.cfg.Domain
		forceTunnel, conflictTarget, err := s.existingCNAME(opCtx, host, false)
		switch {
		case err != nil:
			log.Printf("web: update service %q: %v", id, err) //nolint:gosec // path value, logged for diagnosis
			errorResponse(w, http.StatusBadGateway, err.Error())
			return
		case conflictTarget != "":
			errorResponse(w, http.StatusConflict, fmt.Sprintf(
				"%s is already a CNAME to %s; tick Route via Tunnel to take it over, or remove the record in Cloudflare.",
				host, conflictTarget))
			return
		case forceTunnel:
			wantTunnel = true
		}
	}

	old := dnsState{
		Subdomain:     oldSub,
		DirectOnly:    svc.DirectOnly,
		Tunnel:        oldTunnelRoute != "",
		DNSRecordID:   oldDNSID,
		TunnelRouteID: oldTunnelRoute,
	}
	want := dnsState{
		Subdomain:  newSub,
		DirectOnly: directOnly,
		Tunnel:     wantTunnel,
	}
	dnsID, tunnelRouteID, err := s.reconcileDNS(opCtx, old, want)
	if err != nil {
		log.Printf("web: update DNS %q: %v", newSub, err) //nolint:gosec // subdomain is sanitised above
		errorResponse(w, http.StatusBadGateway, fmt.Sprintf("Cloudflare: %v", err))
		return
	}
	updated.DNSRecordID, updated.TunnelRouteID = dnsID, tunnelRouteID

	s.store.UpdateService(id, updated)
	s.save()
	toastTrigger(w, "Service updated", "refreshServicesTable")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svc := s.store.GetServiceByID(id)
	if svc == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, dnsID, tunnelRoute := s.store.DeleteService(id)

	// Cleanup is bounded so a slow Cloudflare API cannot hang the request, and
	// WithoutCancel keeps it running if the browser goes away after the local
	// delete has already happened. A failure is reported to the user instead of
	// being silently swallowed.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), cfOpTimeout)
	defer cancel()

	var cleanupErr error
	if tunnelRoute != "" {
		cleanupErr = s.cf.RemoveTunnelRoute(cleanupCtx, tunnelRoute, dnsID)
	} else if dnsID != "" {
		cleanupErr = s.cf.DeleteRecord(cleanupCtx, dnsID)
	}
	if cleanupErr != nil {
		log.Printf("web: delete service %q: Cloudflare cleanup: %v", id, cleanupErr) //nolint:gosec // path value, logged for diagnosis
	}

	var extra []string
	if svc.Source == store.SourceDocker {
		// Send the container back to Discovered so it can be re-assigned.
		ip, port := util.SplitTarget(svc.Target)
		if !s.store.IsIgnored(ip, port) {
			s.store.AddDiscovered(&store.DiscoveredService{
				ID:                 util.NewID(),
				IP:                 ip,
				Port:               port,
				Title:              svc.Name,
				Source:             store.SourceDocker,
				ContainerID:        svc.ContainerID,
				ContainerName:      svc.ContainerName,
				SuggestedSubdomain: svc.Subdomain,
				DiscoveredAt:       time.Now(),
			})
		}
		extra = append(extra, "refreshDiscovered")
	}
	if cleanupErr != nil {
		toastTriggerType(w, "Service removed, but Cloudflare cleanup failed: "+cleanupErr.Error(), "error", extra...)
	} else {
		toastTrigger(w, "Service removed", extra...)
	}
	s.store.DeleteIcon(id)
	s.save()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) uploadServiceIcon(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svc := s.store.GetServiceByID(id)
	if svc == nil {
		apiError(w, http.StatusNotFound, "service not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024)
	if err := r.ParseMultipartForm(512 * 1024); err != nil { //nolint:gosec // body bounded by MaxBytesReader above
		apiError(w, http.StatusBadRequest, "file too large or invalid")
		return
	}
	file, _, err := r.FormFile("icon")
	if err != nil {
		apiError(w, http.StatusBadRequest, "icon file required")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, 512*1024))
	if err != nil || len(data) == 0 {
		apiError(w, http.StatusBadRequest, "could not read file")
		return
	}
	if err := s.store.WriteIcon(id, data); err != nil {
		apiError(w, http.StatusInternalServerError, "could not save icon")
		return
	}
	s.applyServiceIcon(w, svc, store.IconFile)
}

func (s *Server) clearServiceIcon(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svc := s.store.GetServiceByID(id)
	if svc == nil {
		apiError(w, http.StatusNotFound, "service not found")
		return
	}
	s.store.DeleteIcon(id)
	s.applyServiceIcon(w, svc, "")
}

func (s *Server) pullServiceFavicon(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svc := s.store.GetServiceByID(id)
	if svc == nil {
		apiError(w, http.StatusNotFound, "service not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	data := util.FetchFaviconForTarget(ctx, svc.Target)
	if len(data) == 0 {
		errorResponse(w, http.StatusUnprocessableEntity, "no favicon found")
		return
	}
	if err := s.store.WriteIcon(id, data); err != nil {
		errorResponse(w, http.StatusInternalServerError, "could not save favicon")
		return
	}
	s.applyServiceIcon(w, svc, store.IconFile)
}

// applyServiceIcon sets a service's Icon field, saves, and renders the icon preview.
func (s *Server) applyServiceIcon(w http.ResponseWriter, svc *store.Service, icon string) {
	updated := *svc
	updated.Icon = icon
	s.store.UpdateService(svc.ID, &updated)
	s.save()
	renderTemplate(w, "icon-preview.html", &updated)
}

// cleanHostMode normalises the Host-header mode form value ("" = auto).
func cleanHostMode(v string) string {
	switch v {
	case "client", "backend":
		return v
	}
	return ""
}
