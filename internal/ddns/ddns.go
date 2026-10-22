package ddns

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"lantern/internal/cf"
	"lantern/internal/config"
	"lantern/internal/store"
)

var ipifyURL = "https://api.ipify.org"

var ipifyClient = &http.Client{Timeout: 10 * time.Second}

// Manager periodically checks the public IP and updates Cloudflare records.
type Manager struct {
	cfg   *config.Config
	store *store.Store
	cf    *cf.Client
}

func New(cfg *config.Config, st *store.Store, cfClient *cf.Client) *Manager {
	return &Manager{cfg: cfg, store: st, cf: cfClient}
}

// Run keeps Cloudflare in step with reality: on startup and every 5 minutes it
// re-checks the public IP for DDNS domains and re-asserts every service's DNS record.
func (m *Manager) Run(ctx context.Context) {
	m.checkAndUpdate(ctx)
	m.SyncServices(ctx)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAndUpdate(ctx)
			m.SyncServices(ctx)
		}
	}
}

// checkAndUpdate verifies every DDNS record against the current public IP on
// every call. The stored IP only advances once all records are correct, so any
// failure is retried on the next tick.
func (m *Manager) checkAndUpdate(ctx context.Context) {
	domains := m.store.GetDDNSDomains()
	if len(domains) == 0 {
		return
	}

	ip, err := getPublicIP(ctx)
	if err != nil {
		log.Printf("ddns: get public IP: %v", err)
		return
	}
	if ip == "" {
		log.Printf("ddns: empty public IP response — skipping")
		return
	}

	if previous := m.store.GetPublicIP(); ip != previous {
		log.Printf("ddns: public IP changed %q → %q", previous, ip)
	}

	failed := false
	changed := false
	for _, domain := range domains {
		recordID, current, err := m.cf.FindRecord(ctx, domain)
		if err != nil {
			log.Printf("ddns: find record %s: %v", domain, err)
			failed = true
			continue
		}
		if recordID == "" {
			id, err := m.cf.CreateRecord(ctx, domain, ip)
			if err != nil {
				log.Printf("ddns: create record %s: %v", domain, err)
				failed = true
			} else {
				log.Printf("ddns: created %s → %s (id %s)", domain, ip, id)
				changed = true
			}
			continue
		}
		if current == ip {
			continue
		}
		if err := m.cf.UpdateRecord(ctx, recordID, ip); err != nil {
			log.Printf("ddns: update %s: %v", domain, err)
			failed = true
		} else {
			log.Printf("ddns: updated %s → %s", domain, ip)
			changed = true
		}
	}
	if !failed {
		m.store.SetPublicIP(ip)
	}
	if changed || !failed {
		m.store.SaveLog("ddns")
	}
}

// SyncServices re-asserts the Cloudflare record of every proxied service
// (and lantern.<domain>): missing or wrong records are created or corrected,
// and stored record IDs are refreshed. No-op without Cloudflare credentials,
// a domain, or (for A records) a server IP.
func (m *Manager) SyncServices(ctx context.Context) {
	if m.cfg.Domain == "" {
		return
	}
	changed := false
	if m.cfg.ServerIP != "" {
		if _, err := m.cf.UpsertARecord(ctx, "lantern."+m.cfg.Domain, m.cfg.ServerIP); err != nil {
			log.Printf("dns: sync lantern.%s: %v", m.cfg.Domain, err)
		}
	}
	services := m.store.GetAllServices()

	// Tunnel ingress rules must point at Lantern (not at the backend), so every
	// tunneled request goes through the proxy. This also migrates old rules.
	var tunnelHosts []string
	for _, svc := range services {
		if !svc.DirectOnly && svc.Subdomain != "" && svc.TunnelRouteID != "" {
			tunnelHosts = append(tunnelHosts, svc.Subdomain+"."+m.cfg.Domain)
		}
	}
	if err := m.cf.EnsureTunnelRoutes(ctx, tunnelHosts); err != nil {
		log.Printf("dns: sync tunnel routes: %v", err)
	}

	for _, svc := range services {
		if svc.DirectOnly || svc.Subdomain == "" {
			continue
		}
		host := svc.Subdomain + "." + m.cfg.Domain
		var id string
		var err error
		switch {
		case svc.TunnelRouteID != "":
			if !m.cf.TunnelEnabled() {
				continue
			}
			id, err = m.cf.EnsureCNAME(ctx, host)
		case m.cfg.ServerIP != "":
			id, err = m.cf.UpsertARecord(ctx, host, m.cfg.ServerIP)
		default:
			continue
		}
		if err != nil {
			log.Printf("dns: sync %s: %v", host, err)
			continue
		}
		if id != "" && id != svc.DNSRecordID {
			log.Printf("dns: %s record id %q → %q", host, svc.DNSRecordID, id)
			m.store.SetDNSRecordID(svc.ID, id)
			changed = true
		}
	}
	if changed {
		m.store.SaveLog("dns")
	}
}

func getPublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipifyURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := ipifyClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
