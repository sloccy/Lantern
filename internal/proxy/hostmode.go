package proxy

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Host header modes for a proxied service.
const (
	hostClient  = "client"  // pass the browser's Host through (Caddy/nginx-style default)
	hostBackend = "backend" // send the target's own host
)

const (
	hostModeTTL      = 10 * time.Minute
	hostProbeTimeout = 3 * time.Second
)

type hostModeCtxKey struct{}

// hostEntry is a cached auto-detected Host mode for one subdomain+target.
type hostEntry struct {
	target  string
	mode    string
	at      time.Time
	refresh sync.Mutex // held while a background refresh is running
}

var probeClient = &http.Client{
	Transport: insecureTransport,
	Timeout:   hostProbeTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// hostModeFor returns the Host mode to use for a request. An explicit service
// setting wins; otherwise the auto-detected mode is used, probing the backend
// on first use and refreshing in the background once the entry is stale.
func (h *Handler) hostModeFor(ctx context.Context, sub, targetStr string, target *url.URL, explicit, publicHost string) string {
	if explicit == hostClient || explicit == hostBackend {
		return explicit
	}
	if v, ok := h.hostModes.Load(sub); ok {
		if e, ok := v.(*hostEntry); ok && e.target == targetStr {
			if time.Since(e.at) > hostModeTTL && e.refresh.TryLock() {
				go func() { //nolint:gosec,contextcheck // background refresh must outlive the triggering request
					defer e.refresh.Unlock()
					h.detectHostMode(context.Background(), sub, targetStr, target, publicHost)
				}()
			}
			return e.mode
		}
	}
	return h.detectHostMode(ctx, sub, targetStr, target, publicHost)
}

// detectHostMode probes the backend with the public Host and with its own Host
// and caches the result. The backend's own Host is only chosen when the public
// one is rejected and its own is accepted.
func (h *Handler) detectHostMode(ctx context.Context, sub, targetStr string, target *url.URL, publicHost string) string {
	mode := hostClient
	pub, pubErr := probeStatus(ctx, target, publicHost)
	if pubErr == nil && hostRejected(pub) {
		if own, err := probeStatus(ctx, target, target.Host); err == nil && own < 400 {
			mode = hostBackend
		}
	}
	h.setHostMode(sub, targetStr, mode)
	log.Printf("proxy: %s host mode = %s", sub, mode) //nolint:gosec // sub is a store-validated subdomain
	return mode
}

func (h *Handler) setHostMode(sub, targetStr, mode string) {
	h.hostModes.Store(sub, &hostEntry{target: targetStr, mode: mode, at: time.Now()})
}

// hostRejected reports whether a status looks like "this Host isn't allowed".
func hostRejected(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusForbidden ||
		status == http.StatusMisdirectedRequest || status >= 500
}

func probeStatus(ctx context.Context, target *url.URL, host string) (int, error) {
	u := *target
	u.Path, u.RawQuery = "/", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody) //nolint:gosec // probing the operator-configured backend target
	if err != nil {
		return 0, err
	}
	req.Host = host
	resp, err := probeClient.Do(req) //nolint:gosec // probing the operator-configured backend target
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// backendOrigin rewrites a browser Origin that names the public host to the
// backend's own origin, so backends that compare Origin to Host accept it.
func backendOrigin(hdr http.Header, publicHost string, target *url.URL) {
	o := hdr.Get("Origin")
	if o == "" {
		return
	}
	if ou, err := url.Parse(o); err == nil && ou.Host == publicHost {
		hdr.Set("Origin", target.Scheme+"://"+target.Host)
	}
}

// upgradeFallbackTransport retries a refused WebSocket upgrade once with the
// backend's own Host. Some backends accept the public Host for normal pages
// (so the "/" probe picks client mode) but reject it on upgrades. When the
// retry succeeds the service switches to backend mode for good.
type upgradeFallbackTransport struct {
	h      *Handler
	sub    string
	target *url.URL
}

func (t *upgradeFallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := insecureTransport.RoundTrip(req)
	if err != nil || resp.StatusCode == http.StatusSwitchingProtocols ||
		!strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return resp, err
	}
	info, _ := req.Context().Value(hostModeCtxKey{}).(hostModeInfo)
	if info.auto && info.mode == hostClient {
		retry := req.Clone(req.Context())
		retry.Host = t.target.Host
		backendOrigin(retry.Header, req.Host, t.target)
		resp2, err2 := insecureTransport.RoundTrip(retry)
		if err2 == nil && resp2.StatusCode == http.StatusSwitchingProtocols {
			_ = resp.Body.Close()
			t.h.setHostMode(t.sub, info.targetStr, hostBackend)
			log.Printf("proxy: %s host mode = backend (WebSocket upgrade refused with public Host)", t.sub) //nolint:gosec // sub is a store-validated subdomain
			return resp2, nil
		}
		if err2 == nil {
			_ = resp2.Body.Close()
		}
	}
	// Refused upgrade: say why, since the browser only reports "connection refused".
	log.Printf("proxy: %s WebSocket upgrade refused by backend: status %d (host mode %q, Host %q, Origin %q)", //nolint:gosec // values are request headers logged for diagnosis
		t.sub, resp.StatusCode, info.mode, req.Host, req.Header.Get("Origin"))
	return resp, nil
}
