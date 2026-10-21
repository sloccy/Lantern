package proxy

import (
	"context"
	"log"
	"net/http"
	"net/url"
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
