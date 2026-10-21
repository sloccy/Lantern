package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"lantern/internal/config"
	"lantern/internal/store"
)

var insecureTransport = &http.Transport{
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for backend self-signed certs
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
	MaxIdleConns:        32,
	MaxIdleConnsPerHost: 4,
}

// bufferPool implements httputil.BufferPool using sync.Pool to reuse the
// 32 KB copy buffers that httputil.ReverseProxy allocates per request.
// *[]byte is stored (not []byte) to avoid boxing the slice header on Put.
type bufferPool struct{ p sync.Pool }

func (b *bufferPool) Get() []byte {
	if v := b.p.Get(); v != nil {
		buf := v.(*[]byte) //nolint:forcetypeassert // pool only stores *[]byte; type is guaranteed
		return *buf
	}
	buf := make([]byte, 32*1024)
	return buf
}

func (b *bufferPool) Put(buf []byte) { b.p.Put(&buf) }

var proxyBufPool bufferPool

// proxyEntry caches a reverse proxy along with the target URL string so we can
// detect when a service's target has changed and rebuild.
type proxyEntry struct {
	rp     *httputil.ReverseProxy
	target string // svc.Target string — used to detect changes
}

// hostModeInfo travels in the request context from proxySubdomain to the
// reverse proxy's Rewrite/ModifyResponse hooks.
type hostModeInfo struct {
	mode      string
	auto      bool   // mode came from auto-detection (not an explicit setting)
	targetStr string // svc.Target, used as the auto-detect cache key
}

// Handler is the top-level HTTP handler that routes by subdomain.
type Handler struct {
	cfg         *config.Config
	store       *store.Store
	webHandler  http.Handler
	proxies     sync.Map // subdomain → *proxyEntry
	hostModes   sync.Map // subdomain → *hostEntry (auto-detected Host mode)
	suffix      string   // ".domain.tld" — pre-computed from cfg.Domain
	lanternHost string   // "lantern.domain.tld" — pre-computed from cfg.Domain
}

func New(cfg *config.Config, st *store.Store, webHandler http.Handler) *Handler {
	suffix := "." + cfg.Domain
	return &Handler{cfg: cfg, store: st, webHandler: webHandler, suffix: suffix, lanternHost: "lantern" + suffix}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	// Strip port if present.
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		host = host[:i]
	}

	switch {
	case host == h.lanternHost || host == h.cfg.Domain || host == "":
		h.webHandler.ServeHTTP(w, r)
		return
	case strings.HasSuffix(host, h.suffix):
		sub := strings.TrimSuffix(host, h.suffix)
		h.proxySubdomain(w, r, sub)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) proxySubdomain(w http.ResponseWriter, r *http.Request, sub string) {
	svc := h.store.GetServiceBySubdomain(sub)
	if svc == nil {
		h.proxies.Delete(sub) // evict stale cache entries if service was deleted
		h.hostModes.Delete(sub)
		h.errorPage(w, 404, fmt.Sprintf("No service assigned to <strong>%s.%s</strong>", html.EscapeString(sub), html.EscapeString(h.cfg.Domain)))
		return
	}
	target, err := url.Parse(svc.Target)
	if err != nil {
		h.errorPage(w, 502, "Invalid target URL for this service.")
		return
	}

	// Use cached proxy; rebuild only when the service's target URL has changed.
	var rp *httputil.ReverseProxy
	if v, ok := h.proxies.Load(sub); ok {
		if e, ok := v.(*proxyEntry); ok && e.target == svc.Target {
			rp = e.rp
		}
	}
	if rp == nil {
		rp = h.buildProxy(sub, target)
		h.proxies.Store(sub, &proxyEntry{rp: rp, target: svc.Target})
	}
	mode := h.hostModeFor(r.Context(), sub, svc.Target, target, svc.HostMode, r.Host)
	ctx := context.WithValue(r.Context(), hostModeCtxKey{}, hostModeInfo{mode: mode, auto: svc.HostMode == "", targetStr: svc.Target})
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// buildProxy constructs a reverse proxy for the given subdomain and target.
// The returned proxy does not capture the per-request *http.Request; all
// needed values are derived from the outgoing request clone that the
// httputil.ReverseProxy passes to Rewrite/ModifyResponse.
//
// The Host mode (client or backend) is chosen per request by proxySubdomain and
// carried in the request context.
func (h *Handler) buildProxy(sub string, target *url.URL) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Transport:  &upgradeFallbackTransport{h: h, sub: sub, target: target},
		BufferPool: &proxyBufPool,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		svcName := ""
		if s := h.store.GetServiceBySubdomain(sub); s != nil {
			svcName = s.Name
		}
		msg := fmt.Sprintf("Could not reach <strong>%s</strong>.<br><small>%s</small>",
			html.EscapeString(svcName), html.EscapeString(err.Error()))
		h.errorPage(w, 502, msg)
	}
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(target) // also points Out.Host at the backend
		info, _ := pr.In.Context().Value(hostModeCtxKey{}).(hostModeInfo)
		if info.mode == hostBackend {
			// Backend sees its own host; make a matching browser Origin
			// (WebSocket upgrades, CSRF checks) consistent with it.
			backendOrigin(pr.Out.Header, pr.In.Host, target)
		} else {
			pr.Out.Host = pr.In.Host
		}
		pr.SetXForwarded()
		pr.Out.Header.Set("X-Real-IP", realIP(pr.Out))
		// Preserve upstream X-Forwarded-Proto (e.g. from Cloudflare)
		// instead of using SetXForwarded's TLS-only detection.
		if proto := pr.In.Header.Get("X-Forwarded-Proto"); proto != "" {
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
		}
	}
	// Keep Location headers on the public site: a redirect to the backend's own
	// host (e.g. Proxmox VE) goes back to the public host, and a plain-http
	// redirect to the public host is upgraded when the client used HTTPS.
	// The incoming host/proto are on the outgoing request via X-Forwarded-*.
	rp.ModifyResponse = func(resp *http.Response) error {
		info, _ := resp.Request.Context().Value(hostModeCtxKey{}).(hostModeInfo)
		// Safety net: a backend answering 421 to the public Host needs its own.
		if info.auto && info.mode == hostClient && resp.StatusCode == http.StatusMisdirectedRequest {
			h.setHostMode(sub, info.targetStr, hostBackend)
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil
		}
		locURL, err := url.Parse(loc)
		if err != nil {
			return nil //nolint:nilerr // unparseable Location header: skip rewrite, don't fail the response
		}
		fwdHost := resp.Request.Header.Get("X-Forwarded-Host")
		switch {
		case locURL.Host == target.Host && fwdHost != "":
			locURL.Scheme = "https"
			locURL.Host = fwdHost
			resp.Header.Set("Location", locURL.String())
		case fwdHost != "" && locURL.Host == fwdHost && locURL.Scheme == "http" &&
			resp.Request.Header.Get("X-Forwarded-Proto") == "https":
			locURL.Scheme = "https"
			resp.Header.Set("Location", locURL.String())
		}
		return nil
	}
	return rp
}

func (h *Handler) errorPage(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	title := "Service Unavailable"
	if code == 404 {
		title = "Service Not Found"
	}
	_, _ = fmt.Fprintf(w, errorHTML, title, title, msg, h.cfg.Domain) //nolint:gosec // errorHTML is a fixed format string; caller-escaped variables
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.SplitN(ip, ",", 2)[0]
	}
	return r.RemoteAddr
}

const errorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s — Lantern</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f0f1a;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}
.card{background:#1a1a2e;border:1px solid #2d2d4e;border-radius:12px;padding:3rem;max-width:480px;text-align:center}
.icon{font-size:3rem;margin-bottom:1rem}
h1{font-size:1.5rem;margin-bottom:.75rem;color:#ef4444}
p{color:#94a3b8;line-height:1.6}
a{color:#7c3aed;text-decoration:none}a:hover{text-decoration:underline}
.back{margin-top:2rem}
.btn{display:inline-block;padding:.5rem 1.25rem;background:#7c3aed;color:#fff;border-radius:6px;text-decoration:none;font-size:.875rem}
.btn:hover{background:#6d28d9;text-decoration:none}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🚫</div>
  <h1>%s</h1>
  <p>%s</p>
  <div class="back"><a class="btn" href="https://lantern.%s">← Back to Lantern</a></div>
</div>
</body>
</html>`
