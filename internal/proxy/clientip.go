package proxy

import (
	"net"
	"net/http"
	"strings"
)

// peerIP returns the IP of the TCP peer (without port).
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// trustedPeer reports whether the TCP peer may speak for the real client:
// loopback (the Cloudflare tunnel connects from there) or a configured
// TRUSTED_PROXIES range. Forwarded headers from anyone else are ignored, so a
// LAN client can't spoof its address.
func (h *Handler) trustedPeer(r *http.Request) bool {
	ip := net.ParseIP(peerIP(r))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range h.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// viaTunnel reports whether the request came through the Cloudflare tunnel
// (a trusted peer that vouches for a public client via CF-Connecting-IP).
func (h *Handler) viaTunnel(r *http.Request) bool {
	return h.trustedPeer(r) && r.Header.Get("Cf-Connecting-Ip") != ""
}

// clientIP is the address of the real client: the peer itself, unless the peer
// is trusted and says who is behind it (Cloudflare's CF-Connecting-IP, or the
// first X-Forwarded-For entry).
func (h *Handler) clientIP(r *http.Request) string {
	if h.trustedPeer(r) {
		if v := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
		}
	}
	return peerIP(r)
}

// forwardedProto is the scheme the client used: taken from a trusted peer's
// X-Forwarded-Proto, otherwise from whether this connection is TLS.
func (h *Handler) forwardedProto(r *http.Request) string {
	if h.trustedPeer(r) {
		if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
			return p
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
