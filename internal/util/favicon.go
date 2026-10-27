package util

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"lantern/internal/store"
)

// blockedCIDRs are IP ranges that must never be the target of favicon fetches.
// RFC1918 private ranges are intentionally NOT blocked — Lantern is a homelab
// dashboard whose entire purpose is to reach LAN services.
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // loopback IPv4
		"::1/128",        // loopback IPv6
		"169.254.0.0/16", // link-local / cloud metadata (AWS, GCP, Azure)
		"fe80::/10",      // link-local IPv6
		"0.0.0.0/8",      // unspecified
		"::/128",         // unspecified IPv6
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, _ := net.ParseCIDR(c)
		nets = append(nets, ipnet)
	}
	return nets
}()

func isBlockedIP(ip net.IP) bool {
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// cgnatCIDR is RFC 6598 shared address space — where Tailscale hands out
// addresses, so a homelab's private hosts are reachable there too.
var cgnatCIDR = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// isPrivateIP is the stricter test used when a remote page, rather than the
// operator, chose the host: everything isBlockedIP refuses plus RFC1918, IPv6
// unique-local and CGNAT. Lantern reaching LAN services is the whole point, but
// only for a target someone configured.
func isPrivateIP(ip net.IP) bool {
	return isBlockedIP(ip) || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || cgnatCIDR.Contains(ip)
}

var baseDialer = &net.Dialer{Timeout: 5 * time.Second}

// validateFaviconURL parses rawURL, enforces http/https scheme, resolves the
// hostname, and rejects blocked IPs. Returns the reconstructed URL string so
// the caller uses a URL derived from validated, parsed components rather than
// the raw user-supplied string.
func validateFaviconURL(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("favicon: disallowed scheme %q", u.Scheme)
	}
	host := u.Hostname()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && isBlockedIP(ip) {
			return "", fmt.Errorf("favicon: host %s resolves to blocked IP %s", host, a)
		}
	}
	return u.String(), nil
}

// dialChecked resolves the hostname and rejects any address reject() refuses
// before establishing a TCP connection. Checking here rather than only before
// the request is what makes redirect chains and DNS rebinding safe: every
// connection the client opens passes through it.
func dialChecked(ctx context.Context, network, addr string, reject func(net.IP) bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && reject(ip) {
			return nil, fmt.Errorf("favicon: host %s resolves to blocked IP %s", host, a)
		}
	}
	return baseDialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
}

// safeDialContext is defense-in-depth against redirect-based bypasses — the
// primary check is in validateFaviconURL.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialChecked(ctx, network, addr, isBlockedIP)
}

// publicOnlyDialContext additionally refuses private address space, for a
// favicon URL whose host came from the fetched page rather than the operator.
func publicOnlyDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialChecked(ctx, network, addr, isPrivateIP)
}

func newFaviconClient(dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fetching favicons from arbitrary LAN hosts: TLS cert validity is not meaningful
			DisableKeepAlives: true,
			DialContext:       dial,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("favicon: too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("favicon: redirect to disallowed scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}
}

var (
	// faviconClient fetches a target the operator configured: LAN addresses are
	// allowed, loopback and link-local are not.
	faviconClient = newFaviconClient(safeDialContext)
	// faviconPublicClient fetches a URL the remote page chose, so it may not
	// reach private address space at all.
	faviconPublicClient = newFaviconClient(publicOnlyDialContext)
)

var (
	reFaviconHref     = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']`)
	reFaviconHref2    = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*icon[^"']*["']`)
	reAppleTouchIcon  = regexp.MustCompile(`(?i)<link[^>]+rel=["']apple-touch-icon["'][^>]+href=["']([^"']+)["']`)
	reAppleTouchIcon2 = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"']+)["'][^>]+rel=["']apple-touch-icon["']`)
)

// FetchFaviconForTarget fetches the page at targetURL, extracts the favicon
// link, fetches the favicon, and returns the raw image bytes.
// Returns nil if no favicon is found or the fetch fails.
func FetchFaviconForTarget(ctx context.Context, targetURL string) []byte {
	safeURL, err := validateFaviconURL(ctx, targetURL)
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, safeURL, http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := faviconClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	return FetchFaviconFromHTML(ctx, string(body), targetURL)
}

// FetchFaviconFromHTML extracts the favicon URL from pre-fetched HTML and
// fetches the favicon bytes. Use this when the page HTML is already available.
func FetchFaviconFromHTML(ctx context.Context, html, baseURL string) []byte {
	ref := extractFaviconURL(html, baseURL)
	if sameHost(ref, baseURL) {
		return fetchFaviconBytes(ctx, ref, faviconClient)
	}
	// The href named another host, so the page — not the operator — picked the
	// target. It does not get to aim Lantern at private address space; a public
	// CDN icon still works. If refused, fall back to the page's own favicon.
	if data := fetchFaviconBytes(ctx, ref, faviconPublicClient); len(data) > 0 {
		return data
	}
	return fetchFaviconBytes(ctx, resolveRef("/favicon.ico", baseURL), faviconClient)
}

// sameHost reports whether two URLs name the same host, ignoring scheme, port
// and case. It is false if either fails to parse.
func sameHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return ua.Hostname() != "" && strings.EqualFold(ua.Hostname(), ub.Hostname())
}

// FetchAndWriteFavicon looks up the target URL for id from the store, fetches
// its favicon, and writes the result to disk. Returns true on success.
// The caller is responsible for updating the entity's Icon field.
// Using a store-derived URL (rather than a caller-supplied string) ensures the
// URL is server-controlled, not user-tainted.
func FetchAndWriteFavicon(ctx context.Context, st *store.Store, id string) bool {
	target := st.GetTarget(id)
	if target == "" {
		return false
	}
	data := FetchFaviconForTarget(ctx, target)
	if len(data) == 0 {
		return false
	}
	return st.WriteIcon(id, data) == nil
}

func fetchFaviconBytes(ctx context.Context, faviconURL string, client *http.Client) []byte {
	safeURL, err := validateFaviconURL(ctx, faviconURL)
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, safeURL, http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

func extractFaviconURL(html, baseURL string) string {
	// Prefer apple-touch-icon: always a high-quality PNG, no ICO format artifacts.
	for _, pair := range [][2]*regexp.Regexp{
		{reAppleTouchIcon, reAppleTouchIcon2},
		{reFaviconHref, reFaviconHref2},
	} {
		for _, re := range pair {
			if m := re.FindStringSubmatch(html); len(m) >= 2 {
				return resolveRef(m[1], baseURL)
			}
		}
	}
	return resolveRef("/favicon.ico", baseURL)
}

func resolveRef(ref, base string) string {
	if strings.HasPrefix(ref, "//") {
		bu, _ := url.Parse(base)
		return bu.Scheme + ":" + ref
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	rel, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return bu.ResolveReference(rel).String()
}
