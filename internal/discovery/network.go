package discovery

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// scanPorts covers common homelab service web UIs.
	scanPorts = []int{
		80,    // HTTP
		443,   // HTTPS
		2283,  // Immich
		3000,  // Grafana, Gitea, various
		3001,  // various
		4533,  // Navidrome
		5000,  // various
		5001,  // Synology DSM HTTPS, various
		5055,  // Overseerr
		6080,  // noVNC
		7878,  // Radarr
		8001,  // various
		8006,  // Proxmox VE
		8080,  // Traefik dashboard, various
		8096,  // Jellyfin
		8123,  // Home Assistant
		8443,  // HTTPS alternative
		8686,  // Lidarr
		8920,  // Jellyfin HTTPS
		8989,  // Sonarr
		9000,  // Portainer, various
		9090,  // Prometheus
		9091,  // Transmission
		9117,  // Jackett
		9443,  // Portainer HTTPS
		19999, // Netdata
		32400, // Plex
	}

	// httpsPorts are probed with HTTPS instead of HTTP.
	httpsPorts = map[int]bool{443: true, 5001: true, 8443: true, 8920: true, 9443: true}

	httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives:   true,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: 3 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	reTitleTag    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reFaviconHref  = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']`)
	reFaviconHref2 = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*icon[^"']*["']`)
)

// ── Stage 3: Fingerprint engine ───────────────────────────────────────────────

type signature struct {
	name       string
	confidence float32
	icon       string
	match      func(h http.Header, body, title string) bool
}

var signatures = []signature{
	{"Proxmox VE", 0.99, "🖥️", func(h http.Header, b, _ string) bool {
		return strings.Contains(h.Get("Server"), "pve-api-daemon") ||
			strings.Contains(b, "Proxmox Virtual Environment")
	}},
	{"Home Assistant", 0.95, "🏠", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Home Assistant") || strings.Contains(b, "Home Assistant")
	}},
	{"Grafana", 0.99, "📊", func(h http.Header, b, t string) bool {
		return h.Get("X-Grafana-Version") != "" ||
			strings.Contains(t, "Grafana") || strings.Contains(b, "grafana")
	}},
	{"Portainer", 0.95, "🐳", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Portainer") || strings.Contains(b, "Portainer")
	}},
	{"Jellyfin", 0.95, "🎬", func(h http.Header, b, t string) bool {
		return h.Get("X-Jellyfin-Version") != "" ||
			strings.Contains(b, "Jellyfin") || strings.Contains(t, "Jellyfin")
	}},
	{"Plex", 0.95, "🎬", func(h http.Header, b, t string) bool {
		return h.Get("X-Plex-Protocol") != "" ||
			strings.Contains(b, "Plex Media Server") || strings.Contains(t, "Plex")
	}},
	{"Sonarr", 0.95, "📺", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Sonarr") || strings.Contains(b, "Sonarr")
	}},
	{"Radarr", 0.95, "🎥", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Radarr") || strings.Contains(b, "Radarr")
	}},
	{"Lidarr", 0.90, "🎵", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Lidarr") || strings.Contains(b, "Lidarr")
	}},
	{"Readarr", 0.90, "📚", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Readarr") || strings.Contains(b, "Readarr")
	}},
	{"Overseerr", 0.95, "🎭", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Overseerr") || strings.Contains(b, "Overseerr")
	}},
	{"Jackett", 0.95, "🔍", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Jackett") || strings.Contains(b, "Jackett")
	}},
	{"Transmission", 0.90, "⬇️", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Transmission") || strings.Contains(b, "Transmission Web")
	}},
	{"qBittorrent", 0.90, "⬇️", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "qBittorrent") || strings.Contains(b, "qBittorrent")
	}},
	{"Prometheus", 0.95, "📈", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Prometheus") || strings.Contains(b, "prometheus_")
	}},
	{"Netdata", 0.99, "📉", func(h http.Header, b, t string) bool {
		return h.Get("X-Netdata-Version") != "" ||
			strings.Contains(b, "netdataRoot") || strings.Contains(t, "Netdata")
	}},
	{"Gitea", 0.99, "🦊", func(h http.Header, b, t string) bool {
		return h.Get("X-Gitea-Version") != "" ||
			strings.Contains(t, "Gitea") || strings.Contains(b, "Gitea")
	}},
	{"Immich", 0.95, "📷", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Immich") || strings.Contains(b, "Immich")
	}},
	{"Navidrome", 0.95, "🎵", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Navidrome") || strings.Contains(b, "Navidrome")
	}},
	{"Uptime Kuma", 0.95, "🟢", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Uptime Kuma") || strings.Contains(b, "uptimekuma")
	}},
	{"Vaultwarden", 0.90, "🔐", func(_ http.Header, b, t string) bool {
		return strings.Contains(b, "Vaultwarden") ||
			strings.Contains(t, "Vaultwarden") || strings.Contains(b, "bitwarden")
	}},
	{"Pi-hole", 0.95, "🕳️", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Pi-hole") || strings.Contains(b, "Pi-hole")
	}},
	{"AdGuard Home", 0.95, "🛡️", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "AdGuard") || strings.Contains(b, "AdGuard Home")
	}},
	{"Nginx Proxy Manager", 0.95, "🔀", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Nginx Proxy Manager") || strings.Contains(b, "Nginx Proxy Manager")
	}},
	{"Traefik", 0.90, "🔀", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Traefik") || strings.Contains(b, "traefik")
	}},
	{"Cockpit", 0.90, "🖥️", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Cockpit") || strings.Contains(b, "cockpit")
	}},
	{"Synology DSM", 0.95, "💾", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Synology") ||
			strings.Contains(b, "Synology DiskStation") || strings.Contains(b, "SYNO.")
	}},
	{"n8n", 0.90, "⚙️", func(_ http.Header, b, t string) bool {
		return strings.EqualFold(t, "n8n") || strings.Contains(b, "\"n8n\"")
	}},
	{"Guacamole", 0.95, "🖥️", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Guacamole") || strings.Contains(b, "guacamole")
	}},
	{"Frigate", 0.95, "📹", func(_ http.Header, b, t string) bool {
		return strings.Contains(t, "Frigate") || strings.Contains(b, "Frigate NVR")
	}},
	{"UniFi", 0.90, "📡", func(_ http.Header, b, t string) bool {
		return strings.Contains(b, "UniFi") || strings.Contains(t, "UniFi")
	}},
}

// fingerprint matches HTTP response data against known service signatures.
// Returns name, confidence (0–1) and an emoji icon, or empty strings if unknown.
func fingerprint(h http.Header, body, title string) (name string, confidence float32, icon string) {
	for _, sig := range signatures {
		if sig.match(h, body, title) {
			return sig.name, sig.confidence, sig.icon
		}
	}
	return "", 0, ""
}

// ── Stage 1: TCP connect sweep ────────────────────────────────────────────────

type openPort struct {
	ip   string
	port int
}

// tcpSweep checks which (ip, port) pairs accept a TCP connection.
// Uses 256 workers with a 750ms dial timeout — no data exchange.
func tcpSweep(ctx context.Context, ips []string, ports []int) []openPort {
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job, 1024)
	results := make(chan openPort, 256)

	const workers = 256
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				addr := fmt.Sprintf("%s:%d", j.ip, j.port)
				conn, err := net.DialTimeout("tcp", addr, 750*time.Millisecond)
				if err == nil {
					conn.Close()
					results <- openPort{j.ip, j.port}
				}
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				jobs <- job{ip, port}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var open []openPort
	for op := range results {
		open = append(open, op)
	}
	return open
}

// ── Subnet helpers ────────────────────────────────────────────────────────────

// getLocalSubnet returns the first non-loopback /24 subnet derived from the
// container's own interface. The /24 is forced regardless of actual prefix.
func getLocalSubnet() (*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			// Force a /24 scan.
			_, subnet, _ := net.ParseCIDR(fmt.Sprintf("%s/24", ip4))
			return subnet, nil
		}
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

// generateIPs returns all host IPs (excluding network and broadcast) in subnet.
func generateIPs(subnet *net.IPNet) []string {
	var ips []string
	ip4 := subnet.IP.To4()
	if ip4 == nil {
		return nil
	}
	cur := make(net.IP, 4)
	copy(cur, ip4.Mask(subnet.Mask))
	incrementIP(cur)

	bcast := broadcastIP(subnet)
	for subnet.Contains(cur) && !cur.Equal(bcast) {
		dst := make(net.IP, 4)
		copy(dst, cur)
		ips = append(ips, dst.String())
		incrementIP(cur)
	}
	return ips
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastIP(subnet *net.IPNet) net.IP {
	ip4 := subnet.IP.To4()
	bcast := make(net.IP, 4)
	for i := range bcast {
		bcast[i] = ip4[i] | ^subnet.Mask[i]
	}
	return bcast
}

// ── Stage 2 + 3: HTTP probe + fingerprint ─────────────────────────────────────

type probeResult struct {
	ip          string
	port        int
	url         string
	title       string
	icon        string
	serviceName string
	confidence  float32
}

// scanNetwork runs a TCP sweep followed by HTTP probing on open ports only.
// Results are streamed over the returned channel as they arrive.
func (d *Discoverer) scanNetwork(ctx context.Context, cidrs []string) <-chan *probeResult {
	ch := make(chan *probeResult, 64)

	go func() {
		defer close(ch)

		// Parse CIDRs or fall back to auto-detect.
		var nets []*net.IPNet
		if len(cidrs) == 0 {
			subnet, err := getLocalSubnet()
			if err != nil {
				log.Printf("discovery: get subnet: %v", err)
				return
			}
			nets = []*net.IPNet{subnet}
		} else {
			for _, cidr := range cidrs {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					log.Printf("discovery: invalid subnet %q: %v", cidr, err)
					continue
				}
				nets = append(nets, ipnet)
			}
			if len(nets) == 0 {
				return
			}
		}

		// Collect all unique host IPs across all subnets.
		seen := make(map[string]bool)
		var ips []string
		for _, subnet := range nets {
			hosts := generateIPs(subnet)
			log.Printf("discovery: subnet %s — %d hosts", subnet, len(hosts))
			for _, ip := range hosts {
				if !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
			}
		}

		// Stage 1: TCP sweep — fast filter, no HTTP overhead.
		log.Printf("discovery: TCP sweep — %d hosts × %d ports (%d pairs)",
			len(ips), len(scanPorts), len(ips)*len(scanPorts))
		open := tcpSweep(ctx, ips, scanPorts)
		log.Printf("discovery: TCP sweep done — %d open ports", len(open))

		if len(open) == 0 || ctx.Err() != nil {
			return
		}

		// Stage 2: HTTP probe on open ports only (80 workers).
		jobs := make(chan openPort, len(open))
		for _, op := range open {
			jobs <- op
		}
		close(jobs)

		const httpWorkers = 80
		var wg sync.WaitGroup
		for i := 0; i < httpWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for op := range jobs {
					if ctx.Err() != nil {
						return
					}
					if r := probeHTTP(ctx, op.ip, op.port); r != nil {
						ch <- r
					}
				}
			}()
		}
		wg.Wait()
	}()

	return ch
}

func probeHTTP(ctx context.Context, ip string, port int) *probeResult {
	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	rawURL := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	title := extractTitle(bodyStr)
	if title == "" {
		title = ip
	}

	// Stage 3: Fingerprint using headers + body + title.
	svcName, confidence, svcIcon := fingerprint(resp.Header, bodyStr, title)

	// Use fingerprint emoji icon if matched; otherwise fetch the favicon.
	icon := svcIcon
	if icon == "" {
		faviconURL := extractFaviconURL(bodyStr, rawURL)
		icon = fetchFaviconBase64(ctx, faviconURL)
	}

	return &probeResult{
		ip:          ip,
		port:        port,
		url:         rawURL,
		title:       title,
		icon:        icon,
		serviceName: svcName,
		confidence:  confidence,
	}
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

func extractTitle(html string) string {
	m := reTitleTag.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(m[1])
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > 80 {
		t = t[:80]
	}
	return t
}

func extractFaviconURL(html, baseURL string) string {
	for _, re := range []*regexp.Regexp{reFaviconHref, reFaviconHref2} {
		if m := re.FindStringSubmatch(html); len(m) >= 2 {
			return resolveRef(m[1], baseURL)
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

func fetchFaviconBase64(ctx context.Context, faviconURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return ""
	}
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || len(data) == 0 {
		return ""
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "image/x-icon"
	}
	return "data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(data)
}
