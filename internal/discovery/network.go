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
	// Non-HTTP ports are silently ignored — the prober makes a real HTTP request.
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

	httpClient = &http.Client{
		Timeout: 4 * time.Second,
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

	reTitleTag   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reFaviconHref = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']`)
	reFaviconHref2 = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*icon[^"']*["']`)
)

// getLocalSubnet returns the first non-loopback /24 subnet.
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

// generateIPs returns all host IPs in the given /24 subnet.
func generateIPs(subnet *net.IPNet) []string {
	var ips []string
	base := subnet.IP.Mask(subnet.Mask)
	for i := 1; i < 255; i++ {
		ip := make(net.IP, 4)
		copy(ip, base)
		ip[3] = byte(i)
		if subnet.Contains(ip) {
			ips = append(ips, ip.String())
		}
	}
	return ips
}

type probeResult struct {
	ip    string
	port  int
	url   string
	title string
	icon  string
}

func (d *Discoverer) scanNetwork(ctx context.Context) []*probeResult {
	subnet, err := getLocalSubnet()
	if err != nil {
		log.Printf("discovery: get subnet: %v", err)
		return nil
	}
	log.Printf("discovery: scanning %s (%d ports per host)", subnet, len(scanPorts))

	ips := generateIPs(subnet)
	type job struct {
		ip   string
		port int
	}

	jobs := make(chan job, 512)
	results := make(chan *probeResult, 256)

	// Workers
	const workers = 80
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				if r := probeHTTP(ctx, j.ip, j.port); r != nil {
					results <- r
				}
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			for _, port := range scanPorts {
				jobs <- job{ip, port}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var out []*probeResult
	for r := range results {
		out = append(out, r)
	}
	return out
}

func probeHTTP(ctx context.Context, ip string, port int) *probeResult {
	scheme := "http"
	if port == 443 || port == 8443 || port == 9443 {
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

	// Read up to 64 KB to find title/favicon links.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	title := extractTitle(bodyStr)
	if title == "" {
		title = ip
	}

	faviconURL := extractFaviconURL(bodyStr, rawURL)
	icon := fetchFaviconBase64(ctx, faviconURL)

	return &probeResult{
		ip:    ip,
		port:  port,
		url:   rawURL,
		title: title,
		icon:  icon,
	}
}

func extractTitle(html string) string {
	m := reTitleTag.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(m[1])
	// Collapse whitespace.
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
		// Protocol-relative.
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
