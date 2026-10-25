package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Domain       string
	CFAPIToken   string
	CFZoneID     string
	CFTunnelID   string
	CFAccountID  string
	ServerIP     string
	DataDir      string
	ScanInterval time.Duration
	ScanTimeout  time.Duration

	// TrustedProxies are extra peers (besides loopback, where the Cloudflare
	// tunnel connects from) whose X-Forwarded-* / CF-Connecting-IP headers are believed.
	TrustedProxies []*net.IPNet
	Compression    bool // gzip compressible proxied responses (COMPRESSION=false disables)
	LogRequests    bool // one log line per proxied request (LOG_REQUESTS=true)

	// AdminPassword protects the management UI and write APIs. Empty disables login.
	AdminPassword string
}

func Load() (*Config, error) {
	scanInterval := 24 * time.Hour
	if s := os.Getenv("SCAN_INTERVAL"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid SCAN_INTERVAL %q: %w", s, err)
		}
		scanInterval = d
	}

	scanTimeoutMs := 200
	if s := os.Getenv("SCAN_TIMEOUT_MS"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			scanTimeoutMs = v
		} else {
			return nil, fmt.Errorf("invalid SCAN_TIMEOUT_MS %q: %w", s, err)
		}
	}

	trusted, err := ParseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Domain:       getEnv("DOMAIN", ""),
		CFAPIToken:   os.Getenv("CF_API_TOKEN"),
		CFZoneID:     os.Getenv("CF_ZONE_ID"),
		CFTunnelID:   os.Getenv("CF_TUNNEL_ID"),
		CFAccountID:  os.Getenv("CF_ACCOUNT_ID"),
		ServerIP:     os.Getenv("SERVER_IP"),
		DataDir:      getEnv("DATA_DIR", "/data"),
		ScanInterval: scanInterval,
		ScanTimeout:  time.Duration(scanTimeoutMs) * time.Millisecond,

		TrustedProxies: trusted,
		Compression:    os.Getenv("COMPRESSION") != "false",
		LogRequests:    os.Getenv("LOG_REQUESTS") == "true",
		AdminPassword:  os.Getenv("ADMIN_PASSWORD"),
	}
	return cfg, nil
}

// ParseTrustedProxies parses a comma-separated list of CIDRs or bare IPs.
func ParseTrustedProxies(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q", part)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			part = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: %w", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
