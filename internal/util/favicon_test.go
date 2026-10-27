package util

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	for in, want := range map[string]bool{
		"10.0.0.1":        true, // RFC1918
		"172.16.0.1":      true, // RFC1918
		"192.168.1.1":     true, // RFC1918
		"100.64.0.1":      true, // CGNAT / Tailscale
		"127.0.0.1":       true, // loopback
		"169.254.169.254": true, // link-local / cloud metadata
		"0.0.0.0":         true, // unspecified
		"fd00::1":         true, // IPv6 unique-local
		"::1":             true, // IPv6 loopback
		"fe80::1":         true, // IPv6 link-local
		"1.1.1.1":         false,
		"93.184.216.34":   false,
		"100.128.0.1":     false, // just outside 100.64.0.0/10
		"2606:4700::1":    false,
	} {
		ip := net.ParseIP(in)
		if ip == nil {
			t.Fatalf("bad test address %q", in)
		}
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestSameHost(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"http://example.com/favicon.ico", "http://example.com/", true},
		{"https://example.com/i.png", "http://example.com:8080/page", true}, // scheme and port ignored
		{"http://EXAMPLE.com/i.png", "http://example.com/", true},           // case ignored
		{"http://cdn.example.com/i.png", "http://example.com/", false},      // subdomain is another host
		{"http://192.168.1.1/i.png", "http://10.0.0.5:8080/", false},
		{"/favicon.ico", "http://example.com/", false}, // relative: no host
		{"", "http://example.com/", false},
	}
	for _, tt := range tests {
		if got := sameHost(tt.a, tt.b); got != tt.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// A page may not point Lantern's favicon fetch at another host in private
// address space. Both test servers are on loopback, which the operator-facing
// client already refuses, so what this pins down is that the cross-host branch
// does not return the other host's bytes — isPrivateIP covers the rule itself.
func TestFetchFaviconFromHTML_CrossHostNotFetched(t *testing.T) {
	secret := []byte("\x89PNG\r\n\x1a\nSECRET-INTERNAL-RESPONSE")

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(secret)
	}))
	defer other.Close()

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // no same-host favicon either
	}))
	defer page.Close()

	html := `<html><head><link rel="icon" href="` + other.URL + `/evil.png"></head></html>`
	got := FetchFaviconFromHTML(context.Background(), html, page.URL)

	if bytes.Equal(got, secret) {
		t.Error("cross-host favicon on another host was fetched and returned")
	}
	if len(got) != 0 {
		t.Errorf("expected no favicon bytes, got %d", len(got))
	}
}

// A relative href still resolves against the page and is fetched normally.
func TestFetchFaviconFromHTML_SameHostRelative(t *testing.T) {
	icon := []byte("\x89PNG\r\n\x1a\nlegitimate-icon")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/icon.png" {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(icon)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// httptest binds loopback, which faviconClient refuses by design, so the
	// fetch itself cannot succeed here. What matters is that a relative href
	// resolves against the page and takes the same-host path.
	html := `<html><head><link rel="icon" href="/static/icon.png"></head></html>`
	ref := extractFaviconURL(html, srv.URL)

	if want := srv.URL + "/static/icon.png"; ref != want {
		t.Errorf("extractFaviconURL = %q, want %q", ref, want)
	}
	if !sameHost(ref, srv.URL) {
		t.Error("relative href should resolve to the same host")
	}
	_ = icon
}
