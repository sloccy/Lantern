package web

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"testing"
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 1, A: 1})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

// An SVG icon is a document, so a top-level visit to /api/icons/<id> would run
// its inline script on Lantern's origin. The restrictive CSP is what stops it.
func TestGetIcon_ContentTypeAndCSP(t *testing.T) {
	s := newAuthTestServer(t, "")

	tests := []struct {
		name    string
		id      string
		data    []byte
		wantCT  string
		wantCSP string
	}{
		{"svg gets the sandbox CSP", "aaaa000000000001",
			[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
			"image/svg+xml", iconCSP},
		{"png gets the sandbox CSP", "aaaa000000000002", pngBytes(t), "image/png", iconCSP},
		{"html is downgraded", "aaaa000000000003",
			[]byte("<html><body><script>alert(1)</script></body></html>"),
			"application/octet-stream", iconCSP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.store.WriteIcon(tt.id, tt.data); err != nil {
				t.Fatalf("WriteIcon: %v", err)
			}
			rec := do(s, http.MethodGet, "/api/icons/"+tt.id, nil, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /api/icons/%s = %d, want 200", tt.id, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != tt.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, tt.wantCT)
			}
			if csp := rec.Header().Get("Content-Security-Policy"); csp != tt.wantCSP {
				t.Errorf("Content-Security-Policy = %q, want %q", csp, tt.wantCSP)
			}
		})
	}
}

func TestIsValidIconID(t *testing.T) {
	for in, want := range map[string]bool{
		"aaaa000000000001": true,
		"ABCDEF":           true,
		"../services":      false,
		"zz":               false,
		"":                 false,
	} {
		if got := isValidIconID(in); got != want {
			t.Errorf("isValidIconID(%q) = %v, want %v", in, got, want)
		}
	}
}
