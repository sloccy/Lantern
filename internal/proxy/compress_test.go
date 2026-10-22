package proxy

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lantern/internal/config"
)

var bigJSON = `{"items":[` + strings.Repeat(`{"name":"lantern","ok":true},`, 200) + `{}]}`

func compressHandler(t *testing.T, backend http.Handler) *Handler {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	st := newTestStore(t)
	addSvc(st, srv.URL, "client")
	return New(&config.Config{Domain: "example.com", Compression: true}, st, http.NotFoundHandler())
}

func getVia(t *testing.T, h *Handler, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "test.example.com"
	req.Header.Set("Accept-Encoding", "gzip")
	if mutate != nil {
		mutate(req)
	}
	h.ServeHTTP(rec, req)
	return rec
}

func TestCompress_JSONIsGzipped(t *testing.T) {
	h := compressHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"abc"`)
		_, _ = io.WriteString(w, bigJSON)
	}))
	rec := getVia(t, h, nil)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", rec.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Errorf("Vary = %q, want Accept-Encoding", rec.Header().Get("Vary"))
	}
	if got := rec.Header().Get("ETag"); got != `W/"abc"` {
		t.Errorf("Etag = %q, want weak", got)
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, _ := io.ReadAll(zr)
	if string(body) != bigJSON {
		t.Error("decompressed body differs from original")
	}
	if rec.Body.Len() >= len(bigJSON) {
		t.Errorf("compressed %d >= original %d", rec.Body.Len(), len(bigJSON))
	}
}

func TestCompress_LeavesIneligibleResponsesAlone(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(w http.ResponseWriter)
		mutate func(*http.Request)
	}{
		{"already encoded", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "br")
		}, nil},
		{"image", func(w http.ResponseWriter) { w.Header().Set("Content-Type", "image/png") }, nil},
		{"tiny body", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "20")
		}, nil},
		{"client declines", func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/json") },
			func(r *http.Request) { r.Header.Set("Accept-Encoding", "gzip;q=0") }},
		{"range request", func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/json") },
			func(r *http.Request) { r.Header.Set("Range", "bytes=0-10") }},
		{"no-transform", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-transform")
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := compressHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.setup(w)
				if w.Header().Get("Content-Length") == "20" {
					_, _ = io.WriteString(w, strings.Repeat("x", 20))
					return
				}
				_, _ = io.WriteString(w, bigJSON)
			}))
			rec := getVia(t, h, tc.mutate)
			if got := rec.Header().Get("Content-Encoding"); got == "gzip" {
				t.Errorf("response was gzipped")
			}
		})
	}
}

func TestCompress_HeadAndNoContent(t *testing.T) {
	h := compressHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
	}))
	if rec := getVia(t, h, nil); rec.Header().Get("Content-Encoding") != "" {
		t.Error("204 must not be encoded")
	}
	if rec := getVia(t, h, func(r *http.Request) { r.Method = http.MethodHead }); rec.Header().Get("Content-Encoding") != "" {
		t.Error("HEAD must not be encoded")
	}
}

// Streams must keep flowing: SSE is never compressed, and a compressed
// streaming response delivers its first chunk before the backend finishes.
func TestCompress_Streaming(t *testing.T) {
	for _, tc := range []struct {
		ctype string
		gzip  bool
	}{{"text/event-stream", false}, {"application/x-ndjson", true}} {
		t.Run(tc.ctype, func(t *testing.T) {
			release := make(chan struct{})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				_, _ = io.WriteString(w, "first\n")
				_ = http.NewResponseController(w).Flush()
				<-release
				_, _ = io.WriteString(w, "second\n")
			}))
			defer backend.Close()
			defer close(release)

			st := newTestStore(t)
			addSvc(st, backend.URL, "client")
			front := httptest.NewServer(New(&config.Config{Domain: "example.com", Compression: true}, st, http.NotFoundHandler()))
			defer front.Close()

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL, http.NoBody)
			req.Host = "test.example.com"
			req.Header.Set("Accept-Encoding", "gzip")
			client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if (resp.Header.Get("Content-Encoding") == "gzip") != tc.gzip {
				t.Fatalf("Content-Encoding = %q, want gzip=%v", resp.Header.Get("Content-Encoding"), tc.gzip)
			}
			var r io.Reader = resp.Body
			if tc.gzip {
				zr, err := gzip.NewReader(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				r = zr
			}
			line, err := bufio.NewReader(r).ReadString('\n')
			if err != nil || line != "first\n" {
				t.Fatalf("first chunk = %q, err %v (stream stalled?)", line, err)
			}
		})
	}
}

func TestCompress_DisabledByConfig(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, bigJSON)
	}))
	defer backend.Close()
	st := newTestStore(t)
	addSvc(st, backend.URL, "client")
	h := New(&config.Config{Domain: "example.com"}, st, http.NotFoundHandler()) // Compression off
	if rec := getVia(t, h, nil); rec.Header().Get("Content-Encoding") != "" {
		t.Error("compression happened although disabled")
	}
}
