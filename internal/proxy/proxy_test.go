package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lantern/internal/config"
	"lantern/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return st
}

func newTestHandler(t *testing.T, st *store.Store, webHandler http.Handler) *Handler {
	t.Helper()
	cfg := &config.Config{Domain: "example.com"}
	if webHandler == nil {
		webHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	return New(cfg, st, webHandler)
}

func TestServeHTTP_LanternHost(t *testing.T) {
	webCalled := false
	web := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webCalled = true
		w.WriteHeader(http.StatusOK)
	})
	h := newTestHandler(t, newTestStore(t), web)

	for _, host := range []string{"lantern.example.com", "example.com", ""} {
		webCalled = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		req.Host = host
		h.ServeHTTP(rec, req)
		if !webCalled {
			t.Errorf("host %q: expected webHandler to be called", host)
		}
	}
}

func TestServeHTTP_UnknownHost(t *testing.T) {
	h := newTestHandler(t, newTestStore(t), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "unknown.other.com"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown host: got %d, want 404", rec.Code)
	}
}

func TestServeHTTP_MissingService(t *testing.T) {
	h := newTestHandler(t, newTestStore(t), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "noservice.example.com"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("missing service: got %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("missing service: Content-Type = %q, want text/html", ct)
	}
}

func TestServeHTTP_ProxyToBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()

	st := newTestStore(t)
	st.AddService(&store.Service{
		ID:        "svc1",
		Name:      "Test",
		Subdomain: "test",
		Target:    backend.URL,
	})

	h := newTestHandler(t, st, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "test.example.com"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("proxy: got %d, want 418", rec.Code)
	}
}

func TestServeHTTP_LocationRewrite(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHost := r.Host
		http.Redirect(w, r, "http://"+backendHost+"/newpath", http.StatusFound) //nolint:gosec // test handler uses a controlled in-process host, not user input
	}))
	defer backend.Close()

	st := newTestStore(t)
	st.AddService(&store.Service{
		ID:        "svc2",
		Name:      "Redirect",
		Subdomain: "redir",
		Target:    backend.URL,
		HostMode:  "backend", // the backend then sees (and redirects to) its own address
	})

	h := newTestHandler(t, st, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "redir.example.com"
	h.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://redir.example.com") {
		t.Errorf("Location rewrite: got %q, want https://redir.example.com/...", loc)
	}
}

func TestServeHTTP_XForwardedProto(t *testing.T) {
	var gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := newTestStore(t)
	st.AddService(&store.Service{
		ID:        "svc3",
		Name:      "Proto",
		Subdomain: "proto",
		Target:    backend.URL,
	})

	h := newTestHandler(t, st, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "proto.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(rec, req)

	if gotProto != "https" {
		t.Errorf("X-Forwarded-Proto: got %q, want https", gotProto)
	}
}

func TestRealIP(t *testing.T) {
	tests := []struct {
		name       string
		realIP     string
		forwarded  string
		remoteAddr string
		want       string
	}{
		{"X-Real-IP wins", "1.2.3.4", "5.6.7.8", "9.10.11.12:9999", "1.2.3.4"},
		{"X-Forwarded-For first", "", "5.6.7.8, 9.10.11.12", "13.14.15.16:9999", "5.6.7.8"},
		{"RemoteAddr fallback", "", "", "9.10.11.12:9999", "9.10.11.12:9999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = tt.remoteAddr
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			if got := realIP(req); got != tt.want {
				t.Errorf("realIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBufferPool(t *testing.T) {
	var pool bufferPool
	buf := pool.Get()
	if len(buf) != 32*1024 {
		t.Errorf("Get: len = %d, want %d", len(buf), 32*1024)
	}
	pool.Put(buf)
	buf2 := pool.Get()
	if len(buf2) != 32*1024 {
		t.Errorf("Get after Put: len = %d, want %d", len(buf2), 32*1024)
	}
}

// hostEcho returns a backend that reports the Host and X-Forwarded-Host it received.
func hostEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-Forwarded-Host", r.Header.Get("X-Forwarded-Host"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serveOnce(t *testing.T, h *Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "test.example.com"
	h.ServeHTTP(rec, req)
	return rec
}

func addSvc(st *store.Store, backendURL, hostMode string) {
	st.AddService(&store.Service{ID: "s1", Name: "S", Subdomain: "test", Target: backendURL, HostMode: hostMode})
}

func TestHostMode_AutoPassesClientHost(t *testing.T) {
	backend := hostEcho(t)
	st := newTestStore(t)
	addSvc(st, backend.URL, "")
	h := newTestHandler(t, st, nil)

	rec := serveOnce(t, h)
	if got := rec.Header().Get("X-Seen-Host"); got != "test.example.com" {
		t.Errorf("backend Host: got %q, want test.example.com", got)
	}
	if got := rec.Header().Get("X-Seen-Forwarded-Host"); got != "test.example.com" {
		t.Errorf("X-Forwarded-Host: got %q, want test.example.com", got)
	}
}

// strictHostBackend rejects any Host other than its own, like Django ALLOWED_HOSTS.
func strictHostBackend(t *testing.T, status int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != strings.TrimPrefix(srv.URL, "http://") {
			http.Error(w, "bad host", status)
			return
		}
		w.Header().Set("X-Seen-Host", r.Host)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHostMode_AutoFallsBackToBackendHost(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusMisdirectedRequest} {
		backend := strictHostBackend(t, status)
		st := newTestStore(t)
		addSvc(st, backend.URL, "")
		h := newTestHandler(t, st, nil)

		rec := serveOnce(t, h)
		if rec.Code != http.StatusOK {
			t.Errorf("status %d: proxied code %d, want 200", status, rec.Code)
		}
		want := strings.TrimPrefix(backend.URL, "http://")
		if got := rec.Header().Get("X-Seen-Host"); got != want {
			t.Errorf("status %d: backend Host %q, want %q", status, got, want)
		}
	}
}

func TestHostMode_AutoKeepsClientWhenBothRejected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	t.Cleanup(backend.Close)
	st := newTestStore(t)
	addSvc(st, backend.URL, "")
	h := newTestHandler(t, st, nil)

	serveOnce(t, h)
	v, _ := h.hostModes.Load("test")
	if e, ok := v.(*hostEntry); !ok || e.mode != hostClient {
		t.Errorf("mode = %+v, want client", v)
	}
}

func TestHostMode_ExplicitOverrides(t *testing.T) {
	backend := hostEcho(t)
	own := strings.TrimPrefix(backend.URL, "http://")

	st := newTestStore(t)
	addSvc(st, backend.URL, "backend")
	h := newTestHandler(t, st, nil)
	if got := serveOnce(t, h).Header().Get("X-Seen-Host"); got != own {
		t.Errorf("backend mode: Host %q, want %q", got, own)
	}

	// Strict backend would trigger auto fallback; explicit client must not.
	strict := strictHostBackend(t, http.StatusBadRequest)
	st2 := newTestStore(t)
	addSvc(st2, strict.URL, "client")
	h2 := newTestHandler(t, st2, nil)
	if code := serveOnce(t, h2).Code; code != http.StatusBadRequest {
		t.Errorf("client mode: code %d, want 400", code)
	}
}

func TestHostMode_TargetChangeRedetects(t *testing.T) {
	strict := strictHostBackend(t, http.StatusBadRequest)
	plain := hostEcho(t)
	st := newTestStore(t)
	addSvc(st, strict.URL, "")
	h := newTestHandler(t, st, nil)
	serveOnce(t, h)

	st.UpdateService("s1", &store.Service{ID: "s1", Name: "S", Subdomain: "test", Target: plain.URL})
	if got := serveOnce(t, h).Header().Get("X-Seen-Host"); got != "test.example.com" {
		t.Errorf("after target change: backend Host %q, want client Host", got)
	}
}

func TestHostMode_LocationUpgradedToHTTPS(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+"/newpath", http.StatusFound) //nolint:gosec // test handler uses a controlled in-process host, not user input
	}))
	t.Cleanup(backend.Close)
	st := newTestStore(t)
	addSvc(st, backend.URL, "")
	h := newTestHandler(t, st, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "test.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); loc != "https://test.example.com/newpath" {
		t.Errorf("Location: got %q, want https://test.example.com/newpath", loc)
	}
}

// TestServeHTTP_WebSocketOrigin mirrors Dozzle: the backend rejects the upgrade
// unless the Origin host matches the Host it was sent.
func TestServeHTTP_WebSocketOrigin(t *testing.T) {
	for _, mode := range []string{"", "client", "backend"} {
		t.Run("mode="+mode, func(t *testing.T) { testWebSocketOrigin(t, mode) })
	}
}

func testWebSocketOrigin(t *testing.T, hostMode string) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin, err := url.Parse(r.Header.Get("Origin"))
		if err != nil || origin.Host != r.Host {
			http.Error(w, "origin mismatch", http.StatusForbidden)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buf.Flush()
	}))
	defer backend.Close()

	st := newTestStore(t)
	st.AddService(&store.Service{ID: "w1", Name: "WS", Subdomain: "ws", Target: backend.URL, HostMode: hostMode})
	front := httptest.NewServer(newTestHandler(t, st, nil))
	defer front.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL+"/attach", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "ws.example.com"
	req.Header.Set("Origin", "https://ws.example.com")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("status: got %d, want 101", resp.StatusCode)
	}
}

// A backend that serves pages for any Host but only accepts WebSocket upgrades
// addressed to its own host (the UniFi pattern) must still end up connected.
func TestHostMode_WebSocketFallsBackToBackend(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Host != strings.TrimPrefix(srv.URL, "http://") {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buf.Flush()
	}))
	defer srv.Close()

	st := newTestStore(t)
	st.AddService(&store.Service{ID: "u1", Name: "U", Subdomain: "ws", Target: srv.URL})
	h := newTestHandler(t, st, nil)
	front := httptest.NewServer(h)
	defer front.Close()

	dial := func() int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL+"/api/ws", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "ws.example.com"
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if got := dial(); got != http.StatusSwitchingProtocols {
		t.Fatalf("first upgrade: status %d, want 101", got)
	}
	v, _ := h.hostModes.Load("ws")
	if e, ok := v.(*hostEntry); !ok || e.mode != hostBackend {
		t.Errorf("mode after fallback = %+v, want backend", v)
	}
	if got := dial(); got != http.StatusSwitchingProtocols {
		t.Errorf("second upgrade: status %d, want 101", got)
	}
}
