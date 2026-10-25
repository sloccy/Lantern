package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
	cfg := &config.Config{Domain: "example.com", Compression: true}
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

// forwardedBackend reports the forwarding headers the backend received.
func forwardedBackend(t *testing.T) (*httptest.Server, *http.Header) {
	t.Helper()
	got := &http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestForwardedHeaders_TrustMatrix(t *testing.T) {
	tests := []struct {
		name       string
		remote     string
		cfIP, xff  string
		proto      string
		realIP     string
		wantIP     string
		wantProto  string
		wantCFSeen bool
	}{
		{"untrusted peer cannot spoof", "203.0.113.9:4000", "6.6.6.6", "7.7.7.7", "https", "8.8.8.8", "203.0.113.9", "http", false},
		{"loopback tunnel uses CF-Connecting-IP", "127.0.0.1:4000", "198.51.100.7", "", "https", "", "198.51.100.7", "https", true},
		{"loopback falls back to XFF", "[::1]:4000", "", "198.51.100.8, 10.0.0.1", "", "", "198.51.100.8", "http", false},
		{"loopback without headers", "127.0.0.1:4000", "", "", "", "", "127.0.0.1", "http", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, got := forwardedBackend(t)
			st := newTestStore(t)
			addSvc(st, backend.URL, "")
			h := newTestHandler(t, st, nil)

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
			req.Host = "test.example.com"
			req.RemoteAddr = tt.remote
			for k, v := range map[string]string{"Cf-Connecting-Ip": tt.cfIP, "X-Forwarded-For": tt.xff, "X-Forwarded-Proto": tt.proto, "X-Real-IP": tt.realIP} {
				if v != "" {
					req.Header.Set(k, v)
				}
			}
			h.ServeHTTP(rec, req)

			if v := got.Get("X-Real-IP"); v != tt.wantIP {
				t.Errorf("X-Real-IP = %q, want %q", v, tt.wantIP)
			}
			if v := got.Get("X-Forwarded-For"); v != tt.wantIP {
				t.Errorf("X-Forwarded-For = %q, want %q", v, tt.wantIP)
			}
			if v := got.Get("X-Forwarded-Proto"); v != tt.wantProto {
				t.Errorf("X-Forwarded-Proto = %q, want %q", v, tt.wantProto)
			}
			if seen := got.Get("Cf-Connecting-Ip") != ""; seen != tt.wantCFSeen {
				t.Errorf("CF-Connecting-IP reached backend = %v, want %v", seen, tt.wantCFSeen)
			}
		})
	}
}

func TestForwardedHeaders_ConfiguredTrustedProxy(t *testing.T) {
	backend, got := forwardedBackend(t)
	st := newTestStore(t)
	addSvc(st, backend.URL, "")
	cfg := &config.Config{Domain: "example.com", TrustedProxies: mustCIDRs(t, "10.0.0.0/8")}
	h := New(cfg, st, http.NotFoundHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "test.example.com"
	req.RemoteAddr = "10.1.2.3:5000"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	h.ServeHTTP(rec, req)
	if v := got.Get("X-Real-IP"); v != "198.51.100.1" {
		t.Errorf("X-Real-IP = %q, want 198.51.100.1", v)
	}
}

func mustCIDRs(t *testing.T, s string) []*net.IPNet {
	t.Helper()
	n, err := config.ParseTrustedProxies(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"App.Example.COM":     "app.example.com",
		"app.example.com:443": "app.example.com",
		"app.example.com.":    "app.example.com",
		"APP.example.com.:80": "app.example.com",
		"":                    "",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServeHTTP_MixedCaseHostRoutes(t *testing.T) {
	backend := hostEcho(t)
	st := newTestStore(t)
	addSvc(st, backend.URL, "")
	h := newTestHandler(t, st, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Host = "Test.Example.com."
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("mixed-case host: got %d, want 200", rec.Code)
	}
}

func TestHostMode_HTTPSBackendDefaultsToBackendHost(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	st := newTestStore(t)
	addSvc(st, srv.URL, "")
	h := newTestHandler(t, st, nil)

	want := strings.TrimPrefix(srv.URL, "https://")
	if got := serveOnce(t, h).Header().Get("X-Seen-Host"); got != want {
		t.Errorf("https backend saw Host %q, want %q", got, want)
	}

	// An explicit setting still wins.
	st2 := newTestStore(t)
	addSvc(st2, srv.URL, "client")
	h2 := newTestHandler(t, st2, nil)
	if got := serveOnce(t, h2).Header().Get("X-Seen-Host"); got != "test.example.com" {
		t.Errorf("explicit client mode saw Host %q, want test.example.com", got)
	}
}

func TestTransport_DeadBackendFailsFast(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: packets are dropped, so connect would hang.
	st := newTestStore(t)
	addSvc(st, "http://192.0.2.1:9", "client")
	h := newTestHandler(t, st, nil)

	start := time.Now()
	rec := serveOnce(t, h)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", rec.Code)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("took %v, want a dial timeout of about 3s", d)
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
	req.TLS = &tls.ConnectionState{} // client connected over HTTPS
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

// Tunnel (public) visitors get a generic 502; LAN visitors keep the detail.
func TestErrorPage_HidesBackendDetailFromTunnelVisitors(t *testing.T) {
	st := newTestStore(t)
	addSvc(st, "http://127.0.0.1:1", "client") // nothing listens: connection refused
	h := newTestHandler(t, st, nil)

	do := func(remote, cfIP string) string {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		req.Host = "test.example.com"
		req.RemoteAddr = remote
		if cfIP != "" {
			req.Header.Set("Cf-Connecting-Ip", cfIP)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("code = %d, want 502", rec.Code)
		}
		return rec.Body.String()
	}

	if body := do("127.0.0.1:5555", "203.0.113.9"); strings.Contains(body, "127.0.0.1:1") {
		t.Errorf("tunnel visitor saw backend address: %s", body)
	}
	if body := do("192.168.1.20:5555", ""); !strings.Contains(body, "127.0.0.1:1") {
		t.Errorf("LAN visitor should see the dial error, got: %s", body)
	}
}
