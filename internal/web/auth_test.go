package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"lantern/internal/cf"
	"lantern/internal/config"
	"lantern/internal/store"
)

func newAuthTestServer(t *testing.T, password string) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	c, _ := cf.New("", "", "", "")
	return New(&config.Config{Domain: "example.com", DataDir: dir, AdminPassword: password}, st, c, "test")
}

func do(s *Server, method, path string, hdr map[string]string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, body)
	req.Host = "lantern.example.com"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func sessionFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

func TestAuth_PublicPathsOpenProtectedPathsLocked(t *testing.T) {
	s := newAuthTestServer(t, "secret")

	for _, p := range []string{"/", "/login", "/fragments/services", "/api/health", "/style.css"} {
		if rec := do(s, http.MethodGet, p, nil, nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, rec.Code)
		}
	}

	rec := do(s, http.MethodGet, "/manage", nil, nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
		t.Errorf("GET /manage = %d → %q, want redirect to login", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(s, http.MethodPost, "/api/services", nil, url.Values{"subdomain": {"x"}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/services = %d, want 401", rec.Code)
	}
	if rec := do(s, http.MethodGet, "/fragments/status", map[string]string{"Hx-Request": "true"}, nil); rec.Code != http.StatusUnauthorized || rec.Header().Get("Hx-Redirect") != "/login" {
		t.Errorf("htmx fragment = %d redirect %q, want 401 + HX-Redirect", rec.Code, rec.Header().Get("Hx-Redirect"))
	}
}

func TestAuth_LoginFlow(t *testing.T) {
	s := newAuthTestServer(t, "secret")

	rec := do(s, http.MethodPost, "/login", nil, url.Values{"password": {"wrong"}})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password = %d, want 401", rec.Code)
	}
	// Immediate retry is throttled, even with the right password.
	if rec := do(s, http.MethodPost, "/login", nil, url.Values{"password": {"secret"}}); rec.Code != http.StatusTooManyRequests {
		t.Errorf("retry right after failure = %d, want 429", rec.Code)
	}
	s.auth.lastFail = time.Time{}

	rec = do(s, http.MethodPost, "/login", nil, url.Values{"password": {"secret"}, "next": {"/manage"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/manage" {
		t.Fatalf("login = %d → %q, want redirect to /manage", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionFrom(t, rec)
	if !c.Secure || !c.HttpOnly || c.Path != "/" {
		t.Errorf("cookie must be Secure, HttpOnly, Path=/: %+v", c)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/manage", http.NoBody)
	req.Host = "lantern.example.com"
	req.AddCookie(c)
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Errorf("GET /manage with session = %d, want 200", rec2.Code)
	}
}

func TestAuth_TokenValidation(t *testing.T) {
	a := newAuthenticator("pw", t.TempDir())
	if !a.validToken(a.newToken(time.Now().Add(time.Hour))) {
		t.Error("fresh token rejected")
	}
	if a.validToken(a.newToken(time.Now().Add(-time.Hour))) {
		t.Error("expired token accepted")
	}
	tok := a.newToken(time.Now().Add(time.Hour))
	_, sig, _ := strings.Cut(tok, ".")
	if a.validToken("9999999999." + sig) {
		t.Error("tampered expiry accepted")
	}
	if a.validToken("garbage") || a.validToken("") {
		t.Error("garbage token accepted")
	}
	if b := newAuthenticator("pw", t.TempDir()); b.validToken(tok) {
		t.Error("token from another key accepted")
	}
}

func TestAuth_SessionKeyPersists(t *testing.T) {
	dir := t.TempDir()
	tok := newAuthenticator("pw", dir).newToken(time.Now().Add(time.Hour))
	if !newAuthenticator("pw", dir).validToken(tok) {
		t.Error("session should survive a restart")
	}
}

func TestAuth_SafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/":                "/",
		"/manage":          "/manage",
		"/manage?x=1":      "/", // only exact allowlist entries survive
		"//evil.com":       "/",
		"/\\evil.com":      "/",
		"/\t/evil.com":     "/", // browsers strip the tab, leaving //evil.com
		"https://evil.com": "/",
		"":                 "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuth_CheckPassword(t *testing.T) {
	a := newAuthenticator("secret", t.TempDir())

	if ok, tooSoon := a.checkPassword("wrong"); ok || tooSoon {
		t.Errorf("wrong password = (ok %v, tooSoon %v), want (false, false)", ok, tooSoon)
	}
	if _, tooSoon := a.checkPassword("secret"); !tooSoon {
		t.Error("attempt right after a failure should be throttled")
	}
	a.lastFail = time.Time{}
	if ok, _ := a.checkPassword("secret"); !ok {
		t.Error("right password rejected")
	}
}

func TestAuth_DisabledWithoutPassword(t *testing.T) {
	s := newAuthTestServer(t, "")
	if rec := do(s, http.MethodGet, "/manage", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("GET /manage without auth configured = %d, want 200", rec.Code)
	}
}

func TestCrossOriginWritesRejected(t *testing.T) {
	s := newAuthTestServer(t, "")
	form := url.Values{"subdomain": {"x"}, "target": {"http://10.0.0.1"}}
	if rec := do(s, http.MethodPost, "/api/services", map[string]string{"Sec-Fetch-Site": "cross-site"}, form); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", rec.Code)
	}
	if rec := do(s, http.MethodPost, "/api/services", map[string]string{"Origin": "https://evil.example"}, form); rec.Code != http.StatusForbidden {
		t.Errorf("foreign-Origin POST = %d, want 403", rec.Code)
	}
	if rec := do(s, http.MethodPost, "/api/services", map[string]string{"Sec-Fetch-Site": "same-origin"}, form); rec.Code == http.StatusForbidden {
		t.Errorf("same-origin POST was blocked")
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newAuthTestServer(t, "")
	h := do(s, http.MethodGet, "/", nil, nil).Header()
	for _, k := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"} {
		if h.Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
}

func TestReservedSubdomainRejected(t *testing.T) {
	s := newAuthTestServer(t, "")
	rec := do(s, http.MethodPost, "/api/services", map[string]string{"Sec-Fetch-Site": "same-origin"},
		url.Values{"subdomain": {"Lantern"}, "target": {"http://10.0.0.1:80"}, "name": {"x"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("creating subdomain 'lantern' = %d, want 400", rec.Code)
	}
	if s.store.GetServiceBySubdomain("lantern") != nil {
		t.Error("reserved subdomain was stored")
	}
}

// The login button must use the app's amber primary style, not Bootstrap's blue.
func TestLoginPage_UsesThemedButton(t *testing.T) {
	s := newAuthTestServer(t, "secret")
	body := do(s, http.MethodGet, "/login", nil, nil).Body.String()
	if !strings.Contains(body, "btn-warning") || strings.Contains(body, "btn-primary") {
		t.Errorf("login button should use btn-warning (theme), not btn-primary")
	}
}
