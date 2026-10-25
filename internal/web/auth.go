package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie  = "__Host-lantern_session" // __Host- prefix: Secure, Path=/, no Domain, never sent to subdomains
	sessionTTL     = 30 * 24 * time.Hour
	loginRetryWait = time.Second // minimum gap after a failed login attempt
)

// authenticator guards the management UI and write APIs with a single shared
// admin password. It is disabled (all requests allowed) when no password is set.
type authenticator struct {
	enabled  bool
	pwHash   [sha256.Size]byte
	key      []byte // HMAC key for session tokens
	mu       sync.Mutex
	lastFail time.Time
}

// newAuthenticator builds an authenticator. The HMAC key is persisted in
// dataDir so sessions survive restarts; deleting the file logs everyone out.
func newAuthenticator(password, dataDir string) *authenticator {
	a := &authenticator{}
	if password == "" {
		return a
	}
	a.enabled = true
	a.pwHash = sha256.Sum256([]byte(password))
	a.key = loadSessionKey(dataDir)
	return a
}

func loadSessionKey(dataDir string) []byte {
	path := filepath.Join(dataDir, "session.key")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 { //nolint:gosec // path is built from the configured data dir
		return b
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("web: generate session key: %v", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		log.Printf("web: could not persist session key (%v); logins will reset on restart", err)
	}
	return key
}

func (a *authenticator) sign(payload string) string {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// newToken returns a signed session token that expires at the given time.
func (a *authenticator) newToken(expires time.Time) string {
	payload := strconv.FormatInt(expires.Unix(), 10)
	return payload + "." + a.sign(payload)
}

// validToken reports whether tok is correctly signed and unexpired.
func (a *authenticator) validToken(tok string) bool {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(a.sign(payload))) {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	return err == nil && time.Now().Unix() < exp
}

func (a *authenticator) authenticated(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && a.validToken(c.Value)
}

// checkPassword compares in constant time. It returns tooSoon=true (without
// checking) when the previous attempt failed less than loginRetryWait ago, which
// caps online guessing at about one try per second.
func (a *authenticator) checkPassword(pw string) (ok, tooSoon bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.lastFail) < loginRetryWait {
		return false, true
	}
	got := sha256.Sum256([]byte(pw))
	if subtle.ConstantTimeCompare(got[:], a.pwHash[:]) == 1 {
		return true, false
	}
	a.lastFail = time.Now()
	return false, false
}

// isPublic lists what stays reachable without logging in: the read-only
// dashboard, its static assets, and the login/logout endpoints.
func isPublic(r *http.Request) bool {
	p := r.URL.Path
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		switch p {
		case "/", "/login", "/api/health",
			"/fragments/services", "/fragments/bookmarks", "/fragments/sysinfo":
			return true
		}
		if strings.HasPrefix(p, "/api/favicon/") || strings.HasPrefix(p, "/api/icons/") {
			return true
		}
		_, isAsset := getStaticAssets()[p]
		return isAsset
	case http.MethodPost:
		return p == "/login" || p == "/logout"
	}
	return false
}

// middleware rejects non-public requests that lack a valid session.
func (a *authenticator) middleware(next http.Handler) http.Handler {
	if !a.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublic(r) || a.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case r.Header.Get("Hx-Request") != "":
			w.Header().Set("Hx-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			apiError(w, http.StatusUnauthorized, "login required")
		case r.Method == http.MethodGet:
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		default:
			http.Error(w, "login required", http.StatusUnauthorized)
		}
	})
}

// safeNext returns next only if it is a same-site relative path, else "/".
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.auth.enabled || s.auth.authenticated(r) {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther) //nolint:gosec // safeNext only returns same-site relative paths
		return
	}
	renderPage(w, loginTmpl, pageData{Version: s.version, Next: safeNext(r.URL.Query().Get("next"))})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.auth.enabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}
	next := safeNext(r.FormValue("next"))
	ok, tooSoon := s.auth.checkPassword(r.FormValue("password"))
	if !ok {
		msg, code := "Incorrect password.", http.StatusUnauthorized
		if tooSoon {
			msg, code = "Too many attempts. Wait a second and try again.", http.StatusTooManyRequests
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		renderPage(w, loginTmpl, pageData{Version: s.version, Next: next, LoginError: msg})
		return
	}
	expires := time.Now().Add(sessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.auth.newToken(expires), Path: "/",
		Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next went through safeNext (same-site relative path only)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
