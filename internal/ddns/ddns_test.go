package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lantern/internal/cf"
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

// ---- getPublicIP -------------------------------------------------------------

func TestGetPublicIP_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "  1.2.3.4  ")
	}))
	defer srv.Close()
	orig := ipifyURL
	ipifyURL = srv.URL
	defer func() { ipifyURL = orig }()

	ip, err := getPublicIP(context.Background())
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if ip != "1.2.3.4" {
		t.Errorf("getPublicIP = %q, want 1.2.3.4", ip)
	}
}

func TestGetPublicIP_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	orig := ipifyURL
	ipifyURL = srv.URL
	defer func() { ipifyURL = orig }()

	// Non-2xx does not cause an error from getPublicIP — it reads (empty) body.
	// The result will be empty string, which the caller handles.
	ip, err := getPublicIP(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "" {
		t.Errorf("expected empty ip on 500, got %q", ip)
	}
}

func TestGetPublicIP_Truncates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write more than 64 bytes — should be truncated.
		_, _ = fmt.Fprint(w, "1.2.3.4")
		for range 100 {
			_, _ = fmt.Fprint(w, "x")
		}
	}))
	defer srv.Close()
	orig := ipifyURL
	ipifyURL = srv.URL
	defer func() { ipifyURL = orig }()

	ip, err := getPublicIP(context.Background())
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if len(ip) > 64 {
		t.Errorf("ip not truncated: len=%d", len(ip))
	}
}

// ---- checkAndUpdate ----------------------------------------------------------

func TestCheckAndUpdate_SetsPublicIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "5.6.7.8")
	}))
	defer srv.Close()
	orig := ipifyURL
	ipifyURL = srv.URL
	defer func() { ipifyURL = orig }()

	st := newTestStore(t)
	// Add a DDNS domain so checkAndUpdate doesn't early-exit.
	st.AddDDNSDomain("home.example.com")

	cfClient, _ := cf.New("", "", "", "") // noop client
	m := New(&config.Config{}, st, cfClient)
	m.checkAndUpdate(context.Background())

	if got := st.GetPublicIP(); got != "5.6.7.8" {
		t.Errorf("GetPublicIP() = %q, want 5.6.7.8", got)
	}
}

func TestCheckAndUpdate_SkipsWhenIPUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "5.6.7.8")
	}))
	defer srv.Close()
	orig := ipifyURL
	ipifyURL = srv.URL
	defer func() { ipifyURL = orig }()

	st := newTestStore(t)
	st.AddDDNSDomain("home.example.com")
	st.SetPublicIP("5.6.7.8") // already up to date

	cfClient, _ := cf.New("", "", "", "")
	m := New(&config.Config{}, st, cfClient)

	// Run twice — second run should see same IP and not update the log.
	m.checkAndUpdate(context.Background())
	m.checkAndUpdate(context.Background())

	// IP should still be correct and no error should occur.
	if got := st.GetPublicIP(); got != "5.6.7.8" {
		t.Errorf("GetPublicIP() = %q, want 5.6.7.8", got)
	}
}

func TestCheckAndUpdate_NoDomains(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = fmt.Fprint(w, "5.6.7.8")
	}))
	defer srv.Close()
	orig := ipifyURL
	ipifyURL = srv.URL
	defer func() { ipifyURL = orig }()

	st := newTestStore(t) // no DDNS domains
	cfClient, _ := cf.New("", "", "", "")
	m := New(&config.Config{}, st, cfClient)
	m.checkAndUpdate(context.Background())

	if called {
		t.Error("expected ipify not to be called when no DDNS domains registered")
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// cfMock serves a minimal Cloudflare DNS API; failPatch makes record updates fail.
func cfMock(t *testing.T, records map[string]string, failPatch *bool) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			name := r.URL.Query().Get("name")
			if ip, ok := records[name]; ok {
				writeJSON(w, map[string]any{"success": true, "result": []map[string]string{{"id": "id-" + name, "content": ip}}})
				return
			}
			writeJSON(w, map[string]any{"success": true, "result": []string{}})
			return
		}
		var body struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		records[body.Name] = body.Content
		writeJSON(w, map[string]any{"success": true, "result": map[string]string{"id": "id-" + body.Name}})
	})
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		if failPatch != nil && *failPatch {
			_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"message":"boom"}]}`)
			return
		}
		name := r.URL.Path[len("/zones/zone1/dns_records/id-"):]
		var body struct {
			Content string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		records[name] = body.Content
		writeJSON(w, map[string]any{"success": true, "result": map[string]string{"id": "id-" + name}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)
}

func TestCheckAndUpdate_RetriesAfterFailure(t *testing.T) {
	ip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "9.9.9.9") }))
	defer ip.Close()
	orig := ipifyURL
	ipifyURL = ip.URL
	defer func() { ipifyURL = orig }()

	records := map[string]string{"home.example.com": "1.1.1.1"}
	fail := true
	cfMock(t, records, &fail)

	st := newTestStore(t)
	st.AddDDNSDomain("home.example.com")
	c, _ := cf.New("tok", "zone1", "", "")
	m := New(&config.Config{}, st, c)

	m.checkAndUpdate(context.Background())
	if st.GetPublicIP() == "9.9.9.9" {
		t.Fatal("public IP stored despite failed update; it would never be retried")
	}
	fail = false
	m.checkAndUpdate(context.Background())
	if records["home.example.com"] != "9.9.9.9" || st.GetPublicIP() != "9.9.9.9" {
		t.Errorf("retry did not fix record: records=%v stored=%q", records, st.GetPublicIP())
	}
}

func TestSyncServices_RepairsAndStoresIDs(t *testing.T) {
	records := map[string]string{"stale.example.com": "1.1.1.1"} // wrong IP; others missing
	cfMock(t, records, nil)

	st := newTestStore(t)
	st.AddService(&store.Service{ID: "a", Subdomain: "stale", Target: "http://x:1"})
	st.AddService(&store.Service{ID: "b", Subdomain: "gone", Target: "http://x:2"})
	st.AddService(&store.Service{ID: "c", Subdomain: "direct", Target: "http://x:3", DirectOnly: true})

	c, _ := cf.New("tok", "zone1", "", "")
	m := New(&config.Config{Domain: "example.com", ServerIP: "10.0.0.1"}, st, c)
	m.SyncServices(context.Background())

	for _, name := range []string{"stale", "gone", "lantern"} {
		if got := records[name+".example.com"]; got != "10.0.0.1" {
			t.Errorf("%s record = %q, want 10.0.0.1", name, got)
		}
	}
	if _, ok := records["direct.example.com"]; ok {
		t.Error("direct-only service must not get a DNS record")
	}
	if got := st.GetServiceByID("b").DNSRecordID; got != "id-gone.example.com" {
		t.Errorf("stored DNSRecordID = %q", got)
	}
}

func TestSyncServices_PointsTunnelRoutesAtLantern(t *testing.T) {
	var putBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, map[string]any{"success": true, "result": []string{}})
			return
		}
		writeJSON(w, map[string]any{"success": true, "result": map[string]string{"id": "cname1"}})
	})
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			putBody = string(b)
			writeJSON(w, map[string]any{"success": true, "result": map[string]any{}})
			return
		}
		writeJSON(w, map[string]any{"success": true, "result": map[string]any{"config": map[string]any{"ingress": []map[string]string{
			{"hostname": "plex.example.com", "service": "http://10.0.0.5:32400"},
			{"service": "http_status:404"},
		}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	st := newTestStore(t)
	st.AddService(&store.Service{ID: "a", Subdomain: "plex", Target: "http://10.0.0.5:32400", TunnelRouteID: "plex.example.com"})
	c, _ := cf.New("tok", "zone1", "tid", "acct")
	m := New(&config.Config{Domain: "example.com", ServerIP: "10.0.0.1"}, st, c)
	m.SyncServices(context.Background())

	if !strings.Contains(putBody, "https://localhost:443") || strings.Contains(putBody, "10.0.0.5") {
		t.Errorf("ingress not rewritten to Lantern: %s", putBody)
	}
}

// A store that lost TunnelRouteID must not fight an existing tunnel CNAME: the
// route is adopted from Cloudflare before the A-record path runs.
func TestSyncServices_AdoptsExistingTunnelRoute(t *testing.T) {
	var posts []string
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			posts = append(posts, body.Name)
			writeJSON(w, map[string]any{"success": true, "result": map[string]string{"id": "new"}})
			return
		}
		if r.URL.Query().Get("name") == "nextcloud.example.com" {
			writeJSON(w, map[string]any{"success": true, "result": []map[string]string{
				{"id": "rec-nc", "type": "CNAME", "content": "tid.cfargotunnel.com"},
			}})
			return
		}
		writeJSON(w, map[string]any{"success": true, "result": []string{}})
	})
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected record write: %s %s", r.Method, r.URL.Path)
		writeJSON(w, map[string]any{"success": true, "result": map[string]string{"id": "x"}})
	})
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			t.Error("unexpected ingress write; the rule already points at Lantern")
		}
		writeJSON(w, map[string]any{"success": true, "result": map[string]any{"config": map[string]any{"ingress": []map[string]any{
			{"hostname": "nextcloud.example.com", "service": "https://localhost:443", "originRequest": map[string]any{"noTLSVerify": true, "originServerName": "nextcloud.example.com"}},
			{"service": "http_status:404"},
		}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	st := newTestStore(t)
	st.AddService(&store.Service{ID: "nc", Subdomain: "nextcloud", Target: "http://10.0.0.5:8080"})
	c, _ := cf.New("tok", "zone1", "tid", "acct")
	m := New(&config.Config{Domain: "example.com", ServerIP: "10.0.0.1"}, st, c)
	m.SyncServices(context.Background())

	svc := st.GetServiceByID("nc")
	if svc.TunnelRouteID != "nextcloud.example.com" {
		t.Errorf("TunnelRouteID = %q, want adopted hostname", svc.TunnelRouteID)
	}
	if svc.DNSRecordID != "rec-nc" {
		t.Errorf("DNSRecordID = %q, want rec-nc", svc.DNSRecordID)
	}
	for _, name := range posts {
		if name == "nextcloud.example.com" {
			t.Errorf("created an A record for %s: an existing tunnel CNAME must not be fought", name)
		}
	}
}

// Strict adoption: a CNAME to some other tunnel (or an A record) never marks the
// service as tunneled, and direct-only services are ignored.
func TestSyncServices_DoesNotAdoptForeignOrARecords(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, map[string]any{"success": true, "result": map[string]string{"id": "new"}})
			return
		}
		if r.URL.Query().Get("type") == "A" {
			writeJSON(w, map[string]any{"success": true, "result": []string{}})
			return
		}
		switch r.URL.Query().Get("name") {
		case "foreign.example.com":
			writeJSON(w, map[string]any{"success": true, "result": []map[string]string{
				{"id": "rec-f", "type": "CNAME", "content": "other.cfargotunnel.com"},
			}})
		case "a.example.com":
			writeJSON(w, map[string]any{"success": true, "result": []map[string]string{
				{"id": "rec-a", "type": "A", "content": "10.0.0.9"},
			}})
		case "direct.example.com":
			writeJSON(w, map[string]any{"success": true, "result": []map[string]string{
				{"id": "rec-d", "type": "CNAME", "content": "tid.cfargotunnel.com"},
			}})
		default:
			writeJSON(w, map[string]any{"success": true, "result": []string{}})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	st := newTestStore(t)
	st.AddService(&store.Service{ID: "f", Subdomain: "foreign", Target: "http://10.0.0.5:1"})
	st.AddService(&store.Service{ID: "a", Subdomain: "a", Target: "http://10.0.0.5:2"})
	st.AddService(&store.Service{ID: "d", Subdomain: "direct", Target: "http://10.0.0.5:3", DirectOnly: true})
	c, _ := cf.New("tok", "zone1", "tid", "acct")
	m := New(&config.Config{Domain: "example.com"}, st, c)
	m.SyncServices(context.Background())

	for _, id := range []string{"f", "a", "d"} {
		if got := st.GetServiceByID(id).TunnelRouteID; got != "" {
			t.Errorf("service %s: TunnelRouteID = %q, want empty (not adopted)", id, got)
		}
	}
}
