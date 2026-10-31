package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lantern/internal/cf"
	"lantern/internal/config"
	"lantern/internal/ddns"
	"lantern/internal/store"
)

// The edit form must reflect Cloudflare's live state: a service whose store
// entry lost TunnelRouteID but whose CNAME points at the tunnel should render
// with the checkbox already ticked (and be adopted in the store).
func TestServiceFormEdit_AdoptsExistingTunnelRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "nextcloud.example.com" {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": []string{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": []map[string]string{
			{"id": "rec-nc", "type": "CNAME", "content": "tid.cfargotunnel.com"},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	cfg := &config.Config{Domain: "example.com"}
	c, _ := cf.New("tok", "zone1", "tid", "acct")

	s := New(cfg, st, c, "test")
	s.SetDDNSManager(ddns.New(cfg, st, c))

	st.AddService(&store.Service{ID: "nc", Name: "Nextcloud", Subdomain: "nextcloud", Target: "http://10.0.0.5:8080"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fragments/service-form/nc", http.NoBody)
	req.SetPathValue("id", "nc")
	rec := httptest.NewRecorder()
	s.fragServiceFormEdit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := st.GetServiceByID("nc").TunnelRouteID; got != "nextcloud.example.com" {
		t.Errorf("TunnelRouteID = %q, want adopted hostname", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, `name="tunnel" checked`) {
		t.Errorf("tunnel checkbox not rendered checked; body:\n%s", body)
	}
}
