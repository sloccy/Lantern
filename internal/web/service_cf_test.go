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

func newServiceTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	c, err := cf.New("tok", "zone1", "tid", "acct")
	if err != nil {
		t.Fatalf("cf.New: %v", err)
	}
	cfg := &config.Config{Domain: "example.com", ServerIP: "10.0.0.1"}
	return New(cfg, st, c, "test"), st
}

func postServiceForm(s *Server, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/services",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.createService(rec, req)
	return rec
}

func deleteServiceReq(s *Server, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/services/"+id, http.NoBody)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.deleteService(rec, req)
	return rec
}

// A re-add after a failed delete must adopt the surviving tunnel CNAME instead
// of trying to create an A record and colliding with it.
func TestCreateService_AdoptsExistingTunnelCNAME(t *testing.T) {
	var posts int
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			posts++
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{"id": "new"}})
			return
		}
		if r.URL.Query().Get("name") == "drive.example.com" {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": []map[string]string{
				{"id": "rec-c", "type": "CNAME", "content": "tid.cfargotunnel.com"},
			}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": []string{}})
	})
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected DNS write: %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{"id": "x"}})
	})
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]any{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]any{"config": map[string]any{"ingress": []map[string]any{
			{"service": "http_status:404"},
		}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	s, st := newServiceTestServer(t)
	rec := postServiceForm(s, url.Values{
		"name": {"Drive"}, "subdomain": {"drive"}, "target": {"http://127.0.0.1:1"},
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; trigger=%s", rec.Code, rec.Header().Get("Hx-Trigger"))
	}
	svc := st.GetServiceBySubdomain("drive")
	if svc == nil {
		t.Fatal("service was not stored")
	}
	if svc.TunnelRouteID != "drive.example.com" {
		t.Errorf("TunnelRouteID = %q, want drive.example.com", svc.TunnelRouteID)
	}
	if svc.DNSRecordID != "rec-c" {
		t.Errorf("DNSRecordID = %q, want rec-c", svc.DNSRecordID)
	}
	if posts != 0 {
		t.Errorf("created %d DNS records, want 0: the existing tunnel CNAME must be adopted", posts)
	}
}

// A CNAME pointing at a different tunnel must not be silently overwritten when
// the form did not ask for tunnel mode.
func TestCreateService_ForeignCNAMEIsConflict(t *testing.T) {
	var writes int
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes++
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{"id": "new"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": []map[string]string{
			{"id": "rec-f", "type": "CNAME", "content": "other.cfargotunnel.com"},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	s, st := newServiceTestServer(t)
	rec := postServiceForm(s, url.Values{
		"name": {"Files"}, "subdomain": {"files"}, "target": {"http://127.0.0.1:1"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if st.GetServiceBySubdomain("files") != nil {
		t.Error("conflicting service was persisted")
	}
	if writes != 0 {
		t.Errorf("DNS writes = %d, want 0", writes)
	}
	if trig := rec.Header().Get("Hx-Trigger"); !strings.Contains(trig, "other.cfargotunnel.com") {
		t.Errorf("toast should name the conflicting target, got %s", trig)
	}
}

// A Cloudflare failure during creation must leave the store untouched instead
// of persisting a service that has no DNS record.
func TestCreateService_CloudflareFailureDoesNotPersist(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": []string{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"errors":  []map[string]string{{"message": "boom"}},
			"result":  nil,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	s, st := newServiceTestServer(t)
	rec := postServiceForm(s, url.Values{
		"name": {"Broken"}, "subdomain": {"broken"}, "target": {"http://127.0.0.1:1"},
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if st.GetServiceBySubdomain("broken") != nil {
		t.Error("service was persisted despite the Cloudflare failure")
	}
}

// Switching off tunnel mode must not create the A record when removing the
// tunnel route failed: that A create is what produced the CNAME conflict.
func TestReconcileDNS_TunnelToAStopsWhenRemovalFails(t *testing.T) {
	var deleted, aCreates int
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted++
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{}})
	})
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			aCreates++
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{"id": "a-new"}})
	})
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false,
				"errors":  []map[string]string{{"message": "ingress down"}},
				"result":  nil,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]any{"config": map[string]any{"ingress": []map[string]any{
			{"hostname": "drive.example.com", "service": "https://localhost:443"},
			{"service": "http_status:404"},
		}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	s, _ := newServiceTestServer(t)
	old := dnsState{Subdomain: "drive", Tunnel: true, DNSRecordID: "rec-c", TunnelRouteID: "drive.example.com"}
	_, _, err := s.reconcileDNS(context.Background(), old, dnsState{Subdomain: "drive"})
	if err == nil {
		t.Fatal("reconcileDNS = nil error, want the ingress failure")
	}
	if deleted != 1 {
		t.Errorf("DNS deletes = %d, want 1 (DNS is removed before ingress)", deleted)
	}
	if aCreates != 0 {
		t.Errorf("A creates = %d, want 0 after a failed tunnel removal", aCreates)
	}
}

func TestDeleteService_ReportsCloudflareCleanupFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{}})
	})
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false,
				"errors":  []map[string]string{{"message": "ingress down"}},
				"result":  nil,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]any{"config": map[string]any{"ingress": []map[string]any{
			{"hostname": "drive.example.com", "service": "https://localhost:443"},
			{"service": "http_status:404"},
		}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	s, st := newServiceTestServer(t)
	st.AddService(&store.Service{
		ID: "drive", Name: "Drive", Subdomain: "drive", Target: "http://127.0.0.1:1",
		DNSRecordID: "rec-c", TunnelRouteID: "drive.example.com",
	})

	rec := deleteServiceReq(s, "drive")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 so the row is removed", rec.Code)
	}
	if st.GetServiceByID("drive") != nil {
		t.Error("service was not removed locally")
	}
	trig := rec.Header().Get("Hx-Trigger")
	if !strings.Contains(trig, "Cloudflare cleanup failed") || !strings.Contains(trig, `"type":"error"`) {
		t.Errorf("expected a cleanup error toast, got %s", trig)
	}
}

// The delete path must return within the configured Cloudflare budget even when
// the API never answers.
func TestDeleteService_BoundedTimeout(t *testing.T) {
	orig := cfOpTimeout
	cfOpTimeout = 100 * time.Millisecond
	t.Cleanup(func() { cfOpTimeout = orig })

	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]string{}})
	})
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cf.SetBaseURLForTest(t, srv.URL)

	s, st := newServiceTestServer(t)
	st.AddService(&store.Service{
		ID: "drive", Name: "Drive", Subdomain: "drive", Target: "http://127.0.0.1:1",
		DNSRecordID: "rec-c", TunnelRouteID: "drive.example.com",
	})

	start := time.Now()
	rec := deleteServiceReq(s, "drive")
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("delete took %v, want it bounded by cfOpTimeout (~100ms)", elapsed)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if st.GetServiceByID("drive") != nil {
		t.Error("service was not removed locally")
	}
	if trig := rec.Header().Get("Hx-Trigger"); !strings.Contains(trig, "Cloudflare cleanup failed") {
		t.Errorf("expected a cleanup error toast, got %s", trig)
	}
}
