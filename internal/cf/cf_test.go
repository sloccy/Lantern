package cf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// cfServer stands up an httptest.Server and redirects cfBaseURL to it,
// restoring the original on cleanup.
func cfServer(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	srv := httptest.NewServer(mux)
	orig := cfBaseURL
	cfBaseURL = srv.URL
	t.Cleanup(func() {
		srv.Close()
		cfBaseURL = orig
	})
}

func cfOK(result any) []byte {
	env := map[string]any{"success": true, "result": result}
	b, _ := json.Marshal(env)
	return b
}

func cfError(msg string) []byte {
	env := map[string]any{
		"success": false,
		"errors":  []map[string]any{{"message": msg}},
		"result":  nil,
	}
	b, _ := json.Marshal(env)
	return b
}

// ---- New / noop ---------------------------------------------------------------

func TestNew_NoopWhenEmptyToken(t *testing.T) {
	c, err := New("", "", "", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.noop {
		t.Error("expected noop=true for empty token")
	}
}

func TestTunnelEnabled(t *testing.T) {
	tests := []struct {
		name      string
		noop      bool
		tunnelID  string
		accountID string
		want      bool
	}{
		{"noop", true, "tid", "aid", false},
		{"no tunnelID", false, "", "aid", false},
		{"no accountID", false, "tid", "", false},
		{"all set", false, "tid", "aid", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{noop: tt.noop, tunnelID: tt.tunnelID, accountID: tt.accountID}
			if got := c.TunnelEnabled(); got != tt.want {
				t.Errorf("TunnelEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTunnelAvailable(t *testing.T) {
	tests := []struct {
		name      string
		noop      bool
		accountID string
		want      bool
	}{
		{"noop", true, "aid", false},
		{"no accountID", false, "", false},
		{"available", false, "aid", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{noop: tt.noop, accountID: tt.accountID}
			if got := c.TunnelAvailable(); got != tt.want {
				t.Errorf("TunnelAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---- removeHostname ----------------------------------------------------------

func TestRemoveHostname(t *testing.T) {
	rules := []ingressRule{
		{Hostname: "a.example.com", Service: "http://a"},
		{Hostname: "b.example.com", Service: "http://b"},
		{Hostname: "a.example.com", Service: "http://a2"},
	}
	got := removeHostname(rules, "a.example.com")
	if len(got) != 1 || got[0].Hostname != "b.example.com" {
		t.Errorf("removeHostname: got %+v", got)
	}
}

// ---- FindRecord ---------------------------------------------------------------

func TestFindRecord_Found(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(cfOK([]dnsRecord{{ID: "rec1", Content: "1.2.3.4"}}))
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	id, ip, err := c.FindRecord(context.Background(), "test.example.com")
	if err != nil {
		t.Fatalf("FindRecord: %v", err)
	}
	if id != "rec1" || ip != "1.2.3.4" {
		t.Errorf("FindRecord = (%q, %q), want (rec1, 1.2.3.4)", id, ip)
	}
}

func TestFindRecord_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(cfOK([]dnsRecord{}))
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	id, ip, err := c.FindRecord(context.Background(), "notfound.example.com")
	if err != nil {
		t.Fatalf("FindRecord: %v", err)
	}
	if id != "" || ip != "" {
		t.Errorf("FindRecord = (%q, %q), want empty", id, ip)
	}
}

// ---- EnsureARecord -----------------------------------------------------------

func TestEnsureARecord_Creates(t *testing.T) {
	var method string
	mux := http.NewServeMux()
	// FindRecord returns empty (no existing record).
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write(cfOK([]dnsRecord{}))
		} else {
			method = r.Method
			_, _ = w.Write(cfOK(dnsRecord{ID: "new1"}))
		}
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	if err := c.EnsureARecord(context.Background(), "test.example.com", "1.2.3.4"); err != nil {
		t.Fatalf("EnsureARecord: %v", err)
	}
	if method != http.MethodPost {
		t.Errorf("expected POST to create record, got %s", method)
	}
}

func TestEnsureARecord_NoOp(t *testing.T) {
	var patchCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write(cfOK([]dnsRecord{{ID: "rec1", Content: "1.2.3.4"}}))
		} else {
			patchCalled = true
			_, _ = w.Write(cfOK(dnsRecord{ID: "rec1"}))
		}
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	if err := c.EnsureARecord(context.Background(), "test.example.com", "1.2.3.4"); err != nil {
		t.Fatalf("EnsureARecord: %v", err)
	}
	if patchCalled {
		t.Error("expected no PATCH when IP unchanged")
	}
}

func TestEnsureARecord_Updates(t *testing.T) {
	var patchCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write(cfOK([]dnsRecord{{ID: "rec1", Content: "1.1.1.1"}}))
		}
	})
	mux.HandleFunc("/zones/zone1/dns_records/rec1", func(w http.ResponseWriter, r *http.Request) {
		patchCalled = true
		_, _ = w.Write(cfOK(dnsRecord{ID: "rec1"}))
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	if err := c.EnsureARecord(context.Background(), "test.example.com", "2.2.2.2"); err != nil {
		t.Fatalf("EnsureARecord: %v", err)
	}
	if !patchCalled {
		t.Error("expected PATCH when IP changed")
	}
}

// ---- Error envelope ----------------------------------------------------------

func TestAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(cfError("Zone not found"))
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	_, _, err := c.FindRecord(context.Background(), "test.example.com")
	if err == nil {
		t.Fatal("expected error from CF error envelope")
	}
	if got := err.Error(); got == "" {
		t.Error("expected non-empty error message")
	}
}

// ---- Noop operations ---------------------------------------------------------

func TestNoopOperations(t *testing.T) {
	c, _ := New("", "", "", "")
	ctx := context.Background()

	if err := c.EnsureARecord(ctx, "x", "1.2.3.4"); err != nil {
		t.Errorf("noop EnsureARecord: %v", err)
	}
	if _, _, err := c.FindRecord(ctx, "x"); err != nil {
		t.Errorf("noop FindRecord: %v", err)
	}
	if err := c.DeleteRecord(ctx, "id1"); err != nil {
		t.Errorf("noop DeleteRecord: %v", err)
	}
	if err := c.UpdateRecord(ctx, "id1", "1.2.3.4"); err != nil {
		t.Errorf("noop UpdateRecord: %v", err)
	}
	if cnameID, err := c.AddTunnelRoute(ctx, "h"); err != nil || cnameID != "" {
		t.Errorf("noop AddTunnelRoute: id=%q err=%v", cnameID, err)
	}
	if err := c.RemoveTunnelRoute(ctx, "h", "id1"); err != nil {
		t.Errorf("noop RemoveTunnelRoute: %v", err)
	}
}

// ---- UpsertARecord / EnsureCNAME ---------------------------------------------

func TestUpsertARecord_ReturnsIDs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("name") == "exists.example.com":
			if r.URL.Query().Get("type") != "A" {
				t.Errorf("type query = %q, want A", r.URL.Query().Get("type"))
			}
			_, _ = w.Write(cfOK([]dnsRecord{{ID: "rec1", Content: "1.2.3.4"}}))
		case r.Method == http.MethodGet:
			_, _ = w.Write(cfOK([]dnsRecord{}))
		default:
			_, _ = w.Write(cfOK(dnsRecord{ID: "new1"}))
		}
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "", "")
	if id, err := c.UpsertARecord(context.Background(), "exists.example.com", "1.2.3.4"); err != nil || id != "rec1" {
		t.Errorf("existing: id=%q err=%v, want rec1", id, err)
	}
	if id, err := c.UpsertARecord(context.Background(), "new.example.com", "1.2.3.4"); err != nil || id != "new1" {
		t.Errorf("missing: id=%q err=%v, want new1", id, err)
	}
}

func TestEnsureCNAME(t *testing.T) {
	var created, patched bool
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			switch r.URL.Query().Get("name") {
			case "ok.example.com":
				_, _ = w.Write(cfOK([]dnsRecord{{ID: "c1", Content: "tid.cfargotunnel.com"}}))
			case "stale.example.com":
				_, _ = w.Write(cfOK([]dnsRecord{{ID: "c2", Content: "old.cfargotunnel.com"}}))
			default:
				_, _ = w.Write(cfOK([]dnsRecord{}))
			}
			return
		}
		created = true
		_, _ = w.Write(cfOK(dnsRecord{ID: "c3"}))
	})
	mux.HandleFunc("/zones/zone1/dns_records/c2", func(w http.ResponseWriter, r *http.Request) {
		patched = true
		_, _ = w.Write(cfOK(dnsRecord{ID: "c2"}))
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "tid", "acct")
	ctx := context.Background()
	if id, err := c.EnsureCNAME(ctx, "ok.example.com"); err != nil || id != "c1" {
		t.Errorf("ok: id=%q err=%v", id, err)
	}
	if id, err := c.EnsureCNAME(ctx, "stale.example.com"); err != nil || id != "c2" || !patched {
		t.Errorf("stale: id=%q err=%v patched=%v", id, err, patched)
	}
	if id, err := c.EnsureCNAME(ctx, "missing.example.com"); err != nil || id != "c3" || !created {
		t.Errorf("missing: id=%q err=%v created=%v", id, err, created)
	}
}

// ---- AddTunnelRoute / RemoveTunnelRoute ---------------------------------------

// tunnelAndDNSMock serves both the tunnel config and DNS endpoints so
// AddTunnelRoute can be exercised end to end.
type tunnelAndDNSMock struct {
	rules       []ingressRule
	ingressPUTs int
	dnsWrites   []string // "METHOD REC_ID" for writes against an existing record
	creations   []string // one entry per record created via POST /dns_records
	deletions   []string
}

func newTunnelAndDNSMock(t *testing.T, initialRules []ingressRule, records []dnsRecord) *tunnelAndDNSMock {
	t.Helper()
	m := &tunnelAndDNSMock{rules: initialRules}
	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body struct {
				Config struct {
					Ingress []ingressRule `json:"ingress"`
				} `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.ingressPUTs++
			m.rules = body.Config.Ingress
			_, _ = w.Write(cfOK(map[string]any{}))
			return
		}
		_, _ = w.Write(cfOK(map[string]any{"config": map[string]any{"ingress": m.rules}}))
	})
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(cfOK(records))
		case http.MethodPost:
			m.creations = append(m.creations, "POST")
			_, _ = w.Write(cfOK(dnsRecord{ID: "created"}))
		default:
			_, _ = w.Write(cfOK(dnsRecord{}))
		}
	})
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/zones/zone1/dns_records/"):]
		switch r.Method {
		case http.MethodDelete:
			m.deletions = append(m.deletions, id)
			_, _ = w.Write(cfOK(dnsRecord{}))
		default:
			var body dnsRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.dnsWrites = append(m.dnsWrites, r.Method+" "+id+" "+body.Type+" "+body.Content)
			_, _ = w.Write(cfOK(dnsRecord{ID: id}))
		}
	})
	cfServer(t, mux)
	return m
}

func TestAddTunnelRoute_AdoptsExistingRecordInPlace(t *testing.T) {
	// A pre-existing A record (from an old enable attempt) occupies the hostname.
	m := newTunnelAndDNSMock(t, nil, []dnsRecord{{ID: "rec-a", Type: "A", Content: "5.6.7.8"}})
	c, _ := New("tok", "zone1", "tid", "acct")

	id, err := c.AddTunnelRoute(context.Background(), "drive.example.com")
	if err != nil || id != "rec-a" {
		t.Fatalf("AddTunnelRoute = (%q, %v), want (rec-a, nil)", id, err)
	}
	if len(m.deletions) != 0 {
		t.Errorf("deletions = %v, want none — enabling must not delete records", m.deletions)
	}
	if len(m.creations) != 0 {
		t.Errorf("creations = %v, want none", m.creations)
	}
	if len(m.dnsWrites) != 1 || m.dnsWrites[0] != "PUT rec-a CNAME tid.cfargotunnel.com" {
		t.Errorf("dnsWrites = %v, want single in-place PUT to CNAME", m.dnsWrites)
	}
	if m.ingressPUTs != 1 {
		t.Errorf("ingressPUTs = %d, want 1", m.ingressPUTs)
	}
}

func TestAddTunnelRoute_LeavesCorrectCNAMEAlone(t *testing.T) {
	// The exact user scenario: CNAME already points at the tunnel from a
	// previous enable — nothing should be written, but the record ID returned
	// so the GUI can mark the tunnel as on.
	m := newTunnelAndDNSMock(t, nil, []dnsRecord{{ID: "rec-c", Type: "CNAME", Content: "tid.cfargotunnel.com"}})
	c, _ := New("tok", "zone1", "tid", "acct")

	id, err := c.AddTunnelRoute(context.Background(), "drive.example.com")
	if err != nil || id != "rec-c" {
		t.Fatalf("AddTunnelRoute = (%q, %v), want (rec-c, nil)", id, err)
	}
	if len(m.dnsWrites) != 0 || len(m.deletions) != 0 || len(m.creations) != 0 {
		t.Errorf("unexpected writes: writes=%v deletions=%v creations=%v", m.dnsWrites, m.deletions, m.creations)
	}
}

func TestAddTunnelRoute_CreatesWhenMissing(t *testing.T) {
	m := newTunnelAndDNSMock(t, nil, []dnsRecord{})
	c, _ := New("tok", "zone1", "tid", "acct")

	id, err := c.AddTunnelRoute(context.Background(), "new.example.com")
	if err != nil || id != "created" {
		t.Fatalf("AddTunnelRoute = (%q, %v), want (created, nil)", id, err)
	}
	if len(m.creations) != 1 || len(m.deletions) != 0 || len(m.dnsWrites) != 0 {
		t.Errorf("creations=%v writes=%v deletions=%v, want one create only", m.creations, m.dnsWrites, m.deletions)
	}
}

func TestRemoveTunnelRoute_RecoversLostRecordID(t *testing.T) {
	// Stored record ID was lost ("record was made previously"): disabling must
	// still find and delete the CNAME by hostname.
	m := newTunnelAndDNSMock(t, []ingressRule{{
		Hostname: "drive.example.com", Service: LanternOrigin,
	}}, []dnsRecord{{ID: "rec-c", Type: "CNAME", Content: "tid.cfargotunnel.com"}})
	c, _ := New("tok", "zone1", "tid", "acct")

	if err := c.RemoveTunnelRoute(context.Background(), "drive.example.com", ""); err != nil {
		t.Fatalf("RemoveTunnelRoute: %v", err)
	}
	if len(m.deletions) != 1 || m.deletions[0] != "rec-c" {
		t.Errorf("deletions = %v, want [rec-c]", m.deletions)
	}
}

// ---- Tunnel ingress -> Lantern -----------------------------------------------

type tunnelMock struct {
	rules []ingressRule
	puts  int
	last  []ingressRule
}

func newTunnelMock(t *testing.T, initial []ingressRule) *tunnelMock {
	t.Helper()
	m := &tunnelMock{rules: initial}
	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/acct/cfd_tunnel/tid/configurations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body struct {
				Config struct {
					Ingress []ingressRule `json:"ingress"`
				} `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.puts++
			m.last = body.Config.Ingress
			m.rules = body.Config.Ingress
			_, _ = w.Write(cfOK(map[string]any{}))
			return
		}
		_, _ = w.Write(cfOK(map[string]any{"config": map[string]any{"ingress": m.rules}}))
	})
	cfServer(t, mux)
	return m
}

func TestEnsureTunnelRoutes_RewritesStaleRuleToLantern(t *testing.T) {
	m := newTunnelMock(t, []ingressRule{
		{Hostname: "plex.example.com", Service: "http://10.0.0.5:32400"}, // old: straight to backend
		{Service: "http_status:404"},
	})
	c, _ := New("tok", "zone1", "tid", "acct")

	if err := c.EnsureTunnelRoutes(context.Background(), []string{"plex.example.com", "new.example.com"}); err != nil {
		t.Fatalf("EnsureTunnelRoutes: %v", err)
	}
	if m.puts != 1 || len(m.last) != 3 {
		t.Fatalf("puts=%d rules=%+v, want 1 put with 3 rules", m.puts, m.last)
	}
	for _, r := range m.last[:2] {
		if r.Service != LanternOrigin || r.OriginRequest == nil || !r.OriginRequest.NoTLSVerify || r.OriginRequest.OriginServerName != r.Hostname {
			t.Errorf("rule not pointing at Lantern: %+v", r)
		}
	}
	if last := m.last[2]; last.Hostname != "" || last.Service != "http_status:404" {
		t.Errorf("catch-all must stay last, got %+v", last)
	}

	// Already correct: no further write.
	if err := c.EnsureTunnelRoutes(context.Background(), []string{"plex.example.com", "new.example.com"}); err != nil {
		t.Fatal(err)
	}
	if m.puts != 1 {
		t.Errorf("puts=%d after no-op ensure, want still 1", m.puts)
	}
}

func TestEnsureTunnelRoutes_NoopWithoutTunnel(t *testing.T) {
	c, _ := New("tok", "zone1", "", "") // no tunnel configured
	if err := c.EnsureTunnelRoutes(context.Background(), []string{"x.example.com"}); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestFindTunnelCNAME(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var recs []dnsRecord
		switch r.URL.Query().Get("name") {
		case "ok.example.com":
			recs = []dnsRecord{{ID: "rec1", Type: "CNAME", Content: "tid.cfargotunnel.com"}}
		case "other.example.com":
			recs = []dnsRecord{{ID: "rec2", Type: "CNAME", Content: "other.cfargotunnel.com"}}
		case "a.example.com":
			recs = []dnsRecord{{ID: "rec3", Type: "A", Content: "10.0.0.1"}}
		}
		_, _ = w.Write(cfOK(recs))
	})
	cfServer(t, mux)

	c, _ := New("tok", "zone1", "tid", "acct")
	tests := []struct {
		host      string
		wantID    string
		wantField string
		wantOK    bool
	}{
		{"ok.example.com", "rec1", "tid.cfargotunnel.com", true},
		{"other.example.com", "rec2", "other.cfargotunnel.com", false},
		{"a.example.com", "", "", false},
		{"missing.example.com", "", "", false},
	}
	for _, tt := range tests {
		id, target, ok, err := c.FindTunnelCNAME(context.Background(), tt.host)
		if err != nil {
			t.Fatalf("%s: %v", tt.host, err)
		}
		if id != tt.wantID || target != tt.wantField || ok != tt.wantOK {
			t.Errorf("%s: got (id=%q target=%q ok=%v), want (%q %q %v)",
				tt.host, id, target, ok, tt.wantID, tt.wantField, tt.wantOK)
		}
	}
}

func TestFindTunnelCNAME_NoopWithoutTunnel(t *testing.T) {
	c, _ := New("tok", "zone1", "", "")
	if id, target, ok, err := c.FindTunnelCNAME(context.Background(), "x.example.com"); err != nil || id != "" || target != "" || ok {
		t.Errorf("noop: got (%q %q %v, %v), want zero values", id, target, ok, err)
	}
}
