package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"lantern/internal/cf"
	"lantern/internal/config"
	"lantern/internal/store"
)

func newDeleteTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	c, _ := cf.New("", "", "", "")
	return New(&config.Config{Domain: "example.com"}, st, c, "test"), st
}

func deleteSvc(t *testing.T, s *Server, id string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/services/"+id, http.NoBody)
	req.SetPathValue("id", id)
	s.deleteService(httptest.NewRecorder(), req)
}

// Deleting several docker services must return every one to Discovered
// (previously they all had ip ""/port 0 and deduped into nothing).
func TestDeleteService_DockerReturnsToDiscovered(t *testing.T) {
	s, st := newDeleteTestServer(t)
	st.AddService(&store.Service{ID: "a", Name: "A", Subdomain: "a", Target: "http://10.0.0.5:8080", Source: store.SourceDocker, ContainerID: "c1", ContainerName: "a"})
	st.AddService(&store.Service{ID: "b", Name: "B", Subdomain: "b", Target: "http://10.0.0.5:9090", Source: store.SourceDocker, ContainerName: "b"}) // stopped: no ContainerID

	deleteSvc(t, s, "a")
	deleteSvc(t, s, "b")

	got := st.GetAllDiscovered()
	if len(got) != 2 {
		t.Fatalf("discovered = %d entries, want 2", len(got))
	}
	for _, d := range got {
		if d.IP != "10.0.0.5" || d.Port == 0 || d.SuggestedSubdomain == "" || d.Source != store.SourceDocker {
			t.Errorf("bad discovered entry: %+v", d)
		}
	}
}

func TestDeleteService_IgnoredDockerStaysIgnored(t *testing.T) {
	s, st := newDeleteTestServer(t)
	st.AddDiscovered(&store.DiscoveredService{ID: "d1", IP: "10.0.0.5", Port: 8080, Source: store.SourceDocker, ContainerName: "a"})
	if err := st.IgnoreDiscovered("d1"); err != nil {
		t.Fatal(err)
	}
	st.AddService(&store.Service{ID: "a", Name: "A", Subdomain: "a", Target: "http://10.0.0.5:8080", Source: store.SourceDocker})

	deleteSvc(t, s, "a")
	if n := len(st.GetAllDiscovered()); n != 0 {
		t.Errorf("discovered = %d, want 0 (ip:port is ignored)", n)
	}
	if ig := st.GetIgnored(); len(ig) != 1 || ig[0].Source != store.SourceDocker || ig[0].ContainerName != "a" {
		t.Errorf("ignored entry lost docker info: %+v", ig)
	}
}
