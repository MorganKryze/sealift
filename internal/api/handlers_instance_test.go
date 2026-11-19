package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func getInstance(t *testing.T, url string) Instance {
	t.Helper()
	resp, err := http.Get(url + "/api/instance")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/instance: %d", resp.StatusCode)
	}
	var in Instance
	if err := json.NewDecoder(resp.Body).Decode(&in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestInstance(t *testing.T) {
	srv, h := newTestServer(t)
	if in := getInstance(t, srv.URL); in.Ephemeral || in.IdleMinutes != nil {
		t.Errorf("default instance = %+v, want not ephemeral and no idle delay", in)
	}
	h.Ephemeral = 45 * time.Minute
	if in := getInstance(t, srv.URL); !in.Ephemeral || in.IdleMinutes == nil || *in.IdleMinutes != 45 {
		t.Errorf("ephemeral instance = %+v, want ephemeral with 45 minutes", in)
	}
}

func deleteProject(t *testing.T, url, id string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url+"/api/projects/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// In ephemeral mode, deleting the last project also empties the caches
// that recorded what it fetched; outside it, the caches stay.
func TestDeleteProjectPurgesCachesWhenEphemeral(t *testing.T) {
	for _, ephemeral := range []bool{false, true} {
		srv, h := newTestServer(t)
		if ephemeral {
			h.Ephemeral = time.Hour
		}
		cached := filepath.Join(h.Store.Root(), "cache", "tarballs", "x.tgz")
		if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cached, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Created through the store: the API would also queue an analysis,
		// and a job in flight keeps the caches.
		p, err := h.Store.CreateProject("demo", []byte(`{"name":"demo"}`))
		if err != nil {
			t.Fatal(err)
		}
		if code := deleteProject(t, srv.URL, p.ID); code != http.StatusNoContent {
			t.Fatalf("ephemeral %v: DELETE = %d, want 204", ephemeral, code)
		}
		_, err = os.Stat(cached)
		if ephemeral && !os.IsNotExist(err) {
			t.Errorf("ephemeral: the tarball cache survived the delete")
		}
		if !ephemeral && err != nil {
			t.Errorf("not ephemeral: the tarball cache is gone: %v", err)
		}
	}
}

// A job of another project in flight keeps the caches through a delete: the
// purge waits for the sweep.
func TestDeleteProjectKeepsCachesWhileAnotherJobRuns(t *testing.T) {
	srv, h := newTestServer(t)
	h.Ephemeral = time.Hour
	cached := filepath.Join(h.Store.Root(), "cache", "tarballs", "x.tgz")
	if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := h.Store.CreateProject("other", []byte(`{"name":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(other.Dir, "analyses", "20261119T120000Z.tmp"), 0o770); err != nil {
		t.Fatal(err)
	}
	p, err := h.Store.CreateProject("demo", []byte(`{"name":"demo"}`))
	if err != nil {
		t.Fatal(err)
	}
	if code := deleteProject(t, srv.URL, p.ID); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", code)
	}
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("the caches went while another project's job ran: %v", err)
	}
}

func TestEphemeralAnswersAreNotStored(t *testing.T) {
	_, h := newTestServer(t)
	for _, ephemeral := range []bool{false, true} {
		h.Ephemeral = 0
		if ephemeral {
			h.Ephemeral = time.Hour
		}
		// Routes reads the mode when it builds the handler.
		s := httptest.NewServer(Routes(h, testStatic()))
		resp, err := http.Get(s.URL + "/api/instance")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		s.Close()
		got := resp.Header.Get("Cache-Control")
		if ephemeral && got != "no-store" || !ephemeral && got == "no-store" {
			t.Errorf("ephemeral %v: Cache-Control = %q", ephemeral, got)
		}
	}
}
