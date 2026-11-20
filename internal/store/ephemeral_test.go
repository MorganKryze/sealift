package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEphemeralProjectIDDoesNotNameTheProject(t *testing.T) {
	s := openTestStore(t)
	s.SetEphemeral(true)
	p, err := s.CreateProject("acme-billing", []byte(`{"name":"acme-billing"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.ID, "acme") || strings.Contains(p.ID, "billing") {
		t.Errorf("ephemeral project id %q carries the project name", p.ID)
	}
	if p.Name != "acme-billing" {
		t.Errorf("name = %q, want the name kept in the record", p.Name)
	}
}

// writeCaches fills the three shared caches and returns their paths.
func writeCaches(t *testing.T, s *Store) []string {
	t.Helper()
	var files []string
	for _, rel := range []string{"cache/pnpm/store/v10/index/ab", "cache/tarballs/x.tgz", "cache/resolve/r1/package.json"} {
		p := filepath.Join(s.Root(), rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("lodash"), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	return files
}

func TestPurgeCachesKeepsToolsKeyAndSettings(t *testing.T) {
	s := openTestStore(t)
	files := writeCaches(t, s)
	tool := filepath.Join(s.Root(), "tools", "trivy", "0.76.2", "trivy")
	db := filepath.Join(s.Root(), "trivy-cache", "db", "trivy.db")
	for _, p := range []string{tool, db} {
		if err := os.MkdirAll(filepath.Dir(p), 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PurgeCaches(); err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the purge", p)
		}
	}
	for _, p := range []string{tool, db, filepath.Join(s.Root(), "private", "settings.json"), filepath.Join(s.Root(), "private", "signing-key.pem")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s did not survive the purge: %v", p, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(s.Root(), "cache", "resolve")); err != nil || !fi.IsDir() {
		t.Errorf("cache/resolve is gone after the purge: %v", err)
	}
}

// uv's cache holds the index pages and metadata of every package a pip
// project resolved, so an erase must empty it too.
func TestPurgeCachesEmptiesUvCache(t *testing.T) {
	s := openTestStore(t)
	page := filepath.Join(s.Root(), "cache", "uv", "simple-v16", "index", "requests.rkyv")
	if err := os.MkdirAll(filepath.Dir(page), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(page, []byte("requests"), 0o600); err != nil {
		t.Fatal(err)
	}

	purged, err := s.PurgeIfIdle()
	if err != nil {
		t.Fatal(err)
	}
	if !purged {
		t.Error("PurgeIfIdle saw the caches empty while cache/uv held a page")
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "cache", "uv")); !os.IsNotExist(err) {
		t.Errorf("cache/uv survived the purge: %v", err)
	}
}

func TestSweepEphemeral(t *testing.T) {
	s := openTestStore(t)
	s.SetEphemeral(true)
	old, err := s.CreateProject("old", []byte(`{"name":"old"}`))
	if err != nil {
		t.Fatal(err)
	}
	busy, err := s.CreateProject("busy", []byte(`{"name":"busy"}`))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.CreateProject("fresh", []byte(`{"name":"fresh"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(busy.Dir, "analyses", "20261119T120000Z.tmp"), 0o770); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	age := func(p Project, d time.Duration) {
		t.Helper()
		err := filepath.WalkDir(p.Dir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return os.Chtimes(path, now.Add(-d), now.Add(-d))
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	age(old, 2*time.Hour)
	age(busy, 2*time.Hour)
	age(fresh, 10*time.Minute)
	writeCaches(t, s)

	if r := s.SweepEphemeral(time.Hour, now); r != (Sweep{Deleted: 1}) {
		t.Errorf("first sweep = %+v, want 1 deleted and no purge (a job is in flight)", r)
	}
	if _, err := os.Stat(old.Dir); !os.IsNotExist(err) {
		t.Errorf("the idle project survived")
	}
	for _, p := range []Project{busy, fresh} {
		if _, err := os.Stat(p.Dir); err != nil {
			t.Errorf("%s was deleted: %v", p.Name, err)
		}
	}

	// Once the job ended and every project went idle, the sweep empties
	// the caches too.
	if err := os.RemoveAll(filepath.Join(busy.Dir, "analyses", "20261119T120000Z.tmp")); err != nil {
		t.Fatal(err)
	}
	age(busy, 2*time.Hour)
	age(fresh, 2*time.Hour)
	if r := s.SweepEphemeral(time.Hour, now); r != (Sweep{Deleted: 2, Purged: true}) {
		t.Errorf("second sweep = %+v, want 2 deleted and the caches purged", r)
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "cache", "tarballs", "x.tgz")); !os.IsNotExist(err) {
		t.Errorf("the tarball cache survived the last project")
	}

	// Nothing left to erase: the next sweep reports nothing, so the log
	// stays quiet on an idle instance.
	if r := s.SweepEphemeral(time.Hour, now); r != (Sweep{}) {
		t.Errorf("idle sweep = %+v, want nothing done", r)
	}
}

// age sets every modification time under dir to now minus d.
func age(t *testing.T, dir string, now time.Time, d time.Duration) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, now.Add(-d), now.Add(-d))
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A project the sweep cannot read is counted and skipped: the other idle
// projects are still erased.
func TestSweepEphemeralSkipsAnUnreadableProject(t *testing.T) {
	s := openTestStore(t)
	s.SetEphemeral(true)
	now := time.Now()
	bad, err := s.CreateProject("bad", []byte(`{"name":"bad"}`))
	if err != nil {
		t.Fatal(err)
	}
	good, err := s.CreateProject("good", []byte(`{"name":"good"}`))
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(bad.Dir, "analyses", "x")
	if err := os.MkdirAll(locked, 0o770); err != nil {
		t.Fatal(err)
	}
	age(t, bad.Dir, now, 2*time.Hour)
	age(t, good.Dir, now, 2*time.Hour)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o770) })

	r := s.SweepEphemeral(time.Hour, now)
	if r.Deleted != 1 || r.Failed != 1 {
		t.Errorf("sweep = %+v, want 1 deleted and 1 failed", r)
	}
	if _, err := os.Stat(good.Dir); !os.IsNotExist(err) {
		t.Errorf("the readable idle project survived")
	}
}

// A purge that a job in flight put off runs at the first sweep that finds
// the instance idle, even while other projects remain.
func TestPurgeIfIdlePutsOffAPurgeWhileAJobRuns(t *testing.T) {
	s := openTestStore(t)
	s.SetEphemeral(true)
	other, err := s.CreateProject("other", []byte(`{"name":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(other.Dir, "exports", "20261119T120000Z.tmp")
	if err := os.MkdirAll(job, 0o770); err != nil {
		t.Fatal(err)
	}
	writeCaches(t, s)
	tarball := filepath.Join(s.Root(), "cache", "tarballs", "x.tgz")

	if purged, err := s.PurgeIfIdle(); err != nil || purged {
		t.Fatalf("PurgeIfIdle with a job in flight = %v, %v; want false, nil", purged, err)
	}
	if _, err := os.Stat(tarball); err != nil {
		t.Fatalf("the caches went while a job ran: %v", err)
	}
	// Still busy: the sweep keeps the caches.
	if r := s.SweepEphemeral(time.Hour, time.Now()); r.Purged {
		t.Errorf("sweep purged while a job ran")
	}
	if err := os.RemoveAll(job); err != nil {
		t.Fatal(err)
	}
	// The project is fresh, so it stays; the put-off purge runs anyway.
	if r := s.SweepEphemeral(time.Hour, time.Now()); !r.Purged || r.Deleted != 0 {
		t.Errorf("sweep after the job = %+v, want the put-off purge and no deletion", r)
	}
	if _, err := os.Stat(tarball); !os.IsNotExist(err) {
		t.Errorf("the put-off purge left the tarball cache")
	}
}
