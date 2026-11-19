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

	deleted, purged, err := s.SweepEphemeral(time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || purged {
		t.Errorf("first sweep: deleted %d, purged %v; want 1 and false (a job is in flight)", deleted, purged)
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
	deleted, purged, err = s.SweepEphemeral(time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 || !purged {
		t.Errorf("second sweep: deleted %d, purged %v; want 2 and true", deleted, purged)
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "cache", "tarballs", "x.tgz")); !os.IsNotExist(err) {
		t.Errorf("the tarball cache survived the last project")
	}

	// Nothing left to erase: the next sweep reports nothing, so the log
	// stays quiet on an idle instance.
	if deleted, purged, err := s.SweepEphemeral(time.Hour, now); err != nil || deleted != 0 || purged {
		t.Errorf("idle sweep: deleted %d, purged %v, err %v; want 0, false, nil", deleted, purged, err)
	}
}
