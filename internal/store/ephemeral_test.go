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
	writeSettings070(t, s.Root())
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

// The wheel cache holds every wheel a pip export downloaded, so an erase
// must empty it too.
func TestPurgeCachesEmptiesTheWheelCache(t *testing.T) {
	s := openTestStore(t)
	wheel := filepath.Join(s.Root(), "cache", "wheels", strings.Repeat("ab", 32)+".whl")
	if err := os.MkdirAll(filepath.Dir(wheel), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wheel, []byte("requests"), 0o600); err != nil {
		t.Fatal(err)
	}

	purged, err := s.PurgeIfIdle()
	if err != nil {
		t.Fatal(err)
	}
	if !purged {
		t.Error("PurgeIfIdle saw the caches empty while cache/wheels held a wheel")
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "cache", "wheels")); !os.IsNotExist(err) {
		t.Errorf("cache/wheels survived the purge: %v", err)
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

	if r := s.SweepEphemeral(time.Hour, now, s.DeleteProjectUnguarded); r != (Sweep{Deleted: 1}) {
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
	if r := s.SweepEphemeral(time.Hour, now, s.DeleteProjectUnguarded); r != (Sweep{Deleted: 2, Purged: true}) {
		t.Errorf("second sweep = %+v, want 2 deleted and the caches purged", r)
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "cache", "tarballs", "x.tgz")); !os.IsNotExist(err) {
		t.Errorf("the tarball cache survived the last project")
	}

	// Nothing left to erase: the next sweep reports nothing, so the log
	// stays quiet on an idle instance.
	if r := s.SweepEphemeral(time.Hour, now, s.DeleteProjectUnguarded); r != (Sweep{}) {
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

// A delete that answers busy, for a job queued since the sweep looked,
// keeps the project and the caches, and counts as no failure.
func TestSweepEphemeralKeepsAProjectItsDeleteFindsBusy(t *testing.T) {
	s := openTestStore(t)
	s.SetEphemeral(true)
	now := time.Now()
	p, err := s.CreateProject("busy", []byte(`{"name":"busy"}`))
	if err != nil {
		t.Fatal(err)
	}
	age(t, p.Dir, now, 2*time.Hour)
	writeCaches(t, s)

	busy := func(string) error { return ErrBusy }
	if r := s.SweepEphemeral(time.Hour, now, busy); r != (Sweep{}) {
		t.Errorf("sweep = %+v, want nothing deleted, purged or failed", r)
	}
	if _, err := os.Stat(p.Dir); err != nil {
		t.Errorf("the busy project was deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "cache", "tarballs", "x.tgz")); err != nil {
		t.Errorf("the caches went while a project stayed: %v", err)
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

	r := s.SweepEphemeral(time.Hour, now, s.DeleteProjectUnguarded)
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
	if r := s.SweepEphemeral(time.Hour, time.Now(), s.DeleteProjectUnguarded); r.Purged {
		t.Errorf("sweep purged while a job ran")
	}
	if err := os.RemoveAll(job); err != nil {
		t.Fatal(err)
	}
	// The project is fresh, so it stays; the put-off purge runs anyway.
	if r := s.SweepEphemeral(time.Hour, time.Now(), s.DeleteProjectUnguarded); !r.Purged || r.Deleted != 0 {
		t.Errorf("sweep after the job = %+v, want the put-off purge and no deletion", r)
	}
	if _, err := os.Stat(tarball); !os.IsNotExist(err) {
		t.Errorf("the put-off purge left the tarball cache")
	}
}

// An ephemeral erase of a pip project leaves no file whose name or content
// names one of its packages, neither in the project tree nor in a cache.
func TestEphemeralPipProjectLeavesNoFile(t *testing.T) {
	s := openTestStore(t)
	s.SetEphemeral(true)
	p, err := s.CreatePipProject("Data tools", []RequirementsFile{
		{Name: "requirements.txt", Data: []byte("zorblax==1.0.0\n")},
		{Name: "requirements-dev.txt", Data: []byte("quuxlib==2.0.0\n")},
	}, DefaultPipTarget)
	if err != nil {
		t.Fatal(err)
	}
	// What a pip analysis leaves behind: its copy of the files, uv's lock
	// and index cache, and a resolve directory.
	for rel, data := range map[string]string{
		filepath.Join(p.Dir, "analyses", "20261120T100000Z", "requirements", "requirements.txt"): "zorblax==1.0.0\n",
		filepath.Join(p.Dir, "analyses", "20261120T100000Z", "project", "requirements.lock"):     "quuxlib==2.0.0\nzorblax==1.0.0\n",
		filepath.Join(s.Root(), "cache", "uv", "simple-v16", "index", "zorblax.rkyv"):            "zorblax",
		filepath.Join(s.Root(), "cache", "uv", "wheels-v5", "quuxlib", "2.0.0.msgpack"):          "quuxlib",
		filepath.Join(s.Root(), "cache", "resolve", "r1", "requirements.in"):                     "quuxlib==2.0.0\n",
	} {
		if err := os.MkdirAll(filepath.Dir(rel), 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rel, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The API's delete in ephemeral mode: the project, then the caches.
	if err := s.DeleteProjectUnguarded(p.ID); err != nil {
		t.Fatal(err)
	}
	if purged, err := s.PurgeIfIdle(); err != nil || !purged {
		t.Fatalf("PurgeIfIdle = %v, %v; want the caches emptied", purged, err)
	}

	for _, dir := range []string{"projects", "cache"} {
		err := filepath.WalkDir(filepath.Join(s.Root(), dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			for _, name := range []string{"zorblax", "quuxlib", "Data tools", "data-tools"} {
				if strings.Contains(strings.ToLower(path), strings.ToLower(name)) {
					t.Errorf("%s names %s after the erase", path, name)
				}
			}
			if d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, name := range []string{"zorblax", "quuxlib"} {
				if strings.Contains(string(data), name) {
					t.Errorf("%s holds %s after the erase", path, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
