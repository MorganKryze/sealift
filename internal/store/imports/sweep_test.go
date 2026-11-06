package imports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/importer"
)

func TestSweep(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)

	queued, _ := s.Create("alice", testArchiveObject, testManifestObject, "")

	running, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	work, _, err := s.Begin("alice", running.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "left-pad-1.3.0.tgz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Listed("alice", running.ID, 1, listedReport()); err != nil {
		t.Fatal(err)
	}
	done := pendingResults()[0]
	done.State = importer.Published
	if err := s.Ended("alice", running.ID, 1, 0, done); err != nil {
		t.Fatal(err)
	}

	finished, _ := s.Create("bob", testArchiveObject, testManifestObject, "")
	if _, _, err := s.Begin("bob", finished.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish("bob", finished.ID, 1, importer.Report{Outcome: importer.OutcomeComplete}, nil); err != nil {
		t.Fatal(err)
	}
	staleWork := filepath.Join(root, "bob", finished.ID, "work-1")
	if err := os.MkdirAll(staleWork, 0o700); err != nil {
		t.Fatal(err)
	}

	reopened, _ := openStore(t, root)
	marked, err := reopened.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if marked != 2 {
		t.Errorf("marked %d, want 2", marked)
	}

	got, _ := reopened.Get("alice", queued.ID)
	a := got.Attempts[0]
	if a.Status != "ended" || a.Outcome != "interrupted" || a.EndedAt == nil || got.Outcome() != "interrupted" {
		t.Errorf("queued import after the sweep: %+v", a)
	}
	if a.StartedAt != nil {
		t.Errorf("a queued attempt gained a start time: %v", a.StartedAt)
	}

	got, _ = reopened.Get("alice", running.ID)
	a = got.Attempts[0]
	if a.Status != "ended" || a.Outcome != "interrupted" {
		t.Fatalf("running import after the sweep: %+v", a)
	}
	pkgs := a.Report.Packages
	if pkgs[0].Kind != "" {
		t.Errorf("a published package gained the kind %q", pkgs[0].Kind)
	}
	if len(pkgs) != 2 || pkgs[0].State != importer.Published || pkgs[1].State != importer.Failed || pkgs[1].Reason != "interrupted" || pkgs[1].Kind != importer.KindInterrupted {
		t.Errorf("packages after the sweep: %+v", pkgs)
	}
	if c := a.Report.Counts; c.Published != 1 || c.Failed != 1 || c.Present != 0 {
		t.Errorf("counts %+v, want 1 published and 1 failed", c)
	}
	for _, p := range pkgs {
		if p.State == importer.Pending {
			t.Errorf("%s is still pending", p.Name)
		}
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Errorf("work directory after the sweep: %v", err)
	}
	if _, err := os.Stat(staleWork); !os.IsNotExist(err) {
		t.Errorf("stale work directory of an ended attempt after the sweep: %v", err)
	}

	got, _ = reopened.Get("bob", finished.ID)
	if got.Outcome() != importer.OutcomeComplete {
		t.Errorf("an ended import changed: %q", got.Outcome())
	}

	again, err := reopened.Sweep()
	if err != nil || again != 0 {
		t.Errorf("second sweep marked %d, %v, want 0", again, err)
	}
}

func TestSweepStartsNothing(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	if _, err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("alice", imp.ID)
	if len(got.Attempts) != 1 || got.Outcome() == "running" || got.Outcome() == "queued" {
		t.Errorf("after the sweep: %+v", got.Attempts)
	}
	if _, err := os.Stat(filepath.Join(root, "alice", imp.ID, "work-1")); !os.IsNotExist(err) {
		t.Errorf("the sweep made a work directory: %v", err)
	}
}

func TestSweepSkipsDamaged(t *testing.T) {
	root := testRoot(t)
	s, logs := openStore(t, root)
	good, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	damaged := plantFixture(t, root, "alice", func(m map[string]any) { m["id"] = "20261106T090000Z-aaaaaaaa" })
	if err := os.WriteFile(filepath.Join(damaged, "import.json"), []byte(`{"formatVersion": 1, "id": "2026`), 0o600); err != nil {
		t.Fatal(err)
	}
	damagedWork := filepath.Join(damaged, "work-1")
	if err := os.Mkdir(damagedWork, 0o700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(root, "alice", "not-an-id")
	if err := os.Mkdir(stray, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stray-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	marked, err := s.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if marked != 1 {
		t.Errorf("marked %d, want 1", marked)
	}
	got, _ := s.Get("alice", good.ID)
	if got.Outcome() != "interrupted" {
		t.Errorf("the good import is %q", got.Outcome())
	}
	if !strings.Contains(logs.String(), "20261106T090000Z-aaaaaaaa") {
		t.Errorf("the log does not name the damaged import:\n%s", logs.String())
	}
	if _, err := os.Stat(damagedWork); err != nil {
		t.Errorf("the sweep touched a damaged import's directory: %v", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("the sweep touched a directory that is not an import: %v", err)
	}
}
