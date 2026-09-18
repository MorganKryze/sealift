package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingCommitPublishesUnderFinalName(t *testing.T) {
	s := openTestStore(t)
	p, err := s.NewDir("analyses", "proj-1")
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	wantFinal := filepath.Join(s.Root(), "projects", "proj-1", "analyses", p.ID())
	if p.Final() != wantFinal {
		t.Fatalf("Final() = %q, want %q", p.Final(), wantFinal)
	}

	marker := filepath.Join(p.Path(), "status.json")
	if err := os.WriteFile(marker, []byte(`{"state":"running"}`), fileMode); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if err := p.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	finalMarker := filepath.Join(p.Final(), "status.json")
	if _, err := os.Stat(finalMarker); err != nil {
		t.Fatalf("stat committed marker: %v", err)
	}
	if _, err := os.Stat(p.Path()); !os.IsNotExist(err) {
		t.Fatalf("stat %s after commit: err = %v, want IsNotExist", p.Path(), err)
	}
}

func TestPendingDiscardLeavesNothingBehind(t *testing.T) {
	s := openTestStore(t)
	p, err := s.NewDir("exports", "proj-1")
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	nested := filepath.Join(p.Path(), "packages", "tarball.tgz")
	if err := os.MkdirAll(filepath.Dir(nested), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(nested, []byte("data"), fileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := p.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}

	parent := filepath.Join(s.Root(), "projects", "proj-1", "exports")
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("exports dir after discard = %v, want empty", entries)
	}
}

func TestNewDirRefusesIDsThatEscapeTheDataVolume(t *testing.T) {
	s := openTestStore(t)

	for _, id := range []string{"../private", "../../x", "a/b", "", ".."} {
		if _, err := s.NewDir("analyses", id); !errors.Is(err, ErrNotFound) {
			t.Errorf("NewDir(%q): err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestNewDirRefusesUnknownKind(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.NewDir("other", "proj-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf(`NewDir("other", ...): err = %v, want ErrNotFound`, err)
	}
}

func TestNewDirRetriesOnIDCollisionWithinOneSecond(t *testing.T) {
	s := openTestStore(t)

	fixed := mustParseTime(t, "2026-09-17T10:15:02Z")
	restore := stubNow(func() time.Time { return fixed })
	defer restore()

	first, err := s.NewDir("analyses", "proj-1")
	if err != nil {
		t.Fatalf("first NewDir: %v", err)
	}
	if err := first.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if first.ID() != "20260917T101502Z" {
		t.Fatalf("first ID = %q, want %q", first.ID(), "20260917T101502Z")
	}

	// Same fixed second again: without a retry, this would collide with
	// the committed directory above the moment it tried to Commit too.
	second, err := s.NewDir("analyses", "proj-1")
	if err != nil {
		t.Fatalf("second NewDir: %v", err)
	}
	if second.ID() == first.ID() {
		t.Fatalf("second ID = %q, want a distinct id from the same second", second.ID())
	}
	if err := second.Commit(); err != nil {
		t.Fatalf("second Commit: %v", err)
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

// stubNow replaces the package's nowFunc for the duration of a test and
// returns a function that restores it, so a collision inside one second
// can be forced deterministically instead of relying on test timing.
func stubNow(fn func() time.Time) func() {
	orig := nowFunc
	nowFunc = fn
	return func() { nowFunc = orig }
}

func TestWriteJSONReadJSONRoundTripAtNestedPath(t *testing.T) {
	s := openTestStore(t)

	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	want := payload{Name: "left-pad", Count: 3}

	path := filepath.Join(s.Root(), "projects", "proj-1", "analyses", "20260917T101502Z", "candidates.json")
	if err := s.WriteJSON(path, want); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// No temporary file should survive a normal write.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "candidates.json" {
		t.Fatalf("directory entries = %v, want only candidates.json", entries)
	}

	var got payload
	if err := s.ReadJSON(path, &got); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if got != want {
		t.Fatalf("ReadJSON = %+v, want %+v", got, want)
	}
}
