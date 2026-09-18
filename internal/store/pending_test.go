package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPendingCommitPublishesUnderFinalName(t *testing.T) {
	s := openTestStore(t)
	p, err := s.NewDir("analyses", "proj-1")
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	marker := filepath.Join(p.Path(), "status.json")
	if err := os.WriteFile(marker, []byte(`{"state":"running"}`), fileMode); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if err := p.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	finalMarker := filepath.Join(s.Root(), "projects", "proj-1", "analyses", p.ID(), "status.json")
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
