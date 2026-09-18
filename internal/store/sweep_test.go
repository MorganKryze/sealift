package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkRunningInterruptedChangesOnlyRunningFiles(t *testing.T) {
	s := openTestStore(t)

	write := func(rel, state string) string {
		path := filepath.Join(s.Root(), "projects", rel, "status.json")
		if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		body := `{"state":"` + state + `","step":"resolve"}`
		if err := os.WriteFile(path, []byte(body), fileMode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return path
	}

	running1 := write("proj-1/analyses/20260917T101502Z", "running")
	running2 := write("proj-2/exports/20260917T101503Z", "running")
	done := write("proj-1/analyses/20260916T090000Z", "done")
	failed := write("proj-1/analyses/20260915T080000Z", "failed")

	n, err := s.MarkRunningInterrupted()
	if err != nil {
		t.Fatalf("MarkRunningInterrupted: %v", err)
	}
	if n != 2 {
		t.Fatalf("changed = %d, want 2", n)
	}

	assertState := func(path, want string) {
		var got struct {
			State string `json:"state"`
			Step  string `json:"step"`
		}
		if err := s.ReadJSON(path, &got); err != nil {
			t.Fatalf("ReadJSON %s: %v", path, err)
		}
		if got.State != want {
			t.Errorf("%s state = %q, want %q", path, got.State, want)
		}
		if got.Step != "resolve" {
			t.Errorf("%s step = %q, want it untouched (\"resolve\")", path, got.Step)
		}
	}
	assertState(running1, string(Interrupted))
	assertState(running2, string(Interrupted))
	assertState(done, "done")
	assertState(failed, "failed")
}

func TestMarkRunningInterruptedSkipsADamagedStatusJSON(t *testing.T) {
	s := openTestStore(t)

	good := filepath.Join(s.Root(), "projects", "proj-1", "analyses", "20260917T101502Z", "status.json")
	if err := os.MkdirAll(filepath.Dir(good), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(good, []byte(`{"state":"running"}`), fileMode); err != nil {
		t.Fatalf("write %s: %v", good, err)
	}

	damaged := filepath.Join(s.Root(), "projects", "proj-2", "analyses", "20260917T101503Z", "status.json")
	if err := os.MkdirAll(filepath.Dir(damaged), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(damaged, []byte(`not json`), fileMode); err != nil {
		t.Fatalf("write %s: %v", damaged, err)
	}

	n, err := s.MarkRunningInterrupted()
	if err != nil {
		t.Fatalf("MarkRunningInterrupted: %v, want it to skip the damaged file instead of failing", err)
	}
	if n != 1 {
		t.Fatalf("changed = %d, want 1 (only the readable file)", n)
	}

	var got struct{ State string }
	if err := s.ReadJSON(good, &got); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if got.State != string(Interrupted) {
		t.Errorf("good file state = %q, want %q", got.State, Interrupted)
	}

	raw, err := os.ReadFile(damaged)
	if err != nil {
		t.Fatalf("read damaged file: %v", err)
	}
	if string(raw) != "not json" {
		t.Errorf("damaged file content changed, want it untouched: %s", raw)
	}
}

func TestMarkRunningInterruptedOnEmptyStoreReturnsZero(t *testing.T) {
	s := openTestStore(t)
	n, err := s.MarkRunningInterrupted()
	if err != nil {
		t.Fatalf("MarkRunningInterrupted: %v", err)
	}
	if n != 0 {
		t.Fatalf("changed = %d, want 0", n)
	}
}
