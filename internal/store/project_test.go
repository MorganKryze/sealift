package store

import (
	"errors"
	"testing"
)

func TestSlug(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"@scope/name", "scope-name"},
		{"My App", "my-app"},
		{"!!!", ""},
		{"---", ""},
		{"left-pad", "left-pad"},
	}
	for _, c := range cases {
		if got := slug(c.name); got != c.want {
			t.Errorf("slug(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCreateProjectRejectsNameWithNoSlug(t *testing.T) {
	s := openTestStore(t)

	if _, err := s.CreateProject("!!!", []byte("{}")); err == nil {
		t.Fatal("CreateProject with an unsluggable name accepted, want an error")
	}
}

func TestCreateProjectRetriesOnIDCollision(t *testing.T) {
	s := openTestStore(t)

	calls := 0
	restore := stubRandomHex(func(_ int) (string, error) {
		calls++
		if calls == 1 {
			return "aaaaaa", nil
		}
		return "bbbbbb", nil
	})
	defer restore()

	first, err := s.CreateProject("dup", []byte(`{"name":"dup"}`))
	if err != nil {
		t.Fatalf("first CreateProject: %v", err)
	}
	if first.ID != "dup-aaaaaa" {
		t.Fatalf("first ID = %q, want %q", first.ID, "dup-aaaaaa")
	}

	// The stub returns "aaaaaa" again first, colliding with the directory
	// CreateProject just made, then "bbbbbb" on retry.
	calls = 0
	second, err := s.CreateProject("dup", []byte(`{"name":"dup"}`))
	if err != nil {
		t.Fatalf("second CreateProject: %v", err)
	}
	if second.ID != "dup-bbbbbb" {
		t.Fatalf("second ID = %q, want a distinct suffix, got %q", second.ID, second.ID)
	}
}

func TestProjectCRUD(t *testing.T) {
	s := openTestStore(t)

	p, err := s.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	got, err := s.Project(p.ID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if got != p {
		t.Fatalf("Project() = %+v, want %+v", got, p)
	}

	list, err := s.Projects()
	if err != nil {
		t.Fatalf("Projects: %v", err)
	}
	if len(list) != 1 || list[0].ID != p.ID {
		t.Fatalf("Projects() = %+v, want one entry with ID %q", list, p.ID)
	}

	newTarget := p.Target
	newTarget.Node = "20.0.0"
	if err := s.SetProjectTarget(p.ID, newTarget); err != nil {
		t.Fatalf("SetProjectTarget: %v", err)
	}
	updated, err := s.Project(p.ID)
	if err != nil {
		t.Fatalf("Project after target change: %v", err)
	}
	if updated.Target.Node != "20.0.0" {
		t.Fatalf("Target.Node = %q, want %q", updated.Target.Node, "20.0.0")
	}

	if err := s.DeleteProject(p.ID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if _, err := s.Project(p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Project after delete: err = %v, want ErrNotFound", err)
	}
}

func TestSetProjectTargetRefusesEmptyField(t *testing.T) {
	s := openTestStore(t)
	p, err := s.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	bad := p.Target
	bad.CPU = ""
	if err := s.SetProjectTarget(p.ID, bad); err == nil {
		t.Fatal("SetProjectTarget with an empty CPU accepted, want an error")
	}
}

func TestProjectNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Project("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Project(\"missing\"): err = %v, want ErrNotFound", err)
	}
	if err := s.SetProjectTarget("missing", Target{OS: "linux", CPU: "x64", Node: "22.17.1", PnpmVer: "10.34.5"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetProjectTarget(\"missing\", ...): err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteProject("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteProject(\"missing\"): err = %v, want ErrNotFound", err)
	}
}

// openTestStore opens a store rooted at a fresh temporary directory.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// stubRandomHex replaces the package's randomHex for the duration of a test
// and returns a function that restores it, so TestCreateProjectRetriesOnIDCollision
// can force a suffix collision deterministically.
func stubRandomHex(fn func(n int) (string, error)) func() {
	orig := randomHexFunc
	randomHexFunc = fn
	return func() { randomHexFunc = orig }
}
