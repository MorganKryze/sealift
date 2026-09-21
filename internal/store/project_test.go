package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestProjectsByManifestSha256FindsTheMatchingProjectsNewestFirst proves
// two projects created from the same bytes are both found by their
// shared hash, newest first, and a project from different bytes is not.
func TestProjectsByManifestSha256FindsTheMatchingProjectsNewestFirst(t *testing.T) {
	s := openTestStore(t)
	manifest := []byte(`{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)

	first, err := s.CreateProject("left-pad", manifest)
	if err != nil {
		t.Fatalf("CreateProject first: %v", err)
	}
	time.Sleep(time.Millisecond) // CreatedAt has second precision on disk (analysisIDLayout-style IDs elsewhere), but Project.CreatedAt itself is a plain timestamp, so this only guards against two calls landing on the exact same instant.
	second, err := s.CreateProject("left-pad-again", manifest)
	if err != nil {
		t.Fatalf("CreateProject second: %v", err)
	}
	other, err := s.CreateProject("right-pad", []byte(`{"name":"right-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject other: %v", err)
	}
	if first.ManifestSha256 == "" || first.ManifestSha256 != second.ManifestSha256 {
		t.Fatalf("ManifestSha256 first=%q second=%q, want equal and non-empty", first.ManifestSha256, second.ManifestSha256)
	}
	if other.ManifestSha256 == first.ManifestSha256 {
		t.Fatalf("other project's ManifestSha256 = %q, want it to differ from the shared one", other.ManifestSha256)
	}

	got, err := s.ProjectsByManifestSha256(first.ManifestSha256)
	if err != nil {
		t.Fatalf("ProjectsByManifestSha256: %v", err)
	}
	if len(got) != 2 || got[0].ID != second.ID || got[1].ID != first.ID {
		t.Fatalf("ProjectsByManifestSha256 = %+v, want [%q, %q] newest first", got, second.ID, first.ID)
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

func TestProjectMethodsRefuseIDsThatEscapeTheDataVolume(t *testing.T) {
	s := openTestStore(t)
	target := Target{OS: "linux", CPU: "x64", Node: "22.17.1", PnpmVer: "10.34.5"}

	for _, id := range []string{"../private", "../../x", "a/b", "", ".."} {
		if _, err := s.Project(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Project(%q): err = %v, want ErrNotFound", id, err)
		}
		if err := s.SetProjectTarget(id, target); !errors.Is(err, ErrNotFound) {
			t.Errorf("SetProjectTarget(%q, ...): err = %v, want ErrNotFound", id, err)
		}
		if err := s.DeleteProject(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteProject(%q): err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestDeleteProjectEscapeAttemptLeavesPrivateSettingsInPlace(t *testing.T) {
	s := openTestStore(t)
	settingsPath := filepath.Join(s.Root(), "private", "settings.json")

	if err := s.DeleteProject("../private"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteProject(\"../private\"): err = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(settingsPath); err != nil {
		t.Fatalf("private/settings.json missing after refused delete: %v", err)
	}
}

func TestProjectsSkipsADirectoryWithoutProjectJSON(t *testing.T) {
	s := openTestStore(t)
	good, err := s.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(s.Root(), "projects", "no-manifest"), dirMode); err != nil {
		t.Fatalf("mkdir damaged project dir: %v", err)
	}

	list, err := s.Projects()
	if err != nil {
		t.Fatalf("Projects: %v", err)
	}
	if len(list) != 1 || list[0].ID != good.ID {
		t.Fatalf("Projects() = %+v, want only %q", list, good.ID)
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
