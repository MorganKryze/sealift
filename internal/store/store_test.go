package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesLayoutModes(t *testing.T) {
	root := t.TempDir()

	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if s.Root() != root {
		t.Fatalf("Root() = %q, want %q", s.Root(), root)
	}

	cases := []struct {
		path string
		mode os.FileMode
	}{
		{"private", privateMode},
		{"tools", dirMode},
		{"trivy-cache", dirMode},
		{"cache", dirMode},
		{"projects", dirMode},
	}
	for _, c := range cases {
		info, err := os.Stat(filepath.Join(root, c.path))
		if err != nil {
			t.Fatalf("stat %s: %v", c.path, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", c.path)
		}
		if got := info.Mode().Perm(); got != c.mode {
			t.Errorf("%s mode = %o, want %o", c.path, got, c.mode)
		}
	}

	info, err := os.Stat(filepath.Join(root, "private", "settings.json"))
	if err != nil {
		t.Fatalf("stat settings.json: %v", err)
	}
	if got := info.Mode().Perm(); got != settingsMode {
		t.Errorf("settings.json mode = %o, want %o", got, settingsMode)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	root := t.TempDir()

	if _, err := Open(root); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if s.Settings() != defaultSettings {
		t.Errorf("Settings() = %+v, want the defaults %+v", s.Settings(), defaultSettings)
	}
}

func TestSettingsRoundTripKeepsSignatureKey(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := defaultSettings
	want.SignatureKey = "top-secret-key"
	want.MinReleaseAgeDays = 14
	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if got := s.Settings(); got != want {
		t.Fatalf("Settings() in memory = %+v, want %+v", got, want)
	}

	// Reopen to prove the signature key survived on disk, not just in memory.
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.Settings(); got != want {
		t.Fatalf("Settings() after reopen = %+v, want %+v", got, want)
	}
}

func TestSaveSettingsRefusesEmptyTargetField(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	bad := defaultSettings
	bad.Target.Node = ""
	if err := s.SaveSettings(bad); err == nil {
		t.Fatal("SaveSettings with an empty Node accepted, want an error")
	}

	// The settings on disk and in memory must stay the last valid ones.
	if got := s.Settings(); got != defaultSettings {
		t.Errorf("Settings() after a refused save = %+v, want %+v", got, defaultSettings)
	}
}

func TestStoreFileIsGroupWritable(t *testing.T) {
	root := t.TempDir()
	// Open, not just t.TempDir, because the group write bit this test checks
	// comes from the umask fix Open applies, not from the directory alone.
	if _, err := Open(root); err != nil {
		t.Fatalf("Open: %v", err)
	}

	path := filepath.Join(root, "projects", "probe.json")
	if err := atomicWriteFile(path, []byte(`{"k":"v"}`), fileMode); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o020 == 0 {
		t.Errorf("mode %o is not group-writable", info.Mode().Perm())
	}
}
