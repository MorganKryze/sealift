package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	want.MinReleaseAgeDays = 21
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

// TestSettingsJSONMatchesTheContract proves settings.json holds the field
// names api/openapi.yaml declares (target, os, cpu, libc, node, pnpmVer,
// signatureKey, minReleaseAgeDays, resolveParallelism, downloadParallelism)
// instead of the exported Go field names.
func TestSettingsJSONMatchesTheContract(t *testing.T) {
	settings := defaultSettings
	settings.SignatureKey = "top-secret-key"

	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}
	wantKeys := []string{"target", "signatureKey", "minReleaseAgeDays", "resolveParallelism", "downloadParallelism"}
	if len(got) != len(wantKeys) {
		t.Fatalf("Settings JSON keys = %v, want exactly %v", got, wantKeys)
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("Settings JSON missing key %q, got %v", k, got)
		}
	}

	target, ok := got["target"].(map[string]any)
	if !ok {
		t.Fatalf("target = %v, want an object", got["target"])
	}
	wantTargetKeys := []string{"os", "cpu", "libc", "node", "pnpmVer"}
	if len(target) != len(wantTargetKeys) {
		t.Fatalf("Target JSON keys = %v, want exactly %v", target, wantTargetKeys)
	}
	for _, k := range wantTargetKeys {
		if _, ok := target[k]; !ok {
			t.Errorf("Target JSON missing key %q, got %v", k, target)
		}
	}
}

// TestSettingsJSONFileRoundTrip proves a settings.json written to disk with
// the contract's field names reads back into the same Settings value.
func TestSettingsJSONFileRoundTrip(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := defaultSettings
	want.SignatureKey = "top-secret-key"
	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, "private", "settings.json"))
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	if !jsonHasKey(t, raw, "signatureKey") || !jsonHasKey(t, raw, "minReleaseAgeDays") {
		t.Fatalf("settings.json = %s, want contract field names", raw)
	}

	var got Settings
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != want {
		t.Fatalf("round-tripped Settings = %+v, want %+v", got, want)
	}
}

// jsonHasKey reports whether raw, a JSON object, has a top-level key named k.
func jsonHasKey(t *testing.T, raw []byte, k string) bool {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}
	_, ok := m[k]
	return ok
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

func TestSaveSettingsNamesTheTargetFieldItRefuses(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for field, change := range map[string]func(*Settings){
		"node is empty":              func(set *Settings) { set.Target.Node = "" },
		"node must be exact":         func(set *Settings) { set.Target.Node = "22.x" },
		"pnpm version must be exact": func(set *Settings) { set.Target.PnpmVer = "10" },
	} {
		set := s.Settings()
		change(&set)
		err := s.SaveSettings(set)
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("%s: SaveSettings = %v, want ErrInvalidTarget", field, err)
			continue
		}
		if !strings.Contains(err.Error(), field) || strings.Contains(err.Error(), "{") {
			t.Errorf("%s: message %q, want it to name the field in words", field, err)
		}
	}
}
