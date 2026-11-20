package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestSettingsRoundTripKeepsLimits(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := defaultSettings
	want.MinReleaseAgeDays = 21
	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if got := s.Settings(); got != want {
		t.Fatalf("Settings() in memory = %+v, want %+v", got, want)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.Settings(); got != want {
		t.Fatalf("Settings() after reopen = %+v, want %+v", got, want)
	}
}

func TestOpenRewritesA04Settings(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "private"), privateMode); err != nil {
		t.Fatalf("mkdir private: %v", err)
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "settings-v0.4.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	path := filepath.Join(root, "private", "settings.json")
	if err := os.WriteFile(path, fixture, settingsMode); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := Settings{
		Target:              Target{OS: "linux", CPU: "arm64", Libc: "musl", Node: "20.19.0", PnpmVer: "10.30.1"},
		MinReleaseAgeDays:   30,
		ResolveParallelism:  6,
		DownloadParallelism: 8,
	}
	if got := s.Settings(); got != want {
		t.Fatalf("Settings() = %+v, want %+v", got, want)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	if jsonHasKey(t, raw, "signatureKey") || strings.Contains(string(raw), "lab-signature-key") {
		t.Fatalf("settings.json still holds the key: %s", raw)
	}
	var onDisk Settings
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("decode settings.json: %v", err)
	}
	if onDisk != want {
		t.Fatalf("settings.json holds %+v, want %+v", onDisk, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != settingsMode {
		t.Errorf("settings.json mode = %o, want %o", info.Mode().Perm(), settingsMode)
	}

	// A file already clean is left alone.
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	second, err := Open(root)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if got := second.Settings(); got != want {
		t.Fatalf("second Open Settings() = %+v, want %+v", got, want)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.ModTime().Equal(old) {
		t.Errorf("second Open rewrote settings.json (mtime %v)", info.ModTime())
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
// minReleaseAgeDays, resolveParallelism, downloadParallelism)
// instead of the exported Go field names.
func TestSettingsJSONMatchesTheContract(t *testing.T) {
	settings := defaultSettings

	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}
	wantKeys := []string{"target", "minReleaseAgeDays", "resolveParallelism", "downloadParallelism"}
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
	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, "private", "settings.json"))
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	if !jsonHasKey(t, raw, "minReleaseAgeDays") {
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

func TestSaveSettingsRefusesLimitsOutOfRange(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for name, change := range map[string]func(*Settings){
		"minimum release age":  func(set *Settings) { set.MinReleaseAgeDays = 0 },
		"resolve parallelism":  func(set *Settings) { set.ResolveParallelism = -1 },
		"download parallelism": func(set *Settings) { set.DownloadParallelism = 1000 },
	} {
		set := s.Settings()
		change(&set)
		err := s.SaveSettings(set)
		if !errors.Is(err, ErrInvalidLimits) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: SaveSettings = %v, want ErrInvalidLimits naming it", name, err)
		}
	}
}

// Every directory outside private/ is group-writable, so the tools account
// can swap a temporary file for a link or a file of its own while the store
// writes it. The write then either fails or leaves its own bytes in place.
func TestWriteFileNeverWritesThroughALink(t *testing.T) {
	swaps := []struct {
		name    string
		replace func(tmp, victim string) error
	}{
		{"a link to the signing key", func(tmp, victim string) error { return os.Symlink(victim, tmp) }},
		{"a file of other bytes", func(tmp, _ string) error { return os.WriteFile(tmp, []byte(`{"formatVersion":0}`), fileMode) }},
	}
	for _, tc := range swaps {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			s, err := Open(root)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			victim := filepath.Join(root, "private", "signing-key.pem")
			held, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			beforeTempWrite = func(tmp string) {
				if err := os.Remove(tmp); err != nil {
					t.Error(err)
				}
				if err := tc.replace(tmp, victim); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { beforeTempWrite = nil })

			path := filepath.Join(root, "projects", "manifest.json")
			const data = `{"formatVersion":3}`
			werr := s.WriteFile(path, []byte(data))
			if got, err := os.ReadFile(victim); err != nil || string(got) != string(held) {
				t.Errorf("the link's target changed (%d bytes, %v), want it untouched", len(got), err)
			}
			if werr != nil {
				return
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("WriteFile = <nil>, then %v", err)
			}
			if !info.Mode().IsRegular() {
				t.Fatalf("WriteFile = <nil>, but the destination is %v, want a regular file", info.Mode().Type())
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != data {
				t.Errorf("WriteFile = <nil>, but the destination holds %d other bytes (%v)", len(got), err)
			}
		})
	}
}
