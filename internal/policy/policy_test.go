package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
)

// writePolicy writes body as policy.yaml in a fresh directory and returns
// its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// refused loads body and expects a refusal whose reason holds every part of want.
func refused(t *testing.T, body string, want ...string) {
	t.Helper()
	_, err := Load(writePolicy(t, body), store.Settings{}, false)
	if err == nil {
		t.Fatalf("Load accepted:\n%s", body)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("Load = %q, want it to name %q", err, w)
		}
	}
}

// stored070 is what a 0.7.0 volume's settings held after its operator
// changed the release age and the target.
var stored070 = store.Settings{
	Target:              store.Target{OS: "linux", CPU: "arm64", Libc: "musl", Node: "20.19.0", PnpmVer: "10.30.1"},
	MinReleaseAgeDays:   21,
	ResolveParallelism:  6,
	DownloadParallelism: 8,
}

func TestNoFileGivesTheDefaults(t *testing.T) {
	p, err := Load("", store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Settings != store.DefaultSettings {
		t.Errorf("Settings = %+v, want the defaults %+v", p.Settings, store.DefaultSettings)
	}
	if p.Pip != store.DefaultPipTarget {
		t.Errorf("Pip = %+v, want %+v", p.Pip, store.DefaultPipTarget)
	}
	if len(p.Overrides) != 0 {
		t.Errorf("Overrides = %v, want none", p.Overrides)
	}
	if p.Brand.Name != "sealift" || p.Brand.Logo != nil {
		t.Errorf("Brand = %+v, want the default brand", p.Brand)
	}

	empty, err := Load(writePolicy(t, ""), store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load of an empty file: %v", err)
	}
	if empty.Settings != store.DefaultSettings || empty.Pip != store.DefaultPipTarget {
		t.Errorf("an empty file gave %+v and %+v, want the defaults", empty.Settings, empty.Pip)
	}
}

func TestStoredValueStaysWithoutAPolicy(t *testing.T) {
	for name, path := range map[string]string{
		"no file":                  "",
		"a file that sets nothing": writePolicy(t, "brand:\n  name: Harbour\n"),
	} {
		p, err := Load(path, stored070, true)
		if err != nil {
			t.Fatalf("%s: Load: %v", name, err)
		}
		if p.Settings != stored070 {
			t.Errorf("%s: Settings = %+v, want the stored %+v", name, p.Settings, stored070)
		}
		if len(p.Overrides) != 0 {
			t.Errorf("%s: Overrides = %v, want none", name, p.Overrides)
		}
	}
}

func TestPolicyWinsOverTheStoredValue(t *testing.T) {
	path := writePolicy(t, `
targets:
  npm: {os: linux, cpu: x64, libc: glibc, node: 22.17.1, pnpm: 10.34.5}
minReleaseAgeDays: 30
parallelism:
  download: 8
`)
	p, err := Load(path, stored070, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := store.Settings{
		Target:              store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
		MinReleaseAgeDays:   30,
		ResolveParallelism:  6,
		DownloadParallelism: 8,
	}
	if p.Settings != want {
		t.Errorf("Settings = %+v, want %+v", p.Settings, want)
	}
	// parallelism.download sets the value the volume already held, so it
	// overrides nothing.
	if wantKeys := []string{"targets.npm", "minReleaseAgeDays"}; !slices.Equal(p.Overrides, wantKeys) {
		t.Errorf("Overrides = %v, want %v", p.Overrides, wantKeys)
	}

	fresh, err := Load(path, store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load on a fresh volume: %v", err)
	}
	if len(fresh.Overrides) != 0 {
		t.Errorf("Overrides on a fresh volume = %v, want none", fresh.Overrides)
	}
	if fresh.Settings.ResolveParallelism != store.DefaultSettings.ResolveParallelism || fresh.Settings.MinReleaseAgeDays != 30 {
		t.Errorf("Settings on a fresh volume = %+v, want the file's values over the defaults", fresh.Settings)
	}
}

func TestPolicyRefusesAnUnknownKey(t *testing.T) {
	refused(t, "minReleaseAge: 30\n", "minReleaseAge", "unknown key", "line 1")
	refused(t, "brand:\n  colour: \"#123456\"\n", "brand.colour", "unknown key")
	refused(t, "targets:\n  npm: {os: linux, cpu: x64, libc: glibc, node: 22.17.1, pnpm: 10.34.5, arch: x64}\n", "targets.npm.arch")
	refused(t, "brand:\n  contact: {label: Ops, url: \"https://ops.example\", phone: \"1\"}\n", "brand.contact.phone")
}

func TestPolicyRefusesAValueOutOfRange(t *testing.T) {
	refused(t, "minReleaseAgeDays: 0\n", "minReleaseAgeDays", "between 1 and 90", "not 0")
	refused(t, "minReleaseAgeDays: 91\n", "minReleaseAgeDays", "between 1 and 90")
	refused(t, "parallelism:\n  resolve: 17\n", "parallelism.resolve", "between 1 and 16")
	refused(t, "parallelism:\n  download: 0\n", "parallelism.download", "between 1 and 32")
	refused(t, "minReleaseAgeDays: soon\n", "line 1", "wrong type")
}

func TestPolicyRefusesAHalfTarget(t *testing.T) {
	refused(t, "targets:\n  npm: {os: linux, cpu: x64, libc: glibc, node: 22.17.1}\n", "targets.npm.pnpm", "required")
	refused(t, "targets:\n  pip: {python: 3.11.2, os: linux, cpu: x86_64, uv: 0.13.7}\n", "targets.pip.glibc", "required")
	refused(t, "targets:\n  npm: {os: linux, cpu: x64, libc: glibc, node: 22.x, pnpm: 10.34.5}\n", "targets.npm", "node must be exact")
	refused(t, "targets:\n  pip: {python: 3.11.2, os: linux, cpu: x86_64, glibc: \"2.10\", uv: 0.13.7}\n", "targets.pip", "glibc must be 2.17 to 2.40")
}

func TestPolicyRefusesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	_, err := Load(path, store.Settings{}, false)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("Load of a missing file = %v, want it to say the file does not exist", err)
	}

	dir := t.TempDir()
	if _, err := Load(dir, store.Settings{}, false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Load of a directory = %v, want it refused as not a regular file", err)
	}

	big := writePolicy(t, "# "+strings.Repeat("x", 64<<10)+"\n")
	if _, err := Load(big, store.Settings{}, false); err == nil || !strings.Contains(err.Error(), "larger than 65536 bytes") {
		t.Errorf("Load of a 64 KiB file = %v, want it refused for its size", err)
	}

	if _, err := Load(writePolicy(t, "brand: [\n"), store.Settings{}, false); err == nil || !strings.Contains(err.Error(), "not valid YAML") {
		t.Errorf("Load of broken YAML = %v, want it refused as not valid YAML", err)
	}
}

func TestPipTargetFromThePolicy(t *testing.T) {
	p, err := Load(writePolicy(t, "targets:\n  pip: {python: 3.12.4, os: linux, cpu: x86_64, glibc: 2.31, uv: 0.13.7}\n"), stored070, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := store.PipTarget{Python: "3.12.4", OS: "linux", CPU: "x86_64", Glibc: "2.31", UvVer: "0.13.7"}
	if p.Pip != want {
		t.Errorf("Pip = %+v, want %+v", p.Pip, want)
	}
	if p.Settings != stored070 || len(p.Overrides) != 0 {
		t.Errorf("a pip target changed the npm settings: %+v, overrides %v", p.Settings, p.Overrides)
	}
}
