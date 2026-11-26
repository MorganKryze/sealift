package policy

import (
	"errors"
	"fmt"
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

func TestStoredValueOutsideTheRulesStopsTheStart(t *testing.T) {
	for _, c := range []struct {
		name                 string
		change               func(*store.Settings)
		key, policyKey, rule string
		replace              string // a policy that sets the key
	}{
		{"a node range", func(s *store.Settings) { s.Target.Node = "22" }, "target", "targets.npm", `node must be exact, such as 22.17.1, not "22"`,
			"targets:\n  npm: {os: linux, cpu: x64, libc: glibc, node: 22.17.1, pnpm: 10.34.5}\n"},
		{"a target without pnpm", func(s *store.Settings) { s.Target.PnpmVer = "" }, "target", "targets.npm", "pnpm version is empty",
			"targets:\n  npm: {os: linux, cpu: x64, libc: glibc, node: 22.17.1, pnpm: 10.34.5}\n"},
		{"a release age past the maximum", func(s *store.Settings) { s.MinReleaseAgeDays = 120 }, "minReleaseAgeDays", "minReleaseAgeDays", "must be between 1 and 90, not 120",
			"minReleaseAgeDays: 30\n"},
		{"a negative release age", func(s *store.Settings) { s.MinReleaseAgeDays = -1 }, "minReleaseAgeDays", "minReleaseAgeDays", "must be between 1 and 90, not -1",
			"minReleaseAgeDays: 30\n"},
		{"a resolve parallelism past the maximum", func(s *store.Settings) { s.ResolveParallelism = 17 }, "resolveParallelism", "parallelism.resolve", "must be between 1 and 16, not 17",
			"parallelism: {resolve: 4}\n"},
		{"a download parallelism past the maximum", func(s *store.Settings) { s.DownloadParallelism = 33 }, "downloadParallelism", "parallelism.download", "must be between 1 and 32, not 33",
			"parallelism: {download: 8}\n"},
	} {
		stored := stored070
		c.change(&stored)
		_, err := Load("", stored, true)
		var held *StoredError
		if !errors.As(err, &held) {
			t.Errorf("%s: Load = %v, want a StoredError", c.name, err)
			continue
		}
		if held.Key != c.key || held.PolicyKey != c.policyKey {
			t.Errorf("%s: the error names %q and %q, want %q and %q", c.name, held.Key, held.PolicyKey, c.key, c.policyKey)
		}
		for _, want := range []string{c.key + " ", c.rule, "set " + c.policyKey + " in the policy file"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: Load = %q, want it to hold %q", c.name, err, want)
			}
		}

		p, err := Load(writePolicy(t, c.replace), stored, true)
		if err != nil {
			t.Errorf("%s: Load with a policy that sets %s: %v", c.name, c.policyKey, err)
			continue
		}
		if !slices.Contains(p.Overrides, c.policyKey) {
			t.Errorf("%s: Overrides = %v, want %s", c.name, p.Overrides, c.policyKey)
		}
	}
}

func TestStoredValueAtEachLimitStays(t *testing.T) {
	for _, stored := range []store.Settings{
		{Target: stored070.Target, MinReleaseAgeDays: 90, ResolveParallelism: 16, DownloadParallelism: 32},
		{Target: stored070.Target, MinReleaseAgeDays: 1, ResolveParallelism: 1, DownloadParallelism: 1},
	} {
		p, err := Load("", stored, true)
		if err != nil {
			t.Errorf("Load(%+v): %v", stored, err)
		} else if p.Settings != stored {
			t.Errorf("Settings = %+v, want the stored %+v", p.Settings, stored)
		}
	}
}

func TestStoredZeroGivesTheDefaultAndSaysSo(t *testing.T) {
	stored := store.Settings{MinReleaseAgeDays: 0, ResolveParallelism: 6, DownloadParallelism: 0}
	p, err := Load("", stored, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := store.DefaultSettings
	want.ResolveParallelism = 6
	if p.Settings != want {
		t.Errorf("Settings = %+v, want %+v", p.Settings, want)
	}
	if wantKeys := []string{"targets.npm", "minReleaseAgeDays", "parallelism.download"}; !slices.Equal(p.Defaulted, wantKeys) {
		t.Errorf("Defaulted = %v, want %v", p.Defaulted, wantKeys)
	}

	set, err := Load(writePolicy(t, "minReleaseAgeDays: 14\n"), stored, true)
	if err != nil {
		t.Fatalf("Load with a policy: %v", err)
	}
	if wantKeys := []string{"targets.npm", "parallelism.download"}; !slices.Equal(set.Defaulted, wantKeys) {
		t.Errorf("Defaulted under a policy that sets the release age = %v, want %v", set.Defaulted, wantKeys)
	}
	if !slices.Equal(set.Overrides, []string{"minReleaseAgeDays"}) {
		t.Errorf("Overrides = %v, want minReleaseAgeDays, which replaces a stored 0", set.Overrides)
	}

	for _, hasStored := range []bool{false, true} {
		var held store.Settings
		if hasStored {
			held = stored070
		}
		if p, _ := Load("", held, hasStored); len(p.Defaulted) != 0 {
			t.Errorf("hasStored %v: Defaulted = %v, want none", hasStored, p.Defaulted)
		}
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
	refused(t, "parallelism:\n  resolve: 0\n", "parallelism.resolve", "between 1 and 16", "not 0")
	refused(t, "parallelism:\n  resolve: 17\n", "parallelism.resolve", "between 1 and 16", "not 17")
	refused(t, "parallelism:\n  download: 0\n", "parallelism.download", "between 1 and 32", "not 0")
	refused(t, "parallelism:\n  download: 33\n", "parallelism.download", "between 1 and 32", "not 33")
	refused(t, "minReleaseAgeDays: soon\n", "line 1", "wrong type")
}

func TestPolicyAcceptsEachLimitFromOneToItsMaximum(t *testing.T) {
	for _, l := range []struct {
		key, line string
		max       int
		got       func(store.Settings) int
	}{
		{"minReleaseAgeDays", "minReleaseAgeDays: %d\n", 90, func(s store.Settings) int { return s.MinReleaseAgeDays }},
		{"parallelism.resolve", "parallelism:\n  resolve: %d\n", 16, func(s store.Settings) int { return s.ResolveParallelism }},
		{"parallelism.download", "parallelism:\n  download: %d\n", 32, func(s store.Settings) int { return s.DownloadParallelism }},
	} {
		for _, v := range []int{1, l.max} {
			p, err := Load(writePolicy(t, fmt.Sprintf(l.line, v)), store.Settings{}, false)
			if err != nil {
				t.Errorf("%s: %d: Load: %v", l.key, v, err)
				continue
			}
			if got := l.got(p.Settings); got != v {
				t.Errorf("%s: %d gave %d", l.key, v, got)
			}
		}
	}
}

func TestPolicyRefusesASecondDocument(t *testing.T) {
	for _, body := range []string{
		"---\n---\nminReleaseAgeDays: 30\n",
		"minReleaseAgeDays: 14\nparallelism: {resolve: 4}\n---\nminReleaseAgeDays: 30\n",
		"minReleaseAgeDays: 14\n---\nreleaseAge: 30\n",
		"minReleaseAgeDays: 14\n...\n---\n",
	} {
		refused(t, body, "holds more than one YAML document")
	}
	for _, body := range []string{
		"---\nminReleaseAgeDays: 30\n",
		"minReleaseAgeDays: 30\n...\n",
	} {
		p, err := Load(writePolicy(t, body), store.Settings{}, false)
		if err != nil {
			t.Errorf("Load(%q): %v", body, err)
		} else if p.Settings.MinReleaseAgeDays != 30 {
			t.Errorf("Load(%q) set the release age to %d, want 30", body, p.Settings.MinReleaseAgeDays)
		}
	}
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

func TestReviewDefaults(t *testing.T) {
	want := Review{ProposeOtherMajors: false, MajorJump: AskReason, CVEWithoutFix: AskReason, Yanked: AskReason}
	if got := DefaultReview(); got != want {
		t.Errorf("DefaultReview() = %+v, want %+v", got, want)
	}
	for name, path := range map[string]string{
		"no file":                    "",
		"a file without review":      writePolicy(t, "minReleaseAgeDays: 30\n"),
		"an empty review":            writePolicy(t, "review: {}\n"),
		"a review that sets nothing": writePolicy(t, "review:\n"),
	} {
		p, err := Load(path, stored070, true)
		if err != nil {
			t.Errorf("%s: Load: %v", name, err)
			continue
		}
		if p.Review != want {
			t.Errorf("%s: Review = %+v, want the defaults %+v", name, p.Review, want)
		}
	}
}

func TestPolicyReadsTheReviewRules(t *testing.T) {
	for _, c := range []struct {
		body string
		want Review
	}{
		{"review:\n  proposeOtherMajors: true\n  majorJump: refuse\n  cveWithoutFix: refuse\n", Review{ProposeOtherMajors: true, MajorJump: Refuse, CVEWithoutFix: Refuse, Yanked: AskReason}},
		{"review:\n  proposeOtherMajors: false\n  majorJump: reason\n  cveWithoutFix: reason\n", Review{MajorJump: AskReason, CVEWithoutFix: AskReason, Yanked: AskReason}},
		{"review:\n  proposeOtherMajors: true\n", Review{ProposeOtherMajors: true, MajorJump: AskReason, CVEWithoutFix: AskReason, Yanked: AskReason}},
		{"review:\n  majorJump: refuse\n", Review{MajorJump: Refuse, CVEWithoutFix: AskReason, Yanked: AskReason}},
		{"review:\n  cveWithoutFix: refuse\n", Review{MajorJump: AskReason, CVEWithoutFix: Refuse, Yanked: AskReason}},
	} {
		p, err := Load(writePolicy(t, c.body), store.Settings{}, false)
		if err != nil {
			t.Errorf("Load(%q): %v", c.body, err)
			continue
		}
		if p.Review != c.want {
			t.Errorf("Load(%q).Review = %+v, want %+v", c.body, p.Review, c.want)
		}
	}
}

func TestReadPolicyReviewYanked(t *testing.T) {
	for _, c := range []struct {
		body string
		want Rule
	}{
		{"review:\n  majorJump: refuse\n", AskReason},
		{"review:\n  yanked: reason\n", AskReason},
		{"review:\n  yanked: refuse\n", Refuse},
	} {
		p, err := Load(writePolicy(t, c.body), store.Settings{}, false)
		if err != nil {
			t.Errorf("Load(%q): %v", c.body, err)
			continue
		}
		if p.Review.Yanked != c.want {
			t.Errorf("Load(%q).Review.Yanked = %q, want %q", c.body, p.Review.Yanked, c.want)
		}
	}
	for _, value := range []string{"maybe", "Refuse", " null"} {
		body := "review:\n  yanked: " + value + "\n"
		_, err := Load(writePolicy(t, body), store.Settings{}, false)
		if err == nil || !strings.Contains(err.Error(), "review.yanked must be one of reason, refuse") {
			t.Errorf("Load(%q) = %v, want the start stopped with review.yanked must be one of reason, refuse", body, err)
		}
		if err != nil && strings.Contains(err.Error(), "maybe") {
			t.Errorf("Load(%q) = %q, which repeats the file's value", body, err)
		}
	}
}

// A rule key written with no value would otherwise fall back to the
// permissive default without a word, while an empty string is refused.
func TestPolicyRefusesARuleWithNoValue(t *testing.T) {
	for _, key := range []string{"majorJump", "cveWithoutFix", "yanked"} {
		for _, value := range []string{"", " null", " ~"} {
			refused(t, "review:\n  "+key+":"+value+"\n", "review."+key, "reason, refuse")
		}
	}
}

func TestPolicyRefusesAnUnknownReviewRule(t *testing.T) {
	for _, c := range []struct{ key, value string }{
		{"majorJump", "forbid"},
		{"cveWithoutFix", "forbid"},
		{"majorJump", "Refuse"},
		{"cveWithoutFix", "\"\""},
		{"majorJump", "\"refuse \""},
	} {
		body := fmt.Sprintf("review:\n  %s: %s\n", c.key, c.value)
		refused(t, body, "review."+c.key, "reason, refuse")
		_, err := Load(writePolicy(t, body), store.Settings{}, false)
		if err != nil && c.value == "forbid" && strings.Contains(err.Error(), "forbid") {
			t.Errorf("Load(%q) = %q, which repeats the file's value", body, err)
		}
	}
	refused(t, "review:\n  majorJumps: refuse\n", "review.majorJumps", "unknown key", "line 2")
	refused(t, "review:\n  proposeOtherMajors: sometimes\n", "line 2", "wrong type")
	refused(t, "review:\n  majorJump: [reason]\n", "line 2", "wrong type")
}
