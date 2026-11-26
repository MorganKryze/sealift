package jobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// TestResolveUsesAGroupWritableDirectoryUnderTheVolume proves resolve gave
// up os.MkdirTemp("") for a directory the tools account, running under a
// different uid once F1 lands, can still traverse: group-writable, and
// under the volume's own cache rather than the system temp directory. It
// also checks resolve removes that directory once it returns, on the
// success path exercised here.
func TestResolveUsesAGroupWritableDirectoryUnderTheVolume(t *testing.T) {
	root := t.TempDir()
	st, err := store.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pnpm := &fakePnpm{}
	a := &Analysis{Store: st, Pnpm: pnpm, Settings: st.Settings()}

	if _, _, err := a.resolve(context.Background(), []byte(`{"dependencies":{}}`)); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(pnpm.dirs) != 1 {
		t.Fatalf("pnpm.dirs = %v, want exactly one resolution", pnpm.dirs)
	}
	dir := pnpm.dirs[0]
	wantParent := filepath.Join(root, "cache", "resolve")
	if !strings.HasPrefix(dir, wantParent+string(filepath.Separator)) {
		t.Errorf("resolve dir = %q, want it under %q", dir, wantParent)
	}
	if len(pnpm.dirModes) != 1 {
		t.Fatalf("pnpm.dirModes = %v, want exactly one recorded mode", pnpm.dirModes)
	}
	if got := pnpm.dirModes[0]; got&0o020 == 0 {
		t.Errorf("resolve dir mode = %o, want group-writable", got)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("resolve dir %q still exists after resolve returned (err = %v), want it removed", dir, err)
	}
}

// TestBuildFullManifest checks that each dependency lands in the
// package.json field its kind names, and that an override replaces its
// version there instead of leaving the current one.
func TestBuildFullManifest(t *testing.T) {
	manifest := npm.Manifest{Dependencies: []npm.Dependency{
		{Name: "foo", Version: "1.0.0", Kind: npm.Prod},
		{Name: "bar", Version: "2.0.0", Kind: npm.Dev},
		{Name: "baz", Version: "3.0.0", Kind: npm.Optional},
	}}
	data := buildFullManifest(manifest, map[string]string{"foo": "1.1.0"})

	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Dependencies["foo"] != "1.1.0" {
		t.Errorf("dependencies.foo = %q, want the override 1.1.0", doc.Dependencies["foo"])
	}
	if doc.DevDependencies["bar"] != "2.0.0" {
		t.Errorf("devDependencies.bar = %q, want 2.0.0", doc.DevDependencies["bar"])
	}
	if doc.OptionalDependencies["baz"] != "3.0.0" {
		t.Errorf("optionalDependencies.baz = %q, want 3.0.0", doc.OptionalDependencies["baz"])
	}
}

// TestBuildProbeManifest checks that only a peer the project itself
// declares gets pinned into the isolated resolution's manifest.
func TestBuildProbeManifest(t *testing.T) {
	data := buildProbeManifest("foo", "2.0.0",
		map[string]string{"react": "^18.0.0", "left-pad": "^1.0.0"},
		map[string]string{"react": "18.2.0"},
	)
	var doc struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Dependencies["foo"] != "2.0.0" {
		t.Errorf("dependencies.foo = %q, want 2.0.0", doc.Dependencies["foo"])
	}
	if doc.Dependencies["react"] != "18.2.0" {
		t.Errorf("dependencies.react = %q, want the project's own pin 18.2.0", doc.Dependencies["react"])
	}
	if _, ok := doc.Dependencies["left-pad"]; ok {
		t.Errorf("dependencies has left-pad, want it left out: the project does not declare it")
	}
}

// TestOrderKeyFirst checks that key candidates come first, in the order
// KeyVersions gave them, and every other candidate keeps its ascending
// order behind them.
func TestOrderKeyFirst(t *testing.T) {
	newer := []string{"1.1.0", "1.2.0", "2.0.0"}
	keys := []string{"2.0.0"}
	got := orderKeyFirst(newer, keys)
	want := []string{"2.0.0", "1.1.0", "1.2.0"}
	if !equalStrings(got, want) {
		t.Errorf("orderKeyFirst(%v, %v) = %v, want %v", newer, keys, got, want)
	}
}

// TestToSignals checks the conversion from rank.Hit to the jobs.Signal
// shape the API returns, including the derived Blocking flag.
func TestToSignals(t *testing.T) {
	hits := []rank.Hit{
		{Signal: rank.TooRecent, Evidence: "published yesterday"},
		{Signal: rank.MajorJump, Evidence: "leaves major version 1"},
	}
	got := toSignals(hits)
	if len(got) != 2 {
		t.Fatalf("len(toSignals(hits)) = %d, want 2", len(got))
	}
	if got[0].Name != "too-recent" || !got[0].Blocking {
		t.Errorf("signal[0] = %+v, want too-recent, blocking", got[0])
	}
	if got[1].Name != "major-jump" || got[1].Blocking {
		t.Errorf("signal[1] = %+v, want major-jump, not blocking", got[1])
	}
}

// TestMergeTrivyReports checks that step 7's two Trivy calls end up
// concatenated into one report, as candidates.trivy.json needs.
func TestMergeTrivyReports(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(a, []byte(`{"SchemaVersion":2,"Results":[{"Target":"a"}]}`), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"SchemaVersion":2,"Results":[{"Target":"b"},{"Target":"c"}]}`), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := mergeTrivyReports([]string{a, b}, out); err != nil {
		t.Fatalf("mergeTrivyReports: %v", err)
	}

	merged, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report trivyReport
	if err := json.Unmarshal(merged, &report); err != nil {
		t.Fatalf("unmarshal merged report: %v", err)
	}
	if report.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", report.SchemaVersion)
	}
	if len(report.Results) != 3 {
		t.Errorf("len(Results) = %d, want 3 (1 from a.json, 2 from b.json)", len(report.Results))
	}
}

func TestFactsOfReadsNodeBesideAnEngineThatIsNotAString(t *testing.T) {
	target := store.Target{Node: "22.17.1"}
	for _, tc := range []struct {
		name           string
		engines        string
		wantRange      string
		wantCompatible bool
	}{
		{name: "node range beside a number", engines: `{"node": ">=99", "npm": 7}`, wantRange: ">=99", wantCompatible: false},
		{name: "node range beside an npm object", engines: `{"node": ">=18", "npm": {"min": 9}}`, wantRange: ">=18", wantCompatible: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var meta npm.VersionMeta
			if err := json.Unmarshal([]byte(`{"version": "1.0.0", "engines": `+tc.engines+`}`), &meta); err != nil {
				t.Fatal(err)
			}
			f := factsOf("1.0.0", meta, npm.Packument{}, target)
			if f.NodeRange != tc.wantRange || f.NodeCompatible != tc.wantCompatible {
				t.Errorf("NodeRange = %q, NodeCompatible = %v; want %q, %v", f.NodeRange, f.NodeCompatible, tc.wantRange, tc.wantCompatible)
			}
		})
	}
}

func TestFactsOfFlagsANodeEngineThatIsNotAString(t *testing.T) {
	const doc = `{
	  "name": "pkg",
	  "versions": {
	    "1.0.0": {"version": "1.0.0", "engines": {"node": ">=18"}},
	    "1.1.0": {"version": "1.1.0", "engines": {"node": 18}},
	    "1.2.0": {"version": "1.2.0", "engines": {"node": {"x": 1}}},
	    "1.3.0": {"version": "1.3.0", "engines": {"node": [">=18"]}},
	    "1.4.0": {"version": "1.4.0", "engines": {"node": null}},
	    "1.5.0": {"version": "1.5.0", "engines": {"node": ">=99"}},
	    "1.6.0": {"version": "1.6.0", "engines": {"node": 0}},
	    "1.7.0": {"version": "1.7.0", "engines": {"node": false}}
	  }
	}`
	var pk npm.Packument
	if err := json.Unmarshal([]byte(doc), &pk); err != nil {
		t.Fatal(err)
	}
	target := store.Target{Node: "18.20.4"}
	policy := rank.Policy{TargetNode: target.Node}
	current := factsOf("1.0.0", pk.Versions["1.0.0"], pk, target)
	// pnpm skips an engines.node that is null, 0 or false, as it skips one
	// that is absent or empty, so those set no constraint.
	for version, wantMismatch := range map[string]bool{
		"1.0.0": false, "1.1.0": true, "1.2.0": true, "1.3.0": true, "1.4.0": false, "1.5.0": true,
		"1.6.0": false, "1.7.0": false,
	} {
		t.Run(version, func(t *testing.T) {
			f := factsOf(version, pk.Versions[version], pk, target)
			mismatch := false
			for _, h := range rank.Signals(current, f, policy) {
				if h.Signal == rank.NodeMismatch {
					mismatch = true
				}
			}
			if mismatch != wantMismatch || f.NodeCompatible == wantMismatch {
				t.Errorf("node mismatch = %v, NodeCompatible = %v, NodeRange = %q; want mismatch %v", mismatch, f.NodeCompatible, f.NodeRange, wantMismatch)
			}
		})
	}
}
