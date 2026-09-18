package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

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
