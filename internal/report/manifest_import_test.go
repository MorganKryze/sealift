package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/store"
)

// The import reads manifest.json through archive.ParseManifest. This test
// fails at the first field the export renames, adds as required or retypes.
func TestManifestParsesAsTheImportReadsIt(t *testing.T) {
	// An empty libc is a setting the store has always accepted, so an export
	// made from one must still import.
	for _, libc := range []string{"glibc", ""} {
		t.Run("libc "+libc, func(t *testing.T) { checkManifestParses(t, libc) })
	}
}

func checkManifestParses(t *testing.T, libc string) {
	t.Helper()
	m := Manifest{
		FormatVersion: ManifestFormatVersion,
		ToolVersion:   "0.3.0",
		AnalysisID:    "20260923T120255Z",
		CreatedAt:     time.Date(2026, 9, 23, 12, 4, 24, 410131126, time.UTC),
		Target:        store.Target{OS: "linux", CPU: "x64", Libc: libc, Node: "22.17.1", PnpmVer: "10.34.5"},
		Archive:       ArchiveManifest{SHA256: "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7", Size: 7031361},
		Packages: []PackageEntry{
			{
				Name: "@babel/code-frame", Version: "7.29.7", File: "babel-code-frame-7.29.7.tgz",
				OriginalIntegrity:     "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA==",
				ShippedSHA512:         "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4",
				PublishConfigStripped: true,
			},
		},
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	got, err := archive.ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	p := got.Packages[0]
	if got.FormatVersion != m.FormatVersion || got.ToolVersion != m.ToolVersion || got.AnalysisID != m.AnalysisID ||
		got.Target != (archive.Target{OS: "linux", CPU: "x64", Libc: libc, Node: "22.17.1", PnpmVer: "10.34.5"}) ||
		got.Archive != (archive.Summary{SHA256: m.Archive.SHA256, Size: m.Archive.Size}) ||
		p.Name != "@babel/code-frame" || p.File != m.Packages[0].File || !p.PublishConfigStripped ||
		p.ShippedSHA512 != m.Packages[0].ShippedSHA512 || p.OriginalIntegrity != m.Packages[0].OriginalIntegrity {
		t.Errorf("parsed %+v from %s", got, data)
	}
}

func reviewFixture(name, from, to string) *archive.Review {
	after := [5]int{0, 0, 1, 0, 0}
	return &archive.Review{
		CVEs:    archive.ReviewCVEs{Before: [5]int{1, 2, 1, 0, 0}, After: &after},
		Updates: []archive.ReviewUpdate{{Name: name, From: from, To: to, Fixed: [5]int{1, 2, 0, 0, 0}, Left: [5]int{0, 0, 1, 0, 0}}},
		Kept:    []archive.ReviewKept{{Name: "debug", Version: "2.6.9", Jump: "4.4.3"}},
		Jumps: []archive.ReviewJump{
			{Family: name + " 5", Packages: []archive.ReviewMove{{Name: name, From: from, To: to}}, Reason: "Moved to the next line with the team on 2026-11-20."},
			{Packages: []archive.ReviewMove{{Name: "qs", From: "6.5.2", To: "7.0.0"}}, Reason: "Needed by the new router."},
		},
		Left: []archive.ReviewCVE{
			{Dependency: name, Version: to, ID: "CVE-2024-0001", Severity: "MEDIUM", Package: "cookie", FixedIn: "0.7.0"},
			{Dependency: name, Version: to, ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier", Reason: "No release fixes it; we never minify input."},
		},
		Unchanged: 3,
	}
}

// An export that carries a review writes it where the import reads it, in
// the format an import that predates the review accepts.
func TestManifestWithAReviewParsesAsTheImportReadsIt(t *testing.T) {
	m := npmManifestFixture()
	m.Review = reviewFixture("express", "4.17.1", "5.1.0")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	eco, err := archive.ManifestEcosystem(data)
	if err != nil || eco != archive.NPM {
		t.Fatalf("ManifestEcosystem = %q, %v; want npm", eco, err)
	}
	got, err := archive.ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if got.FormatVersion != 2 || got.ReviewProblem != "" || !reflect.DeepEqual(got.Review, m.Review) {
		t.Errorf("parsed format %d, review %+v, problem %q; want the review %+v", got.FormatVersion, got.Review, got.ReviewProblem, m.Review)
	}
}

func TestPipManifestWithAReviewParsesAsTheImportReadsIt(t *testing.T) {
	m := PipManifest{
		FormatVersion: PipManifestFormatVersion, Ecosystem: store.Pip, ToolVersion: "0.7.0",
		AnalysisID: "20261120T091500Z", CreatedAt: time.Date(2026, 11, 20, 9, 17, 42, 0, time.UTC),
		Target:  store.DefaultPipTarget,
		Archive: ArchiveManifest{SHA256: "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7", Size: 1395712},
		Packages: []WheelEntry{{
			Name: "jinja2", Version: "3.1.6", File: "jinja2-3.1.6-py3-none-any.whl",
			SHA256:        "dc4cadfd8d415504c2c06cd7f95028fcce2e45cd2297b52222fba1c0b0be8abb",
			ShippedSHA512: "43e5e55037605ffd406599cb282af332714528dfd8cb7d3aa42e46c782fb4c7abab45a415ba60b3698e72fd2915750813cdf4a53b47e856db3d78a66712dabde",
		}},
		Review: reviewFixture("jinja2", "3.1.4", "3.1.6"),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got, err := archive.ParsePipManifest(data)
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	if got.ReviewProblem != "" || !reflect.DeepEqual(got.Review, m.Review) {
		t.Errorf("parsed review %+v, problem %q; want %+v", got.Review, got.ReviewProblem, m.Review)
	}
}

// An export without a review writes the bytes it wrote before reviews
// existed.
func TestManifestWithoutAReviewOmitsTheKey(t *testing.T) {
	for name, m := range map[string]any{
		"npm": npmManifestFixture(),
		"pip": PipManifest{FormatVersion: PipManifestFormatVersion, Ecosystem: store.Pip},
	} {
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(`"review"`)) {
			t.Errorf("%s manifest without a review holds the key: %s", name, data)
		}
	}
}
