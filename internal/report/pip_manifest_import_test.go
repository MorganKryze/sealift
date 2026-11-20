package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/store"
)

// npmManifestGolden holds the bytes 0.6.2 wrote for npmManifestFixture.
// SEALIFT_UPDATE_GOLDEN=1 rewrites it; it is taken at the tag v0.6.2.
const npmManifestGolden = "testdata/npm-manifest-0.6.2.json"

func npmManifestFixture() Manifest {
	return Manifest{
		FormatVersion: ManifestFormatVersion,
		ToolVersion:   "0.6.2",
		AnalysisID:    "20261119T101500Z",
		CreatedAt:     time.Date(2026, 11, 19, 10, 17, 3, 120000000, time.UTC),
		Target:        store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
		Archive:       ArchiveManifest{SHA256: "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7", Size: 7031361},
		Packages: []PackageEntry{
			{
				Name: "@babel/code-frame", Version: "7.29.7", File: "babel-code-frame-7.29.7.tgz",
				OriginalIntegrity:     "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA==",
				ShippedSHA512:         "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4",
				PublishConfigStripped: true,
			},
			{
				Name: "express", Version: "5.1.0", File: "express-5.1.0.tgz",
				OriginalIntegrity: "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA==",
				ShippedSHA512:     "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4",
			},
		},
	}
}

// An npm export signs these exact bytes, so a change to them is a change to
// what every deployed import reads.
func TestNPMManifestBytesUnchanged(t *testing.T) {
	got, err := json.MarshalIndent(npmManifestFixture(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SEALIFT_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(npmManifestGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(npmManifestGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(npmManifestGolden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("manifest bytes changed:\n%s\nwant:\n%s", got, want)
	}
}

// The import reads a pip manifest through archive.ManifestEcosystem, then
// archive.ParsePipManifest. This test fails at the first field the export
// renames, adds as required or retypes.
func TestPipManifestParsesAsTheImportReadsIt(t *testing.T) {
	m := PipManifest{
		FormatVersion: PipManifestFormatVersion,
		Ecosystem:     store.Pip,
		ToolVersion:   "0.7.0",
		AnalysisID:    "20261120T091500Z",
		CreatedAt:     time.Date(2026, 11, 20, 9, 17, 42, 518204331, time.UTC),
		Target:        store.DefaultPipTarget,
		Archive:       ArchiveManifest{SHA256: "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7", Size: 1395712},
		Packages: []WheelEntry{
			{
				Name: "markupsafe", Version: "3.0.2", File: "MarkupSafe-3.0.2-cp311-cp311-manylinux_2_17_x86_64.whl",
				SHA256:        "7743268b07457bf5f423266c39c8de26a3bbea92091b6a7d715a5bdfeffecbc0",
				ShippedSHA512: "2567b4efaa0966369b002906a9ed2f891befe023b797e90a664ddc12b1fb9cc54c9de7d96b7a4aebaa161927a7ff8e1d24ef18e08a998eb92a930f8a213e61ec",
			},
		},
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	eco, err := archive.ManifestEcosystem(data)
	if err != nil || eco != archive.Pip {
		t.Fatalf("ManifestEcosystem = %q, %v; want pip", eco, err)
	}
	got, err := archive.ParsePipManifest(data)
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	target := store.DefaultPipTarget
	w := m.Packages[0]
	if got.FormatVersion != m.FormatVersion || got.Ecosystem != archive.Pip || got.ToolVersion != m.ToolVersion ||
		got.AnalysisID != m.AnalysisID || got.CreatedAt != "2026-11-20T09:17:42.518204331Z" ||
		got.Target != (archive.PipTarget{Python: target.Python, OS: target.OS, CPU: target.CPU, Glibc: target.Glibc, UvVer: target.UvVer}) ||
		got.Archive != (archive.Summary{SHA256: m.Archive.SHA256, Size: m.Archive.Size}) ||
		got.Packages[0] != (archive.Wheel{Name: w.Name, Version: w.Version, File: w.File, SHA256: w.SHA256, ShippedSHA512: w.ShippedSHA512}) {
		t.Errorf("parsed %+v from %s", got, data)
	}

	if _, err := archive.ParseManifest(data); err == nil {
		t.Error("the npm reader accepts a pip manifest")
	}
}
