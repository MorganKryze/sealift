package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/store"
)

// The import reads manifest.json through archive.ParseManifest. This test
// fails at the first field the export renames, adds as required or retypes.
func TestManifestParsesAsTheImportReadsIt(t *testing.T) {
	m := Manifest{
		FormatVersion: ManifestFormatVersion,
		ToolVersion:   "0.3.0",
		AnalysisID:    "20260923T120255Z",
		CreatedAt:     time.Date(2026, 9, 23, 12, 4, 24, 410131126, time.UTC),
		Target:        store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
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

	got, err := archive.ParseManifest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	p := got.Packages[0]
	if got.FormatVersion != m.FormatVersion || got.ToolVersion != m.ToolVersion || got.AnalysisID != m.AnalysisID ||
		got.Target != (archive.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"}) ||
		got.Archive != (archive.Summary{SHA256: m.Archive.SHA256, Size: m.Archive.Size}) ||
		p.Name != "@babel/code-frame" || p.File != m.Packages[0].File || !p.PublishConfigStripped ||
		p.ShippedSHA512 != m.Packages[0].ShippedSHA512 || p.OriginalIntegrity != m.Packages[0].OriginalIntegrity {
		t.Errorf("parsed %+v from %s", got, data)
	}
}
