package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

func TestManifestJSONFields(t *testing.T) {
	m := Manifest{
		FormatVersion: ManifestFormatVersion,
		ToolVersion:   "0.1.0",
		AnalysisID:    "20260917T101502Z",
		CreatedAt:     time.Date(2026, 9, 17, 10, 20, 0, 0, time.UTC),
		Target:        store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
		Archive:       ArchiveManifest{SHA256: "abc123", Size: 4096},
		Packages: []PackageEntry{
			{
				Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz",
				OriginalIntegrity: "sha512-AA==", ShippedSHA512: "deadbeef", PublishConfigStripped: true,
			},
		},
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"formatVersion", "toolVersion", "analysisId", "createdAt", "target", "archive", "packages"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("manifest JSON missing key %q in %s", key, data)
		}
	}

	var pkgs []map[string]json.RawMessage
	if err := json.Unmarshal(fields["packages"], &pkgs); err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d entries, want 1", len(pkgs))
	}
	for _, key := range []string{"name", "version", "file", "originalIntegrity", "shippedSha512", "publishConfigStripped"} {
		if _, ok := pkgs[0][key]; !ok {
			t.Errorf("package entry missing key %q in %s", key, fields["packages"])
		}
	}

	var back Manifest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.FormatVersion != 1 || back.Packages[0].Name != "left-pad" || !back.Packages[0].PublishConfigStripped {
		t.Errorf("round trip = %+v", back)
	}
}
