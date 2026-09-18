package report

import (
	"bytes"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/rank"
)

func TestWriteSummary(t *testing.T) {
	s := Summary{
		AnalysisDate: time.Date(2026, 9, 10, 8, 30, 0, 0, time.UTC),
		TrivyDBDate:  time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
		TrivyVersion: "0.72.0",
		ToolVersion:  "0.1.0",
		Target:       store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
		Before:       rank.Vector{2, 3, 1, 0, 0},
		After:        &rank.Vector{0, 1, 1, 0, 0},
		Dependencies: []DependencyChange{
			{Name: "lodash", CurrentVersion: "4.17.20", SelectedVersion: "4.17.21", Before: rank.Vector{2, 1, 0, 0, 0}, After: rank.Vector{0, 0, 0, 0, 0}},
		},
		RemainingHigh: []rank.Finding{
			{ID: "CVE-2024-1", Package: "minimist", Version: "1.2.5", Title: "prototype pollution"},
		},
		Signals: []SignalNote{
			{Dependency: "lodash", Version: "4.17.21", Signal: rank.MajorJump, Evidence: "leaves major version 4"},
		},
		ArchiveSize:   4096,
		ArchiveSHA256: "abc123",
		PackageCount:  2,
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, s); err != nil {
		t.Fatal(err)
	}

	want := `# Export summary

- Analysis date: 2026-09-10T08:30:00Z
- Trivy DB date: 2026-09-09
- Trivy version: 0.72.0
- Tool version: 0.1.0
- Target: linux/x64 glibc, Node 22.17.1, pnpm 10.34.5

## CVE counts

| | Critical | High | Medium | Low | Unknown |
| --- | --- | --- | --- | --- | --- |
| Before | 2 | 3 | 1 | 0 | 0 |
| After | 0 | 1 | 1 | 0 | 0 |

## Updated dependencies

| Dependency | Current | Selected | CVE change |
| --- | --- | --- | --- |
| lodash | 4.17.20 | 4.17.21 | -2 critical, -1 high |

## Remaining critical and high CVEs

- [high] CVE-2024-1 in minimist@1.2.5: prototype pollution

## Non-blocking signals on selected versions

- lodash 4.17.21: major-jump (leaves major version 4)

## Archive

- Size: 4096 bytes
- SHA-256: abc123
- Packages: 2
`
	if buf.String() != want {
		t.Errorf("summary.md =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestWriteSummaryEmptySections(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSummary(&buf, Summary{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"None.\n"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("summary.md missing %q in:\n%s", want, buf.String())
		}
	}
}

// TestWriteSummaryNilAfterSaysCheckDidNotRun proves a nil After, the case
// once step 9 failed to measure it, reads as an explicit statement instead
// of a row of zeros that would look like a clean bill of health.
func TestWriteSummaryNilAfterSaysCheckDidNotRun(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSummary(&buf, Summary{Before: rank.Vector{1, 0, 0, 0, 0}}); err != nil {
		t.Fatal(err)
	}
	want := "| After | the combined check did not run | | | | |\n"
	if !bytes.Contains(buf.Bytes(), []byte(want)) {
		t.Errorf("summary.md missing %q in:\n%s", want, buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte("| After | 0 | 0 | 0 | 0 | 0 |")) {
		t.Error("summary.md printed a zero vector for After, want the did-not-run note instead")
	}
}

func TestVectorDelta(t *testing.T) {
	if got := vectorDelta(rank.Vector{1, 0, 0, 0, 0}, rank.Vector{1, 0, 0, 0, 0}); got != "no change" {
		t.Errorf("vectorDelta = %q, want %q", got, "no change")
	}
	if got := vectorDelta(rank.Vector{2, 0, 0, 0, 0}, rank.Vector{0, 1, 0, 0, 0}); got != "-2 critical, +1 high" {
		t.Errorf("vectorDelta = %q", got)
	}
}
