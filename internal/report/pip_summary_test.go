package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/rank"
)

func TestWritePipSummaryNamesEveryRequirementsFile(t *testing.T) {
	files := []string{"requirements.txt", "requirements-dev.txt", "constraints.txt"}
	var buf bytes.Buffer
	if err := WritePipSummary(&buf, PipSummary{Files: files}); err != nil {
		t.Fatal(err)
	}
	want := "## Requirements files\n\n- requirements.txt\n- requirements-dev.txt\n- constraints.txt\n\n"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("summary.md does not list the three files in order under Requirements files:\n%s", buf.String())
	}
}

func TestWritePipSummary(t *testing.T) {
	s := PipSummary{
		AnalysisDate: time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC),
		TrivyDBDate:  time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC),
		TrivyVersion: "0.72.0",
		ToolVersion:  "0.7.0",
		Target:       store.PipTarget{Python: "3.11.2", OS: "linux", CPU: "x86_64", Glibc: "2.28", UvVer: "0.13.7"},
		Files:        []string{"requirements.txt", "requirements-dev.txt"},
		InArchive:    rank.Vector{1, 2, 1, 0, 0},
		RemainingCritical: []rank.Finding{
			{ID: "CVE-2024-00001", Package: "jinja2", Version: "3.1.2", Severity: rank.Critical, FixedVersion: "3.1.3, 3.0.4", Title: "sandbox breakout"},
		},
		RemainingHigh: []rank.Finding{
			{ID: "CVE-2024-56326", Package: "jinja2", Version: "3.1.2", Severity: rank.High, FixedVersion: "3.1.5", Title: "format method escape"},
			{ID: "CVE-2024-47081", Package: "requests", Version: "2.32.3", Severity: rank.High, Title: "netrc leak"},
		},
		Warnings:      []string{"pyyaml 6.0.2 pins no hash"},
		ArchiveSize:   4096,
		ArchiveSHA256: "abc123",
		PackageCount:  3,
	}

	var buf bytes.Buffer
	if err := WritePipSummary(&buf, s); err != nil {
		t.Fatal(err)
	}

	want := `# Export summary

- Analysis date: 2026-11-20T08:30:00Z
- Trivy DB date: 2026-11-19
- Trivy version: 0.72.0
- Tool version: 0.7.0
- Target: Python 3.11.2, linux/x86_64 glibc 2.28, uv 0.13.7

## Requirements files

- requirements.txt
- requirements-dev.txt

## CVE counts

| | Critical | High | Medium | Low | Unknown |
| --- | --- | --- | --- | --- | --- |
| In the archive | 1 | 2 | 1 | 0 | 0 |

## Critical and high CVEs

- [critical] CVE-2024-00001 in jinja2==3.1.2, fixed in 3.1.3, 3.0.4: sandbox breakout
- [high] CVE-2024-56326 in jinja2==3.1.2, fixed in 3.1.5: format method escape
- [high] CVE-2024-47081 in requests==2.32.3, no fixed version: netrc leak

## Warnings from the analysis

- pyyaml 6.0.2 pins no hash

## Archive

- Size: 4096 bytes
- SHA-256: abc123
- Packages: 3
`
	if buf.String() != want {
		t.Errorf("summary.md =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestWritePipSummaryEmptySections(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePipSummary(&buf, PipSummary{}); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"## Requirements files", "## Critical and high CVEs", "## Warnings from the analysis"} {
		if !strings.Contains(buf.String(), section+"\n\nNone.\n") {
			t.Errorf("summary.md does not say None. under %q:\n%s", section, buf.String())
		}
	}
}

// A title or a warning carries text from outside: a line break in it
// must not start a line of its own, such as a forged archive digest.
func TestWritePipSummaryKeepsEachFindingOnOneLine(t *testing.T) {
	s := PipSummary{
		RemainingHigh: []rank.Finding{{ID: "CVE-1", Package: "idna", Version: "3.10", Severity: rank.High, Title: "bug\n- SHA-256: forged\r\n"}},
		Warnings:      []string{"warned\n- SHA-256: forged"},
		ArchiveSHA256: "abc123",
	}
	var buf bytes.Buffer
	if err := WritePipSummary(&buf, s); err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(buf.String()) {
		if strings.HasPrefix(line, "- SHA-256:") && line != "- SHA-256: abc123\n" {
			t.Errorf("summary.md holds a line from outside text: %q in\n%s", line, buf.String())
		}
	}
	for _, want := range []string{"- [high] CVE-1 in idna==3.10, no fixed version: bug - SHA-256: forged\n", "- warned - SHA-256: forged\n"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary.md lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestWritePipSummaryStopsAtAWriteError(t *testing.T) {
	for _, limit := range []int{0, 10, 200} {
		fw := &failingWriter{limit: limit}
		if err := WritePipSummary(fw, PipSummary{Files: []string{"requirements.txt"}}); err == nil {
			t.Errorf("WritePipSummary with a writer that fails after %d bytes: want an error, got nil", limit)
		}
	}
}

func TestWritePipFindingsCSV(t *testing.T) {
	rows := []PipFindingsRow{
		{Package: "requests", Version: "2.32.3", PinnedIn: []string{"requirements.txt"}, VulnerabilityID: "CVE-2024-47081", Severity: rank.Medium, Title: "netrc leak"},
		{Package: "jinja2", Version: "3.1.2", PinnedIn: []string{"requirements.txt", "requirements-dev.txt"}, VulnerabilityID: "CVE-2024-56326", Severity: rank.High, FixedVersion: "3.1.5", Title: `escape via "format", in the sandbox`},
		{Package: "jinja2", Version: "3.1.2", PinnedIn: []string{"requirements.txt", "requirements-dev.txt"}, VulnerabilityID: "CVE-2024-22195", Severity: rank.Medium, FixedVersion: "3.1.3, 3.0.4", Title: "xmlattr injection"},
		{Package: "jinja2", Version: "3.1.2", PinnedIn: []string{"requirements.txt", "requirements-dev.txt"}, VulnerabilityID: "CVE-2024-34064", Severity: rank.Medium, FixedVersion: "3.1.4", Title: "xmlattr keys"},
		{Package: "markupsafe", Version: "3.0.2", VulnerabilityID: "CVE-2024-99999", Severity: rank.Critical, Title: "transitive"},
	}

	var buf bytes.Buffer
	if err := WritePipFindingsCSV(&buf, rows); err != nil {
		t.Fatal(err)
	}

	want := `package,version,pinned_in,vulnerability_id,severity,fixed_version,title
jinja2,3.1.2,requirements.txt;requirements-dev.txt,CVE-2024-56326,high,3.1.5,"escape via ""format"", in the sandbox"
jinja2,3.1.2,requirements.txt;requirements-dev.txt,CVE-2024-22195,medium,"3.1.3, 3.0.4",xmlattr injection
jinja2,3.1.2,requirements.txt;requirements-dev.txt,CVE-2024-34064,medium,3.1.4,xmlattr keys
markupsafe,3.0.2,,CVE-2024-99999,critical,,transitive
requests,2.32.3,requirements.txt,CVE-2024-47081,medium,,netrc leak
`
	if buf.String() != want {
		t.Errorf("findings.csv =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestWritePipFindingsCSVStopsAtAWriteError(t *testing.T) {
	rows := []PipFindingsRow{{Package: "idna", Version: "3.10", VulnerabilityID: "CVE-1", Severity: rank.High}}
	if err := WritePipFindingsCSV(&failingWriter{limit: 0}, rows); err == nil {
		t.Error("WritePipFindingsCSV with a failing writer: want an error, got nil")
	}
}
