package report

import (
	"cmp"
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/rank"
)

// PipFindingsHeader is the exact column order a pip export's findings.csv
// commits to.
var PipFindingsHeader = []string{"package", "version", "pinned_in", "vulnerability_id", "severity", "fixed_version", "title"}

// PipFindingsRow is one line of a pip export's findings.csv: one
// vulnerability of one package of the set.
type PipFindingsRow struct {
	Package, Version string
	PinnedIn         []string // the requirements files that pin it; empty for a transitive package
	VulnerabilityID  string
	Severity         rank.Severity
	FixedVersion     string // as Trivy reports it
	Title            string
}

// WritePipFindingsCSV writes a pip export's findings.csv: the header
// followed by rows sorted by package, then severity, then id, so the same
// input always gives the same file.
func WritePipFindingsCSV(w io.Writer, rows []PipFindingsRow) error {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b PipFindingsRow) int {
		return cmp.Or(
			strings.Compare(a.Package, b.Package),
			strings.Compare(a.Version, b.Version),
			cmp.Compare(a.Severity, b.Severity),
			strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
		)
	})

	cw := csv.NewWriter(w)
	if err := cw.Write(PipFindingsHeader); err != nil {
		return fmt.Errorf("write findings.csv header: %w", err)
	}
	for _, r := range sorted {
		record := []string{
			r.Package, r.Version, strings.Join(r.PinnedIn, ";"), r.VulnerabilityID,
			r.Severity.String(), r.FixedVersion, r.Title,
		}
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("write findings.csv row: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("write findings.csv: %w", err)
	}
	return nil
}

// PipSummary is the content of a pip export's summary.md.
type PipSummary struct {
	AnalysisDate, TrivyDBDate time.Time
	TrivyVersion, ToolVersion string
	Target                    store.PipTarget
	Files                     []string // every requirements file, in the analysis's order
	InArchive                 rank.Vector
	RemainingCritical         []rank.Finding
	RemainingHigh             []rank.Finding
	Warnings                  []string
	Yanked                    []archive.ReviewYanked // the yanked releases the archive carries, as its review signs them
	ArchiveSize               int64
	ArchiveSHA256             string
	PackageCount              int
}

// WritePipSummary writes a pip export's summary.md.
func WritePipSummary(w io.Writer, s PipSummary) error {
	ew := &errWriter{w: w}
	fmt.Fprintln(ew, "# Export summary")
	fmt.Fprintln(ew)
	fmt.Fprintf(ew, "- Analysis date: %s\n", s.AnalysisDate.Format(time.RFC3339))
	fmt.Fprintf(ew, "- Trivy DB date: %s\n", s.TrivyDBDate.Format(time.DateOnly))
	fmt.Fprintf(ew, "- Trivy version: %s\n", s.TrivyVersion)
	fmt.Fprintf(ew, "- Tool version: %s\n", s.ToolVersion)
	fmt.Fprintf(ew, "- Target: Python %s, %s/%s glibc %s, uv %s\n", s.Target.Python, s.Target.OS, s.Target.CPU, s.Target.Glibc, s.Target.UvVer)
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Requirements files")
	fmt.Fprintln(ew)
	writeItems(ew, s.Files)
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## CVE counts")
	fmt.Fprintln(ew)
	fmt.Fprintln(ew, "| | Critical | High | Medium | Low | Unknown |")
	fmt.Fprintln(ew, "| --- | --- | --- | --- | --- | --- |")
	v := s.InArchive
	fmt.Fprintf(ew, "| In the archive | %d | %d | %d | %d | %d |\n", v[0], v[1], v[2], v[3], v[4])
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Critical and high CVEs")
	fmt.Fprintln(ew)
	if len(s.RemainingCritical) == 0 && len(s.RemainingHigh) == 0 {
		fmt.Fprintln(ew, "None.")
	}
	for _, f := range slices.Concat(s.RemainingCritical, s.RemainingHigh) {
		fmt.Fprintln(ew, pipFindingLine(f))
	}
	fmt.Fprintln(ew)

	// A set with none leaves the section out: an analysis of sealift 0.7.0
	// recorded no yanked mark, and its warnings name what it found.
	if len(s.Yanked) > 0 {
		fmt.Fprintln(ew, "## Yanked releases")
		fmt.Fprintln(ew)
		for _, y := range s.Yanked {
			fmt.Fprintln(ew, yankedLine(y))
		}
		fmt.Fprintln(ew)
	}

	fmt.Fprintln(ew, "## Warnings from the analysis")
	fmt.Fprintln(ew)
	writeItems(ew, s.Warnings)
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Archive")
	fmt.Fprintln(ew)
	fmt.Fprintf(ew, "- Size: %d bytes\n", s.ArchiveSize)
	fmt.Fprintf(ew, "- SHA-256: %s\n", s.ArchiveSHA256)
	fmt.Fprintf(ew, "- Packages: %d\n", s.PackageCount)
	return ew.err
}

// writeItems lists items one per line, as "None." when there are none.
func writeItems(w io.Writer, items []string) {
	if len(items) == 0 {
		fmt.Fprintln(w, "None.")
	}
	for _, item := range items {
		fmt.Fprintf(w, "- %s\n", oneLine(item))
	}
}

// yankedLine names a yanked release with the index's reason, when it gave
// one, and the reason given for carrying it.
func yankedLine(y archive.ReviewYanked) string {
	line := fmt.Sprintf("- %s==%s is yanked on the index", y.Dependency, y.Version)
	if y.IndexReason != "" {
		line += " (" + y.IndexReason + ")"
	}
	return oneLine(line + ". Reason given: " + y.Reason)
}

// pipFindingLine describes one finding with the versions that fix it.
func pipFindingLine(f rank.Finding) string {
	fixed := "no fixed version"
	if f.FixedVersion != "" {
		fixed = "fixed in " + f.FixedVersion
	}
	line := fmt.Sprintf("- [%s] %s in %s==%s, %s", f.Severity, f.ID, f.Package, f.Version, fixed)
	if f.Title != "" {
		line += ": " + f.Title
	}
	return oneLine(line)
}

// oneLine turns every control and format character of s into a space and
// trims the ends. Trivy's text and the analysis's warnings come from
// outside, and a line break in them would start a line of its own, such
// as a second SHA-256.
func oneLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s))
}
