package report

import (
	"cmp"
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/MorganKryze/sealift/rank"
)

// FindingsHeader is the exact column order findings.csv commits to.
var FindingsHeader = []string{
	"dependency", "current_version", "selected_version",
	"package", "package_version", "vulnerability_id",
	"severity", "status", "fixed_version", "title",
}

// FindingsRow is one line of findings.csv: one dependency update paired
// with one vulnerability affecting one package of its resolution.
type FindingsRow struct {
	Dependency      string
	CurrentVersion  string
	SelectedVersion string
	Package         string
	PackageVersion  string
	VulnerabilityID string
	Severity        rank.Severity
	Status          rank.Status
	FixedVersion    string
	Title           string
}

// DependencyResolution names one dependency's current and selected
// resolutions as rank.Index keys ("name@version"), so FindingsRows can
// compare them.
type DependencyResolution struct {
	Name            string
	CurrentVersion  string
	SelectedVersion string
	CurrentKeys     []string
	SelectedKeys    []string
}

// FindingsRows expands ix into one row per dependency, status and affected
// package. rank.Index.Set collapses several packages carrying the same
// vulnerability ID into the worst one; this instead keeps every affected
// package, because findings.csv reports one row per affected package.
func FindingsRows(ix rank.Index, deps []DependencyResolution) []FindingsRow {
	var rows []FindingsRow
	for _, d := range deps {
		before := ix.Set(d.CurrentKeys)
		after := ix.Set(d.SelectedKeys)
		for _, change := range rank.Diff(before, after) {
			keys := d.SelectedKeys
			if change.Status == rank.Fixed {
				keys = d.CurrentKeys
			}
			for _, key := range keys {
				for _, f := range ix[key] {
					if f.ID != change.Finding.ID {
						continue
					}
					rows = append(rows, FindingsRow{
						Dependency:      d.Name,
						CurrentVersion:  d.CurrentVersion,
						SelectedVersion: d.SelectedVersion,
						Package:         f.Package,
						PackageVersion:  f.Version,
						VulnerabilityID: f.ID,
						Severity:        f.Severity,
						Status:          change.Status,
						FixedVersion:    f.FixedVersion,
						Title:           f.Title,
					})
				}
			}
		}
	}
	return rows
}

// WriteFindingsCSV writes findings.csv: the header followed by rows sorted
// by dependency, then vulnerability ID, then package, so the same input
// always gives the same file.
func WriteFindingsCSV(w io.Writer, rows []FindingsRow) error {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b FindingsRow) int {
		return cmp.Or(
			strings.Compare(a.Dependency, b.Dependency),
			strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
			strings.Compare(a.Package, b.Package),
			strings.Compare(a.PackageVersion, b.PackageVersion),
		)
	})

	cw := csv.NewWriter(w)
	if err := cw.Write(FindingsHeader); err != nil {
		return fmt.Errorf("write findings.csv header: %w", err)
	}
	for _, r := range sorted {
		record := []string{
			r.Dependency, r.CurrentVersion, r.SelectedVersion,
			r.Package, r.PackageVersion, r.VulnerabilityID,
			r.Severity.String(), string(r.Status), r.FixedVersion, r.Title,
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
