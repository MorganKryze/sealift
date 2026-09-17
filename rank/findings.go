// Package rank scores vulnerability findings, flags risky candidate
// versions, and picks the best candidate version of a dependency.
package rank

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Severity orders vulnerability severities from most to least serious.
type Severity int

// Severities, most serious first.
const (
	Critical Severity = iota
	High
	Medium
	Low
	Unknown
)

// ParseSeverity maps a Trivy severity name; any other value gives Unknown.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	}
	return Unknown
}

// String returns the lowercase severity name.
func (s Severity) String() string {
	return [...]string{"critical", "high", "medium", "low", "unknown"}[s]
}

// Finding is one vulnerability reported for a package version.
type Finding struct {
	ID           string
	Package      string
	Version      string
	Severity     Severity
	FixedVersion string // as Trivy reports it, possibly a list such as "4.19.2, 5.0.0-beta.3"
	Title        string
}

// ReadTrivyJSON reads the vulnerabilities of a `trivy --format json` report.
func ReadTrivyJSON(r io.Reader) ([]Finding, error) {
	var report struct {
		SchemaVersion int
		Results       []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string
				PkgName          string
				InstalledVersion string
				FixedVersion     string
				Severity         string
				Title            string
			}
		}
	}
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("read trivy report: %w", err)
	}
	if report.SchemaVersion != 2 {
		return nil, fmt.Errorf("read trivy report: schema version %d, want 2", report.SchemaVersion)
	}
	var findings []Finding
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			findings = append(findings, Finding{
				ID:           v.VulnerabilityID,
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				Severity:     ParseSeverity(v.Severity),
				FixedVersion: v.FixedVersion,
				Title:        v.Title,
			})
		}
	}
	return findings, nil
}

// Index looks findings up by "name@version".
type Index map[string][]Finding

// NewIndex groups findings by "name@version".
func NewIndex(findings []Finding) Index {
	ix := Index{}
	for _, f := range findings {
		key := f.Package + "@" + f.Version
		ix[key] = append(ix[key], f)
	}
	return ix
}

// Set returns the distinct vulnerabilities, keyed by ID, that affect any of
// the "name@version" keys. When an ID comes with several severities, the
// most serious one wins.
func (ix Index) Set(keys []string) map[string]Finding {
	set := map[string]Finding{}
	for _, key := range keys {
		for _, f := range ix[key] {
			if prev, ok := set[f.ID]; !ok || f.Severity < prev.Severity {
				set[f.ID] = f
			}
		}
	}
	return set
}

// Vector counts distinct vulnerabilities by severity, most serious first.
type Vector [5]int

// VectorOf counts a vulnerability set by severity.
func VectorOf(set map[string]Finding) Vector {
	var v Vector
	for _, f := range set {
		v[f.Severity]++
	}
	return v
}

// Compare orders vectors: fewer critical first, then fewer high, and so on.
// It returns -1, 0 or +1.
func (v Vector) Compare(o Vector) int {
	return slices.Compare(v[:], o[:])
}
