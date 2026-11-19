package jobs

import (
	"testing"

	"github.com/MorganKryze/sealift/rank"
)

// The projected row counts the project once the selection replaces each
// changed dependency: what only the replaced version carried goes, what the
// kept dependencies share stays, and the selected version's own count joins.
func TestProjectedVector(t *testing.T) {
	project := []rank.Finding{
		{ID: "CVE-A", Severity: rank.High},        // only in a@1, which the selection replaces
		{ID: "CVE-SHARED", Severity: rank.Medium}, // in a@1 and in b, which stays
		{ID: "CVE-B", Severity: rank.Low},         // only in b
		{ID: "CVE-A", Severity: rank.Medium},      // the same id on another package: counts once
	}
	deps := []DependencyResult{
		{Name: "a", Current: "1.0.0", Vector: Vector{0, 1, 1, 0, 0},
			CVEs: []CVE{{ID: "CVE-A", Severity: "HIGH"}, {ID: "CVE-SHARED", Severity: "MEDIUM"}},
			Candidates: []Candidate{
				{Version: "1.1.0", Vector: Vector{0, 0, 1, 0, 0}, CVEs: []CVE{{ID: "CVE-NEW", Severity: "MEDIUM"}}},
				{Version: "1.2.0", Vector: Vector{0, 0, 0, 0, 0}, CVEs: []CVE{}},
			}},
		{Name: "b", Current: "2.0.0", CVEs: []CVE{{ID: "CVE-SHARED", Severity: "MEDIUM"}, {ID: "CVE-B", Severity: "LOW"}}},
	}
	cases := []struct {
		name      string
		selection map[string][]string
		want      rank.Vector
	}{
		{"nothing changed", map[string][]string{"b": {"2.0.0"}}, rank.Vector{0, 1, 1, 1, 0}},
		{"one replacement", map[string][]string{"a": {"1.1.0"}}, rank.Vector{0, 0, 2, 1, 0}},
		{"several versions keep the best", map[string][]string{"a": {"1.1.0", "1.2.0"}}, rank.Vector{0, 0, 1, 1, 0}},
		{"the current version competes like the others", map[string][]string{"a": {"1.0.0", "1.2.0"}}, rank.Vector{0, 0, 1, 1, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := projectedVector(project, deps, c.selection); got != c.want {
				t.Errorf("projectedVector = %v, want %v", got, c.want)
			}
		})
	}
}
