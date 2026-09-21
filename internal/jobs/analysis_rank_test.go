package jobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// TestRankDependency_CurrentVersionResolveFailure covers the case a design
// review flagged: when the current version's own isolated resolution
// fails, dr.Vector has nothing to hold but its zero value, and rank.Best
// would read that as "no CVEs", recommending nothing is wrong and picking
// a "best" candidate the user never asked to compare against anything.
// rankDependency must warn instead, and never call rank.Best for this
// dependency.
func TestRankDependency_CurrentVersionResolveFailure(t *testing.T) {
	r := &run{
		a:      &Analysis{Settings: store.Settings{Target: store.Target{Node: "22.17.1"}}},
		ctx:    context.Background(),
		emit:   func(Event) {},
		result: &Result{},
	}
	dep := npm.Dependency{Name: "foo", Version: "1.0.0"}
	d := depInfo{
		dep: dep,
		packument: npm.Packument{Name: "foo", Versions: map[string]npm.VersionMeta{
			"1.0.0": {Version: "1.0.0"},
			"1.1.0": {Version: "1.1.0"},
		}},
		newer: []string{"1.1.0"},
	}
	group := []candidateOutcome{
		{task: candidateTask{dep: dep, version: "1.0.0", current: true}, err: errors.New("no matching version found")},
		{task: candidateTask{dep: dep, version: "1.1.0", key: true}},
	}
	dr := DependencyResult{Name: dep.Name, Current: dep.Version}
	policy := rank.Policy{Now: time.Now(), TargetNode: "22.17.1"}

	r.rankDependency(&dr, d, group, rank.Index{}, policy)

	if dr.Best != "" {
		t.Errorf("Best = %q, want empty: the current version never resolved, so nothing is a valid comparison", dr.Best)
	}
	if dr.Vector != (Vector{}) {
		t.Errorf("Vector = %v, want the zero value: it must never be read as a real, clean count", dr.Vector)
	}
	if len(r.result.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want exactly one warning", r.result.Warnings)
	}
	if !strings.Contains(r.result.Warnings[0], "foo") || !strings.Contains(r.result.Warnings[0], "does not resolve") {
		t.Errorf("warning %q does not name the dependency and its failure", r.result.Warnings[0])
	}
}

// TestRankDependency_CVEsListTheVulnerabilitiesBehindTheVector proves dr's
// cves, on the current version and on each candidate, list the same
// vulnerabilities the vector counts: express@4.17.1's two known CVEs, and
// none for the clean 4.21.2 candidate rank/testdata's own real Trivy
// report carries.
func TestRankDependency_CVEsListTheVulnerabilitiesBehindTheVector(t *testing.T) {
	data, err := os.ReadFile("../../rank/testdata/trivy-report.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	findings, err := rank.ReadTrivyJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("ReadTrivyJSON: %v", err)
	}
	combinedIndex := rank.NewIndex(findings)

	r := &run{
		a:      &Analysis{Settings: store.Settings{Target: store.Target{Node: "22.17.1"}}},
		ctx:    context.Background(),
		emit:   func(Event) {},
		result: &Result{},
	}
	dep := npm.Dependency{Name: "express", Version: "4.17.1"}
	d := depInfo{
		dep: dep,
		packument: npm.Packument{Name: "express", Versions: map[string]npm.VersionMeta{
			"4.17.1": {Version: "4.17.1"},
			"4.21.2": {Version: "4.21.2"},
		}},
		newer: []string{"4.21.2"},
	}
	group := []candidateOutcome{
		{task: candidateTask{dep: dep, version: "4.17.1", current: true}, pkgs: []npm.LockPackage{{Name: "express", Version: "4.17.1"}}},
		{task: candidateTask{dep: dep, version: "4.21.2", key: true}, pkgs: []npm.LockPackage{{Name: "express", Version: "4.21.2"}}},
	}
	dr := DependencyResult{Name: dep.Name, Current: dep.Version}
	policy := rank.Policy{Now: time.Now(), TargetNode: "22.17.1"}

	r.rankDependency(&dr, d, group, combinedIndex, policy)

	wantIDs := []string{"CVE-2024-29041", "CVE-2024-43796"}
	if len(dr.CVEs) != len(wantIDs) {
		t.Fatalf("dr.CVEs = %+v, want %d entries", dr.CVEs, len(wantIDs))
	}
	for i, want := range wantIDs {
		if dr.CVEs[i].ID != want {
			t.Errorf("dr.CVEs[%d].ID = %q, want %q", i, dr.CVEs[i].ID, want)
		}
	}
	if len(dr.Candidates) != 1 || dr.Candidates[0].Version != "4.21.2" {
		t.Fatalf("dr.Candidates = %+v, want exactly the 4.21.2 candidate", dr.Candidates)
	}
	if len(dr.Candidates[0].CVEs) != 0 {
		t.Errorf("4.21.2 candidate's CVEs = %+v, want none", dr.Candidates[0].CVEs)
	}
}
