package jobs

import (
	"context"
	"errors"
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
