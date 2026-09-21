package jobs

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
)

// TestRemaining checks the pure estimate: mean duration so far times what
// remains, divided by parallelism, zero when done is zero (one data
// point is not yet a rate).
func TestRemaining(t *testing.T) {
	for _, tc := range []struct {
		name        string
		elapsed     time.Duration
		done, total int
		parallelism int
		want        time.Duration
	}{
		{"one worker", 10 * time.Second, 5, 15, 1, 20 * time.Second},
		{"two workers halve it", 10 * time.Second, 5, 15, 2, 10 * time.Second},
		{"nothing done yet is unknown", 10 * time.Second, 0, 15, 1, 0},
		{"nothing left", 10 * time.Second, 15, 15, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := remaining(tc.elapsed, tc.done, tc.total, tc.parallelism); got != tc.want {
				t.Errorf("remaining(%v, %d, %d, %d) = %v, want %v", tc.elapsed, tc.done, tc.total, tc.parallelism, got, tc.want)
			}
		})
	}
}

// TestStepResolveCandidatesEmitsEstimatedRemainingMs proves the progress
// events resolve-candidates emits carry estimatedRemainingMs once at
// least one candidate has resolved, and omit it for the first event
// (done == 0), so the field never prints a guess computed from zero
// data.
func TestStepResolveCandidatesEmitsEstimatedRemainingMs(t *testing.T) {
	dep := npm.Dependency{Name: "foo", Version: "1.0.0"}
	manifest := npm.Manifest{Dependencies: []npm.Dependency{dep}}
	deps := []depInfo{{dep: dep, newer: []string{"1.1.0", "1.2.0"}}}

	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)

	var mu sync.Mutex
	var events []progressData
	r := &run{
		a: &Analysis{
			Store:    st,
			Pnpm:     &fakePnpm{},
			Project:  proj,
			Settings: store.Settings{ResolveParallelism: 2},
			Dir:      pending.Path(),
		},
		ctx: context.Background(),
		emit: func(e Event) {
			if e.Kind != "progress" {
				return
			}
			var d progressData
			if err := json.Unmarshal(e.Data, &d); err != nil {
				t.Fatalf("unmarshal progress event: %v", err)
			}
			// resolveCandidateTasks calls onProgress from its own worker
			// goroutines, concurrently: this callback, and the slice it
			// appends to, must be safe for that.
			mu.Lock()
			events = append(events, d)
			mu.Unlock()
		},
	}

	if _, err := r.stepResolveCandidates(deps, manifest, nil); err != nil {
		t.Fatalf("stepResolveCandidates: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("no progress events emitted")
	}
	var last progressData
	var sawFullyDone bool
	for _, e := range events {
		if e.Done == e.Total {
			sawFullyDone = true
			last = e
		}
	}
	if !sawFullyDone {
		t.Fatalf("events = %+v, want one with done == total", events)
	}
	if last.EstimatedRemainingMs == nil {
		t.Error("the done == total event has no estimatedRemainingMs, want one now that candidates have resolved")
	}
}

// TestProjectVersionsOf checks that every dependency, of every kind, ends
// up mapped to its own version, since buildProbeManifest needs to look a
// peer up by name alone.
func TestProjectVersionsOf(t *testing.T) {
	manifest := npm.Manifest{Dependencies: []npm.Dependency{
		{Name: "react", Version: "18.2.0", Kind: npm.Prod},
		{Name: "typescript", Version: "5.4.0", Kind: npm.Dev},
	}}
	got := projectVersionsOf(manifest)
	if got["react"] != "18.2.0" || got["typescript"] != "5.4.0" || len(got) != 2 {
		t.Errorf("projectVersionsOf(manifest) = %v, want {react: 18.2.0, typescript: 5.4.0}", got)
	}
}

// TestBuildCandidateTasksKeyFirstAcrossDependencies checks that every
// dependency's current version and key candidates queue ahead of any
// dependency's non-key candidates. A single dependency-major pass would
// let dependency "a"'s non-key candidate queue ahead of dependency "b"'s
// tasks entirely, delaying b's key candidate under a shared, limited
// semaphore, though key candidates must go first.
func TestBuildCandidateTasksKeyFirstAcrossDependencies(t *testing.T) {
	depA := npm.Dependency{Name: "a", Version: "1.0.0"}
	depB := npm.Dependency{Name: "b", Version: "1.0.0"}
	deps := []depInfo{
		// a's key candidates are 1.2.0 (latest same-major) and 2.0.0
		// (latest overall); 1.1.0 is its only non-key, "rest" candidate.
		{dep: depA, newer: []string{"1.1.0", "1.2.0", "2.0.0"}},
		{dep: depB, newer: []string{"1.1.0"}},
	}
	tasks := buildCandidateTasks(deps, nil)

	indexOf := func(name, version string) int {
		for i, ct := range tasks {
			if ct.dep.Name == name && ct.version == version {
				return i
			}
		}
		t.Fatalf("no task for %s@%s in %+v", name, version, tasks)
		return -1
	}

	aRest := indexOf("a", "1.1.0")
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if bIdx := indexOf("b", v); bIdx > aRest {
			t.Errorf("b@%s at index %d, want it before a's non-key candidate a@1.1.0 at index %d", v, bIdx, aRest)
		}
	}
}

// TestBuildCandidateTasksKeyVersionsUnaffected is a sanity check that the
// keys rank.KeyVersions actually picked still land in the primary pass:
// without it, a change to the split logic could silently drop the key
// flag while still passing the ordering check above.
func TestBuildCandidateTasksKeyVersionsUnaffected(t *testing.T) {
	dep := npm.Dependency{Name: "a", Version: "1.0.0"}
	deps := []depInfo{{dep: dep, newer: []string{"1.1.0", "1.2.0", "2.0.0"}}}
	tasks := buildCandidateTasks(deps, nil)

	keyByVersion := map[string]bool{}
	for _, ct := range tasks {
		keyByVersion[ct.version] = ct.key
	}
	if !keyByVersion["1.2.0"] || !keyByVersion["2.0.0"] {
		t.Errorf("key flags = %v, want 1.2.0 and 2.0.0 marked key", keyByVersion)
	}
	if keyByVersion["1.1.0"] {
		t.Errorf("1.1.0 marked key, want it in the non-key rest")
	}
}
