package jobs

import (
	"testing"

	"github.com/MorganKryze/sealift/npm"
)

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
// semaphore (spec section 4, "Candidate resolution": key candidates first).
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
