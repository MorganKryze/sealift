package npm

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

const graphLock = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express:
        specifier: 4.17.1
        version: 4.17.1
      react:
        specifier: 18.3.1
        version: 18.3.1(scheduler@0.23.2)
    devDependencies:
      aliased:
        specifier: npm:other@1.0.0
        version: other@1.0.0
packages:
  express@4.17.1:
    resolution: {integrity: sha512-a}
snapshots:
  express@4.17.1:
    dependencies:
      qs: 6.0.0
      body-parser: 1.0.0
  body-parser@1.0.0:
    dependencies:
      qs: 6.0.0
  qs@6.0.0: {}
  react@18.3.1(scheduler@0.23.2):
    dependencies:
      loose-envify: 1.4.0
      shared: 2.0.0(react@18.3.1)
  shared@2.0.0(react@18.3.1):
    optionalDependencies:
      qs: 6.0.0
  loose-envify@1.4.0: {}
  other@1.0.0:
    dependencies:
      deep: 3.0.0
  deep@3.0.0: {}
`

func TestLockHoldersWalksEachDirectDependencysTree(t *testing.T) {
	holders, err := LockHolders(strings.NewReader(graphLock), []string{"qs@6.0.0", "body-parser@1.0.0", "loose-envify@1.4.0", "express@4.17.1", "deep@3.0.0", "missing@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string][]string{
		"qs@6.0.0":           {"express", "react"},
		"body-parser@1.0.0":  {"express"},
		"loose-envify@1.4.0": {"react"},
		"express@4.17.1":     {"express"},
		"deep@3.0.0":         {"aliased"},
	} {
		if got := holders[key]; !slices.Equal(got, want) {
			t.Errorf("holders[%s] = %q, want %q", key, got, want)
		}
	}
	if got := holders["missing@1.0.0"]; got != nil {
		t.Errorf("holders of a package outside the lockfile = %q", got)
	}
}

func TestLockHoldersReadsTheFixture(t *testing.T) {
	f, err := os.Open("testdata/pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	holders, err := LockHolders(f, []string{"@babel/core@7.26.9"})
	if err != nil {
		t.Fatal(err)
	}
	if len(holders["@babel/core@7.26.9"]) == 0 {
		t.Error("the fixture's direct @babel/core has no holder")
	}
}

func TestLockHoldersRefusesAnotherVersion(t *testing.T) {
	if _, err := LockHolders(strings.NewReader("lockfileVersion: '6.0'\n"), []string{"qs@6.0.0"}); err == nil {
		t.Error("LockHolders accepted lockfile 6.0")
	}
}

// fanInLock is a lockfile whose directs all depend on one hub that holds
// leaves other packages: a forward walk per direct costs directs times nodes.
func fanInLock(directs, leaves int) string {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n")
	for i := range directs {
		fmt.Fprintf(&b, "      d%d:\n        specifier: 1.0.0\n        version: 1.0.0\n", i)
	}
	b.WriteString("snapshots:\n")
	for i := range directs {
		fmt.Fprintf(&b, "  d%d@1.0.0:\n    dependencies:\n      hub: 1.0.0\n", i)
	}
	b.WriteString("  hub@1.0.0:\n    dependencies:\n")
	for i := range leaves {
		fmt.Fprintf(&b, "      l%d: 1.0.0\n", i)
	}
	for i := range leaves {
		fmt.Fprintf(&b, "  l%d@1.0.0: {}\n", i)
	}
	return b.String()
}

func TestLockHoldersWalksBackFromTheAskedKeysOnly(t *testing.T) {
	lock := fanInLock(1000, 19000)
	// A forward walk per direct would visit 20 million packages; walking
	// back from l7 visits l7, the hub and the 1,000 directs. Parsing the
	// YAML dominates the time, so the visit cap is the bound checked.
	saved := maxLockVisits
	maxLockVisits = 25000
	defer func() { maxLockVisits = saved }()
	holders, err := LockHolders(strings.NewReader(lock), []string{"l7@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(holders["l7@1.0.0"]); got != 1000 {
		t.Errorf("l7 has %d holders, want 1000", got)
	}
	if got := holders["l8@1.0.0"]; got != nil {
		t.Errorf("a package nobody asked about has holders %q", got)
	}
}

func TestLockHoldersRefusesPastTheVisitCap(t *testing.T) {
	saved := maxLockVisits
	maxLockVisits = 100
	defer func() { maxLockVisits = saved }()
	_, err := LockHolders(strings.NewReader(fanInLock(200, 10)), []string{"l1@1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "visits") {
		t.Errorf("LockHolders past its cap = %v, want a refusal naming the visits", err)
	}
}

// Walking back from l0 in fanInLock(3, 2) visits l0, the hub and the three
// directs: five visits fit a cap of five, not one of four.
func TestLockHoldersAllowsAWalkOfExactlyTheCap(t *testing.T) {
	saved := maxLockVisits
	defer func() { maxLockVisits = saved }()
	maxLockVisits = 5
	if _, err := LockHolders(strings.NewReader(fanInLock(3, 2)), []string{"l0@1.0.0"}); err != nil {
		t.Errorf("a walk of exactly the cap = %v, want it allowed", err)
	}
	maxLockVisits = 4
	if _, err := LockHolders(strings.NewReader(fanInLock(3, 2)), []string{"l0@1.0.0"}); !errors.Is(err, ErrLockTooLarge) {
		t.Errorf("a walk one past the cap = %v, want ErrLockTooLarge", err)
	}
}

// Two keys of five visits each fit a per-key cap of nine, but the cap
// counts the whole call.
func TestLockHoldersSumsTheCapOverEveryKey(t *testing.T) {
	saved := maxLockVisits
	defer func() { maxLockVisits = saved }()
	maxLockVisits = 9
	if _, err := LockHolders(strings.NewReader(fanInLock(3, 2)), []string{"l0@1.0.0", "l1@1.0.0"}); !errors.Is(err, ErrLockTooLarge) {
		t.Errorf("two keys of five visits under a cap of nine = %v, want ErrLockTooLarge", err)
	}
}

func TestLockHoldersCountsEveryAliasOfOnePackage(t *testing.T) {
	lock := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      first:
        specifier: npm:other@1.0.0
        version: other@1.0.0
      second:
        specifier: npm:other@1.0.0
        version: other@1.0.0
snapshots:
  other@1.0.0:
    dependencies:
      deep: 3.0.0
  deep@3.0.0: {}
`
	holders, err := LockHolders(strings.NewReader(lock), []string{"deep@3.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := holders["deep@3.0.0"], []string{"first", "second"}; !slices.Equal(got, want) {
		t.Errorf("deep's holders = %q, want %q", got, want)
	}
}
