package npm

import (
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
	holders, err := LockHolders(strings.NewReader(graphLock))
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
	holders, err := LockHolders(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders["@babel/core@7.26.9"]) == 0 {
		t.Error("the fixture's direct @babel/core has no holder")
	}
}

func TestLockHoldersRefusesAnotherVersion(t *testing.T) {
	if _, err := LockHolders(strings.NewReader("lockfileVersion: '6.0'\n")); err == nil {
		t.Error("LockHolders accepted lockfile 6.0")
	}
}
