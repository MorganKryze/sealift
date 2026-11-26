package npm

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/pnpm-lock.yaml: pnpm 10.34.5 resolution of 50 popular packages
// pinned to their newest release before 2025-03-01.
func loadFixtureLockfile(t *testing.T) []LockPackage {
	t.Helper()
	f, err := os.Open("testdata/pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pkgs, err := ParseLockfile(f)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestParseLockfileFixture(t *testing.T) {
	pkgs := loadFixtureLockfile(t)
	if len(pkgs) != 840 {
		t.Fatalf("got %d packages, want 840", len(pkgs))
	}
	byKey := map[string]LockPackage{}
	for _, p := range pkgs {
		byKey[p.Key()] = p
	}

	express, ok := byKey["express@4.21.2"]
	if !ok {
		t.Fatal("express@4.21.2 missing")
	}
	if !strings.HasPrefix(express.Integrity, "sha512-28HqgMZAmih1") {
		t.Errorf("express integrity = %q", express.Integrity)
	}
	if express.Engines["node"] != ">= 0.10.0" {
		t.Errorf("express engines.node = %q", express.Engines["node"])
	}

	musl := byKey["@img/sharp-linuxmusl-x64@0.33.5"]
	if !slices.Equal(musl.OS, []string{"linux"}) || !slices.Equal(musl.CPU, []string{"x64"}) || !slices.Equal(musl.Libc, []string{"musl"}) {
		t.Errorf("sharp-linuxmusl-x64 platform = %v %v %v", musl.OS, musl.CPU, musl.Libc)
	}

	sorted := slices.IsSortedFunc(pkgs, func(a, b LockPackage) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	if !sorted {
		t.Error("packages are not sorted by name, then version")
	}
}

func TestParseLockfileRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"old format":   "lockfileVersion: '6.0'\npackages: {}\n",
		"no integrity": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {tarball: https://example.com/left-pad.tgz}\n",
		"bad key":      "lockfileVersion: '9.0'\npackages:\n  left-pad:\n    resolution: {integrity: sha512-AA==}\n",
		"not yaml":     "lockfileVersion: [",
	} {
		if _, err := ParseLockfile(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: ParseLockfile returned no error", name)
		}
	}
}

func TestParseLockfileRejectsUnsafeKey(t *testing.T) {
	for _, key := range []string{
		"a@1.0.0/../../x",
		"a@../../x",
		"a@1.0.0/x",
		"../a@1.0.0",
		"@s/../a@1.0.0",
		"a/b@1.0.0",
		"a@^1.0.0",
		"a@https://example.com/a.tgz",
	} {
		doc := "lockfileVersion: '9.0'\npackages:\n  '" + key + "':\n    resolution: {integrity: sha512-AA==}\n"
		_, err := ParseLockfile(strings.NewReader(doc))
		if err == nil {
			t.Errorf("%s: ParseLockfile returned no error", key)
		} else if !strings.Contains(err.Error(), key) {
			t.Errorf("%s: error %q does not name the key", key, err)
		}
	}
}

// pnpm 10 and 11 install a version whose engines hold an object or a list
// and write it into the lockfile; the lockfile must still parse, and its
// engines read as a packument's do.
func TestParseLockfileReadsEnginesThatAreNotStrings(t *testing.T) {
	cases := []struct {
		name, engines string
		want          map[string]string
	}{
		{"string", `{node: '>=18'}`, map[string]string{"node": ">=18"}},
		{"node is a map", `{node: {x: 1}}`, map[string]string{"node": `not a string: {"x":1}`}},
		{"node is a list", `{node: ['>=18']}`, map[string]string{"node": `not a string: [">=18"]`}},
		{"node is an empty list", `{node: []}`, map[string]string{"node": "not a string: []"}},
		{"node is a number", `{node: 18}`, map[string]string{"node": "not a string: 18"}},
		{"node is null", `{node: null}`, map[string]string{"node": ""}},
		{"another engine is a map", `{node: '>=18', npm: {min: 9}}`, map[string]string{"node": ">=18"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n    engines: " + c.engines + "\n"
			pkgs, err := ParseLockfile(strings.NewReader(doc))
			if err != nil {
				t.Fatal(err)
			}
			if got := pkgs[0].Engines; !maps.Equal(got, c.want) {
				t.Errorf("engines = %q, want %q", got, c.want)
			}
		})
	}
}

// An engines value reached through an alias is read once and counted by the
// document's decoder, so a lockfile of aliases cannot multiply the work.
func TestParseLockfileReadsAnAliasedEngines(t *testing.T) {
	doc := "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n    engines: &e {node: {x: 1}}\n  b@1.0.0:\n    resolution: {integrity: sha512-y}\n    engines: *e\n"
	pkgs, err := ParseLockfile(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Engines["node"] != `not a string: {"x":1}` {
			t.Errorf("%s engines.node = %q", p.Name, p.Engines["node"])
		}
	}
}

func TestParseLockfileRefusesAnAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\nx0: &a0 [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]\n")
	for i := 1; i < 9; i++ {
		fmt.Fprintf(&b, "x%d: &a%d [*a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d, *a%[3]d]\n", i, i, i-1)
	}
	b.WriteString("packages:\n")
	for i := range 50 {
		fmt.Fprintf(&b, "  p%d@1.0.0:\n    resolution: {integrity: sha512-x}\n    engines: {node: *a8}\n", i)
	}
	_, err := ParseLockfile(strings.NewReader(b.String()))
	if err == nil || !strings.Contains(err.Error(), "excessive aliasing") {
		t.Fatalf("a lockfile of nested aliases: err = %v, want excessive aliasing", err)
	}
}
