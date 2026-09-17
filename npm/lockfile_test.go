package npm

import (
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
