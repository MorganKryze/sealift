package imports

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testSecond = "20261106T101500Z"

// openStoreInOneSecond opens a store whose clock never leaves testSecond.
func openStoreInOneSecond(t *testing.T, root string) *Store {
	t.Helper()
	s, _ := openStore(t, root)
	s.now = func() time.Time { return time.Date(2026, 11, 6, 10, 15, 0, 500_000_000, time.UTC) }
	return s
}

func createFor(t *testing.T, s *Store, user string) Import {
	t.Helper()
	imp, err := s.Create(user, testArchiveObject, testManifestObject, &testSignatureObject, "")
	if err != nil {
		t.Fatal(err)
	}
	return imp
}

func TestCreateInOneSecondListsInCreationOrder(t *testing.T) {
	s := openStoreInOneSecond(t, testRoot(t))
	var created []string
	for range 5 {
		created = append(created, createFor(t, s, "alice").ID)
	}
	want := []string{testSecond + "-00000000", testSecond + "-00000001", testSecond + "-00000002", testSecond + "-00000003", testSecond + "-00000004"}
	if strings.Join(created, " ") != strings.Join(want, " ") {
		t.Fatalf("ids %v, want %v", created, want)
	}
	list, err := s.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, imp := range list {
		listed = append(listed, imp.ID)
	}
	slices.Reverse(want)
	if strings.Join(listed, " ") != strings.Join(want, " ") {
		t.Errorf("list %v, want newest first %v", listed, want)
	}
}

func TestCreateCountsPastARandomSuffixOfItsSecond(t *testing.T) {
	root := testRoot(t)
	s := openStoreInOneSecond(t, root)
	old := testSecond + "-9c3e41a7"
	plantFixture(t, root, "alice", func(m map[string]any) {
		m["id"] = old
		m["createdAt"] = "2026-11-06T10:15:00Z"
	})
	imp := createFor(t, s, "alice")
	if imp.ID != testSecond+"-9c3e41a8" {
		t.Fatalf("id %s, want one past %s", imp.ID, old)
	}
	list, err := s.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != imp.ID || list[1].ID != old {
		t.Errorf("list %v, want the new import first", list)
	}
}

func TestCreateCountsEachUserApart(t *testing.T) {
	s := openStoreInOneSecond(t, testRoot(t))
	createFor(t, s, "alice")
	createFor(t, s, "alice")
	if got := createFor(t, s, "bob").ID; got != testSecond+"-00000000" {
		t.Errorf("bob's first id %s, want suffix 00000000", got)
	}
}

func TestCreateNeverHandsAnIDOutTwice(t *testing.T) {
	root := testRoot(t)
	s := openStoreInOneSecond(t, root)
	createFor(t, s, "alice")
	gone := createFor(t, s, "alice")
	if err := os.RemoveAll(filepath.Join(root, "alice", gone.ID)); err != nil {
		t.Fatal(err)
	}
	if got := createFor(t, s, "alice").ID; got != testSecond+"-00000002" {
		t.Errorf("id %s after %s was removed, want suffix 00000002", got, gone.ID)
	}
}

func TestCreateRefusesPastTheLastSuffix(t *testing.T) {
	root := testRoot(t)
	s := openStoreInOneSecond(t, root)
	if err := os.MkdirAll(filepath.Join(root, "alice", testSecond+"-fffffffe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := createFor(t, s, "alice").ID; got != testSecond+"-ffffffff" {
		t.Fatalf("id %s, want the last suffix ffffffff", got)
	}
	if imp, err := s.Create("alice", testArchiveObject, testManifestObject, &testSignatureObject, ""); err == nil {
		t.Fatalf("Create past ffffffff gave %s, want an error", imp.ID)
	}
}

func TestCreateStartsAgainInTheNextSecond(t *testing.T) {
	s := openStoreInOneSecond(t, testRoot(t))
	createFor(t, s, "alice")
	createFor(t, s, "alice")
	s.now = func() time.Time { return time.Date(2026, 11, 6, 10, 15, 1, 0, time.UTC) }
	if got := createFor(t, s, "alice").ID; got != "20261106T101501Z-00000000" {
		t.Errorf("id %s, want the next second with suffix 00000000", got)
	}
}

func TestCreateIgnoresFoldersOfAnotherShape(t *testing.T) {
	root := testRoot(t)
	s := openStoreInOneSecond(t, root)
	for _, name := range []string{testSecond + "-zz", testSecond + "-fffffffff"} {
		if err := os.MkdirAll(filepath.Join(root, "alice", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got := createFor(t, s, "alice").ID; got != testSecond+"-00000000" {
		t.Errorf("id %s, want suffix 00000000 past folders that are no id", got)
	}
}
