package imports

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/importer"
)

// testRoot joins a glob character into the path, so a store that globbed its
// directories would miss them.
func testRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "data[1]", "imports")
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func openStore(t *testing.T, root string) (*Store, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	s, err := Open(root, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 6, 10, 15, 0, 0, time.UTC)
	s.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	return s, logs
}

var (
	testArchiveObject  = Object{Key: "packages/npm/a/packages_npm.tar.gz", ETag: `"abc123"`, Size: 123456}
	testManifestObject = Object{Key: "packages/npm/a/manifest.json", ETag: `"def456"`}
)

func pendingResults() []importer.Result {
	return []importer.Result{
		{Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz", State: importer.Pending},
		{Name: "zeta", Version: "2.0.0", File: "zeta-2.0.0.tgz", State: importer.Pending},
	}
}

func listedReport() importer.Report { return importer.Report{Packages: pendingResults()} }

func TestValidUser(t *testing.T) {
	for name, tc := range map[string]struct {
		user string
		ok   bool
	}{
		"letters":            {"alice", true},
		"one character":      {"a", true},
		"digits first":       {"0day", true},
		"dot and hyphen":     {"a.b-c", true},
		"58 characters":      {strings.Repeat("a", 58), true},
		"59 characters":      {strings.Repeat("a", 59), false},
		"empty":              {"", false},
		"upper case":         {"Alice", false},
		"leading dot":        {".alice", false},
		"trailing hyphen":    {"alice-", false},
		"double dot":         {"a..b", false},
		"slash":              {"a/b", false},
		"backslash":          {`a\b`, false},
		"parent":             {"..", false},
		"underscore":         {"a_b", false},
		"space":              {"a b", false},
		"newline at the end": {"alice\n", false},
		"non ASCII":          {"alicé", false},
		"glob":               {"a*", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ValidUser(tc.user); got != tc.ok {
				t.Errorf("ValidUser(%q) = %v, want %v", tc.user, got, tc.ok)
			}
		})
	}
}

func TestValidID(t *testing.T) {
	for name, tc := range map[string]struct {
		id string
		ok bool
	}{
		"well formed":    {"20261106T101500Z-3f9a0c1d", true},
		"empty":          {"", false},
		"upper hex":      {"20261106T101500Z-3F9A0C1D", false},
		"short hex":      {"20261106T101500Z-3f9a0c1", false},
		"long hex":       {"20261106T101500Z-3f9a0c1d0", false},
		"no time":        {"3f9a0c1d", false},
		"path":           {"../20261106T101500Z-3f9a0c1d", false},
		"trailing slash": {"20261106T101500Z-3f9a0c1d/", false},
		"newline":        {"20261106T101500Z-3f9a0c1d\n", false},
		"glob":           {"20261106T101500Z-*", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ValidID(tc.id); got != tc.ok {
				t.Errorf("ValidID(%q) = %v, want %v", tc.id, got, tc.ok)
			}
		})
	}
}

func TestStoreRoundTrip(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp, err := s.Create("alice", testArchiveObject, testManifestObject, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(imp.ID) || imp.User != "alice" || imp.FormatVersion != FormatVersion {
		t.Fatalf("created %+v", imp)
	}
	if len(imp.Attempts) != 1 || imp.Attempts[0].N != 1 || imp.Attempts[0].Status != "queued" || imp.Attempts[0].QueuedAt == nil {
		t.Fatalf("attempts %+v", imp.Attempts)
	}
	if imp.Outcome() != "queued" {
		t.Errorf("outcome %q, want queued", imp.Outcome())
	}

	dir, _, err := s.Begin("alice", imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(root, "alice", imp.ID, "work-1")
	if dir != wantDir {
		t.Errorf("work directory %q, want %q", dir, wantDir)
	}
	assertMode(t, dir, 0o700)
	got, err := s.Get("alice", imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome() != "running" || got.Attempts[0].StartedAt == nil {
		t.Errorf("running attempt %+v", got.Attempts[0])
	}

	if err := s.Listed("alice", imp.ID, 1, listedReport()); err != nil {
		t.Fatal(err)
	}
	ended := pendingResults()[0]
	ended.State = importer.Published
	if err := s.Ended("alice", imp.ID, 1, 0, ended); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get("alice", imp.ID)
	pkgs := got.Attempts[0].Report.Packages
	if len(pkgs) != 2 || pkgs[0].State != importer.Published || pkgs[1].State != importer.Pending {
		t.Fatalf("packages %+v", pkgs)
	}
	if got.Attempts[0].Report.Counts.Published != 1 || got.Attempts[0].Report.Counts.Failed != 0 {
		t.Errorf("counts %+v", got.Attempts[0].Report.Counts)
	}

	rep := importer.Report{Outcome: importer.OutcomeIncomplete, ImportVersion: "0.3.0", Packages: []importer.Result{
		{Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz", State: importer.Published},
		{Name: "zeta", Version: "2.0.0", File: "zeta-2.0.0.tgz", State: importer.Failed, Reason: "upload failed"},
	}, Counts: importer.Counts{Published: 1, Failed: 1}}
	if err := s.Finish("alice", imp.ID, 1, rep, &Removal{Removed: true}); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get("alice", imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := got.Attempts[0]
	if a.Status != "ended" || a.Outcome != importer.OutcomeIncomplete || a.EndedAt == nil || a.Removal == nil || !a.Removal.Removed {
		t.Errorf("ended attempt %+v", a)
	}
	if got.Outcome() != importer.OutcomeIncomplete || !got.ArchiveRemoved() {
		t.Errorf("outcome %q, archive removed %v", got.Outcome(), got.ArchiveRemoved())
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("work directory after Finish: %v", err)
	}

	assertMode(t, filepath.Join(root, "alice"), 0o700)
	assertMode(t, filepath.Join(root, "alice", imp.ID), 0o700)
	assertMode(t, filepath.Join(root, "alice", imp.ID, "import.json"), 0o600)

	list, err := s.List("alice")
	if err != nil || len(list) != 1 || list[0].ID != imp.ID {
		t.Fatalf("List: %+v, %v", list, err)
	}
}

func TestSlicesAreNeverWrittenNull(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp, err := s.Create("alice", testArchiveObject, testManifestObject, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "alice", imp.ID, "import.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("null")) {
		t.Errorf("queued record holds null:\n%s", b)
	}
	if err := s.Listed("alice", imp.ID, 1, importer.Report{}); err == nil {
		// A listing of no package is stored as an empty list.
		b, _ = os.ReadFile(filepath.Join(root, "alice", imp.ID, "import.json"))
		if bytes.Contains(b, []byte("null")) {
			t.Errorf("record after an empty listing holds null:\n%s", b)
		}
	}
	var doc struct {
		FormatVersion int `json:"formatVersion"`
		Attempts      []struct {
			Report struct {
				Packages []json.RawMessage `json:"packages"`
			} `json:"report"`
		} `json:"attempts"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.FormatVersion != 1 || len(doc.Attempts) != 1 || doc.Attempts[0].Report.Packages == nil {
		t.Errorf("record %s, %v", b, err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %o, want %o", path, got, want)
	}
}

// plantFixture copies testdata/import-v1.json into the store, after applying
// edit to its decoded form.
func plantFixture(t *testing.T, root, user string, edit func(m map[string]any)) string {
	t.Helper()
	return plantFile(t, "import-v1.json", root, user, edit)
}

// plantFile is plantFixture for any file of testdata.
func plantFile(t *testing.T, name, root, user string, edit func(m map[string]any)) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["user"] = user
	if edit != nil {
		edit(m)
	}
	b, _ = json.Marshal(m)
	dir := filepath.Join(root, user, m["id"].(string))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "import.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestStoreReadsV1Fixture(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	plantFixture(t, root, "alice", nil)
	got, err := s.Get("alice", "20261106T101500Z-3f9a0c1d")
	if err != nil {
		t.Fatal(err)
	}
	a := got.Attempts[0]
	if got.FormatVersion != 1 || got.User != "alice" || !got.CreatedAt.Equal(time.Date(2026, 11, 6, 10, 15, 0, 0, time.UTC)) ||
		got.Archive != (Object{Key: "packages/npm/a/packages_npm.tar.gz", ETag: `"abc123"`, Size: 123456}) ||
		got.Manifest != (Object{Key: "packages/npm/a/manifest.json", ETag: `"def456"`, Size: 2048}) ||
		!strings.HasPrefix(got.ExpectedSHA256, "0a0b0c0d") {
		t.Errorf("import %+v", got)
	}
	if a.N != 1 || a.Status != "ended" || a.QueuedAt == nil || a.StartedAt == nil || a.EndedAt == nil || a.Outcome != "incomplete" ||
		a.Removal == nil || !a.Removal.Removed {
		t.Errorf("attempt %+v", a)
	}
	rep := a.Report
	if rep.Outcome != "incomplete" || !rep.Unencrypted || rep.ImportVersion != "0.3.0" || rep.Archive.File != "packages_npm.tar.gz" ||
		rep.Target.PnpmVer != "10.34.5" || rep.Nexus.Repository != "npm-hosted" || rep.Counts.Published != 1 || rep.Counts.Failed != 1 ||
		len(rep.Packages) != 2 || rep.Packages[1].Reason != "upload failed: nexus answered 500" {
		t.Errorf("report %+v", rep)
	}
	if got.Outcome() != "incomplete" || !got.ArchiveRemoved() {
		t.Errorf("outcome %q, removed %v", got.Outcome(), got.ArchiveRemoved())
	}

	// A record from before a field existed still reads.
	root2 := testRoot(t)
	s2, _ := openStore(t, root2)
	plantFixture(t, root2, "alice", func(m map[string]any) {
		delete(m, "expectedSha256")
		att := m["attempts"].([]any)[0].(map[string]any)
		delete(att, "removal")
		delete(att, "report")
	})
	old, err := s2.Get("alice", "20261106T101500Z-3f9a0c1d")
	if err != nil {
		t.Fatal(err)
	}
	if old.ExpectedSHA256 != "" || old.Attempts[0].Removal != nil || old.ArchiveRemoved() || old.Attempts[0].Report.Packages == nil || old.Outcome() != "incomplete" {
		t.Errorf("old record %+v", old)
	}
}

func TestImportOfAnotherUser(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp, err := s.Create("alice", testArchiveObject, testManifestObject, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("bob", imp.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get by another user: %v, want ErrNotFound", err)
	}
	// The record sits in bob's folder but names alice.
	plantFixture(t, root, "bob", func(m map[string]any) { m["user"] = "alice" })
	if _, err := s.Get("bob", "20261106T101500Z-3f9a0c1d"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get of a record naming another user: %v, want ErrNotFound", err)
	}
	if list, _ := s.List("bob"); len(list) != 0 {
		t.Errorf("bob lists %+v", list)
	}
	for _, bad := range []struct{ user, id string }{
		{"alice", "../" + imp.ID}, {"../alice", imp.ID}, {"", imp.ID}, {"alice", ""}, {"alice", "missing"},
	} {
		if _, err := s.Get(bad.user, bad.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q, %q): %v, want ErrNotFound", bad.user, bad.id, err)
		}
	}
	if _, _, err := s.Begin("bob", imp.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Begin by another user: %v, want ErrNotFound", err)
	}
	if _, err := s.Create("../x", testArchiveObject, testManifestObject, ""); err == nil {
		t.Error("Create accepted a bad user")
	}
}

func TestEndedWritesEachPackage(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	if _, _, err := s.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Listed("alice", imp.ID, 1, listedReport()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "alice", imp.ID)
	onDisk := func() []importer.Result {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "import.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc Import
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Attempts[0].Report.Packages
	}
	for i, state := range []importer.State{importer.Published, importer.Failed} {
		r := pendingResults()[i]
		r.State = state
		if state == importer.Failed {
			r.Reason = "upload failed"
		}
		if err := s.Ended("alice", imp.ID, 1, i, r); err != nil {
			t.Fatal(err)
		}
		pkgs := onDisk()
		if pkgs[i].State != state || pkgs[i].Reason != r.Reason {
			t.Errorf("after Ended(%d) the file holds %+v", i, pkgs[i])
		}
		if i == 0 && pkgs[1].State != importer.Pending {
			t.Errorf("package 1 is %q before it ended", pkgs[1].State)
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".tmp") {
				t.Errorf("temporary file %s left behind", e.Name())
			}
		}
	}
	got, _ := s.Get("alice", imp.ID)
	if c := got.Attempts[0].Report.Counts; c.Published != 1 || c.Failed != 1 {
		t.Errorf("counts %+v", c)
	}
	if err := s.Ended("alice", imp.ID, 1, 5, importer.Result{}); err == nil {
		t.Error("Ended accepted an index past the list")
	}
}

func TestStateChangesAreChecked(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	if err := s.Listed("alice", imp.ID, 1, listedReport()); err == nil {
		t.Error("Listed on a queued attempt succeeded")
	}
	if _, _, err := s.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Begin("alice", imp.ID); err == nil {
		t.Error("Begin on a running attempt succeeded")
	}
	if err := s.Finish("alice", imp.ID, 1, importer.Report{Outcome: importer.OutcomeRefused}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish("alice", imp.ID, 1, importer.Report{Outcome: importer.OutcomeComplete}, nil); err == nil {
		t.Error("Finish on an ended attempt succeeded")
	}
	if err := s.Ended("alice", imp.ID, 1, 0, importer.Result{}); err == nil {
		t.Error("Ended on an ended attempt succeeded")
	}
	got, _ := s.Get("alice", imp.ID)
	if got.Outcome() != importer.OutcomeRefused {
		t.Errorf("outcome %q after a rejected second Finish", got.Outcome())
	}
}

func TestListSkipsDamaged(t *testing.T) {
	root := testRoot(t)
	s, logs := openStore(t, root)
	good, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	truncated := plantFixture(t, root, "alice", func(m map[string]any) { m["id"] = "20261106T090000Z-aaaaaaaa" })
	if err := os.WriteFile(filepath.Join(truncated, "import.json"), []byte(`{"formatVersion": 1, "id": "2026`), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := plantFixture(t, root, "alice", func(m map[string]any) { m["id"] = "20261106T080000Z-bbbbbbbb" })
	if os.Getuid() != 0 {
		if err := os.Chmod(unreadable, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
	}
	other := plantFixture(t, root, "alice", func(m map[string]any) { m["id"] = "20261106T070000Z-cccccccc"; m["formatVersion"] = 2 })
	_ = other

	list, err := s.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != good.ID {
		t.Fatalf("List served %+v, want only %s", list, good.ID)
	}
	for _, id := range []string{"20261106T090000Z-aaaaaaaa", "20261106T070000Z-cccccccc"} {
		if !strings.Contains(logs.String(), id) {
			t.Errorf("the log does not name %s:\n%s", id, logs.String())
		}
	}
	if _, err := s.Get("alice", "20261106T090000Z-aaaaaaaa"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get of a damaged record: %v, want an error other than ErrNotFound", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	for _, id := range []string{"20261106T090000Z-aaaaaaaa", "20261106T110000Z-bbbbbbbb", "20261106T100000Z-cccccccc"} {
		plantFixture(t, root, "alice", func(m map[string]any) {
			m["id"] = id
			m["createdAt"] = id[:4] + "-" + id[4:6] + "-" + id[6:8] + "T" + id[9:11] + ":00:00Z"
		})
	}
	list, err := s.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, i := range list {
		ids = append(ids, i.ID)
	}
	want := []string{"20261106T110000Z-bbbbbbbb", "20261106T100000Z-cccccccc", "20261106T090000Z-aaaaaaaa"}
	if strings.Join(ids, " ") != strings.Join(want, " ") {
		t.Errorf("order %v, want %v", ids, want)
	}
}

var _ io.Writer = (*logBuffer)(nil)

func TestStoreReadsV040Fixture(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	dir := plantFile(t, "import-v0.4.0-incomplete.json", root, "alice", nil)
	got, err := s.Get("alice", "20261106T110000Z-7c2e55aa")
	if err != nil {
		t.Fatal(err)
	}
	rep := got.Attempts[0].Report
	if rep.ArchiveChecked != nil {
		t.Errorf("archiveChecked = %v, want absent", *rep.ArchiveChecked)
	}
	if len(rep.Packages) != 4 || rep.Counts.Failed != 3 || got.Outcome() != importer.OutcomeIncomplete {
		t.Fatalf("report %+v", rep)
	}
	for _, p := range rep.Packages {
		if p.Kind != "" {
			t.Errorf("%s: kind %q, want absent", p.Name, p.Kind)
		}
	}

	// A write through the store keeps the record readable and holds no null.
	if err := s.Removed("alice", got.ID, 1, Removal{}); err == nil {
		t.Fatal("Removed accepted an incomplete attempt")
	}
	if _, err := s.Retry("alice", got.ID); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "import.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("null")) {
		t.Errorf("record rewritten from a v0.4.0 one holds null:\n%s", b)
	}
	if bytes.Contains(b, []byte(`"archiveChecked"`)) || bytes.Contains(b, []byte(`"kind"`)) {
		t.Errorf("the store invented a field on an old record:\n%s", b)
	}
	again, err := s.Get("alice", got.ID)
	if err != nil || len(again.Attempts) != 2 || again.Attempts[0].Report.Packages[1].Reason == "" {
		t.Errorf("record after the rewrite: %+v, %v", again, err)
	}
}

func TestStoreListedKeepsTheReport(t *testing.T) {
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	if _, _, err := s.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	unchecked := false
	rep := importer.Report{
		ImportVersion: "0.5.0", ArchiveChecked: &unchecked,
		Archive:  importer.ArchiveInfo{File: "packages_npm.tar.gz", SHA256: "ab", Size: 12},
		Target:   importer.TargetInfo{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
		Nexus:    importer.NexusInfo{URL: "http://nexus:8081", Repository: "npm-hosted"},
		Counts:   importer.Counts{Failed: 9},
		Packages: pendingResults(),
	}
	if err := s.Listed("alice", imp.ID, 1, rep); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("alice", imp.ID)
	stored := got.Attempts[0].Report
	if stored.Outcome != "" || stored.Reason != "" || stored.Target.OS != "linux" || stored.Archive.SHA256 != "ab" || stored.Nexus.Repository != "npm-hosted" || stored.ImportVersion != "0.5.0" {
		t.Errorf("stored report %+v", stored)
	}
	if stored.ArchiveChecked == nil || *stored.ArchiveChecked {
		t.Errorf("archiveChecked = %v, want false", stored.ArchiveChecked)
	}
	if len(stored.Packages) != 2 || stored.Counts != (importer.Counts{}) {
		t.Errorf("packages %+v, counts %+v: counts are recomputed from the packages", stored.Packages, stored.Counts)
	}
	if got.Outcome() != string(StatusRunning) {
		t.Errorf("outcome %q, want running", got.Outcome())
	}

	// A list of no package is stored as an empty list.
	other, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	if _, _, err := s.Begin("alice", other.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Listed("alice", other.ID, 1, importer.Report{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "alice", other.ID, "import.json"))
	if bytes.Contains(b, []byte("null")) {
		t.Errorf("record holds null:\n%s", b)
	}
}

func TestStoreChecked(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp, _ := s.Create("alice", testArchiveObject, testManifestObject, "")
	if err := s.Checked("alice", imp.ID, 1); err == nil {
		t.Error("Checked on a queued attempt succeeded")
	}
	if _, _, err := s.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	unchecked := false
	if err := s.Listed("alice", imp.ID, 1, importer.Report{ArchiveChecked: &unchecked, Packages: pendingResults()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Checked("alice", imp.ID, 2); err == nil {
		t.Error("Checked named an attempt that is not the latest")
	}
	got, _ := s.Get("alice", imp.ID)
	if c := got.Attempts[0].Report.ArchiveChecked; c == nil || *c {
		t.Errorf("archiveChecked = %v after a refused call, want false", c)
	}
	if err := s.Checked("alice", imp.ID, 1); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get("alice", imp.ID)
	if c := got.Attempts[0].Report.ArchiveChecked; c == nil || !*c {
		t.Errorf("archiveChecked = %v, want true", c)
	}
	if len(got.Attempts[0].Report.Packages) != 2 {
		t.Errorf("Checked changed the packages: %+v", got.Attempts[0].Report.Packages)
	}
	if err := s.Finish("alice", imp.ID, 1, importer.Report{Outcome: importer.OutcomeRefused}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Checked("alice", imp.ID, 1); err == nil {
		t.Error("Checked on an ended attempt succeeded")
	}
}
