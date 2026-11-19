package imports

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/MorganKryze/sealift/internal/importer"
)

func result(name string, state importer.State, kind importer.Kind) importer.Result {
	r := importer.Result{Name: name, Version: "1.0.0", File: "x.tgz", State: state, Kind: kind}
	if state == importer.Failed {
		r.Reason = "failed"
	}
	return r
}

var clock = regexp.MustCompile(`\d{4}-\d\d-\d\dT[0-9:.]+(Z|[+-]\d\d:\d\d)`)

// stamps replaces the times a store writes, which a test cannot predict.
func stamps(out []byte) string { return clock.ReplaceAllString(string(out), "<time>") }

func TestPublishedListReadsStoredRecords(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root := testRoot(t)
	s, _ := openStore(t, root)
	imp := newImport(t, s, "alice")
	const user = "alice"

	pending := func(names ...string) importer.Report {
		var rep importer.Report
		for _, n := range names {
			rep.Packages = append(rep.Packages, result(n, importer.Pending, ""))
		}
		return rep
	}
	if _, _, err := s.Begin(user, imp.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Listed(user, imp.ID, 1, pending("a", "b", "c", "d", "@scope/e")); err != nil {
		t.Fatal(err)
	}
	first := []importer.Result{
		result("a", importer.Published, ""),
		result("b", importer.Failed, importer.KindNexus),
		result("c", importer.Present, ""),
		result("d", importer.Failed, importer.KindConflict),
	}
	for i, r := range first {
		if err := s.Ended(user, imp.ID, 1, i, r); err != nil {
			t.Fatal(err)
		}
	}
	reopened, _ := openStore(t, root)
	if _, err := reopened.Sweep(); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Retry(user, imp.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.Begin(user, imp.ID); err != nil {
		t.Fatal(err)
	}
	second := importer.Report{Outcome: importer.OutcomeComplete, Packages: []importer.Result{
		result("a", importer.Present, ""),
		result("b", importer.Present, ""),
		result("c", importer.Present, ""),
		result("d", importer.Failed, importer.KindConflict),
		result("@scope/e", importer.Published, ""),
	}}
	if err := reopened.Finish(user, imp.ID, 2, second, nil); err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs("../../../charts/sealift/files/published.mjs")
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, user, imp.ID, recordFile)
	out, err := exec.Command(node, script, record).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	want := "Published by this import:\na@1.0.0\n@scope/e@1.0.0\n\n" +
		"Possibly published, check each in Nexus first:\nb@1.0.0\n" +
		"  attempt 1: state=failed kind=nexus reason=\"failed\" started=<time> ended=<time>\n" +
		"  attempt 2: state=present kind=- reason=- started=<time> ended=<time>\n\n" +
		"Never uploaded, nothing to remove:\nd@1.0.0\n" +
		"  attempt 1: state=failed kind=conflict reason=\"failed\" started=<time> ended=<time>\n" +
		"  attempt 2: state=failed kind=conflict reason=\"failed\" started=<time> ended=<time>\n"
	if got := stamps(out); got != want {
		t.Errorf("output:\n%q\nwant:\n%q", got, want)
	}

	t.Run("an interrupted package stays possible when a retry finds it present", func(t *testing.T) {
		imp := newImport(t, reopened, user)
		if _, _, err := reopened.Begin(user, imp.ID); err != nil {
			t.Fatal(err)
		}
		if err := reopened.Listed(user, imp.ID, 1, pending("g", "h")); err != nil {
			t.Fatal(err)
		}
		if err := reopened.Ended(user, imp.ID, 1, 0, result("g", importer.Failed, importer.KindInterrupted)); err != nil {
			t.Fatal(err)
		}
		again, _ := openStore(t, root)
		if _, err := again.Sweep(); err != nil {
			t.Fatal(err)
		}
		if _, err := again.Retry(user, imp.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := again.Begin(user, imp.ID); err != nil {
			t.Fatal(err)
		}
		rep := importer.Report{Outcome: importer.OutcomeComplete, Packages: []importer.Result{
			result("g", importer.Present, ""),
			result("h", importer.Present, ""),
		}}
		if err := again.Finish(user, imp.ID, 2, rep, nil); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, script, filepath.Join(root, user, imp.ID, recordFile)).Output()
		if err != nil {
			t.Fatalf("node: %v", err)
		}
		want := "Published by this import:\n\n" +
			"Possibly published, check each in Nexus first:\ng@1.0.0\n" +
			"  attempt 1: state=failed kind=interrupted reason=\"failed\" started=<time> ended=<time>\n" +
			"  attempt 2: state=present kind=- reason=- started=<time> ended=<time>\n" +
			"h@1.0.0\n" +
			"  attempt 1: state=failed kind=interrupted reason=\"interrupted\" started=<time> ended=<time>\n" +
			"  attempt 2: state=present kind=- reason=- started=<time> ended=<time>\n\n" +
			"Never uploaded, nothing to remove:\n"
		if got := stamps(out); got != want {
			t.Errorf("output:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("a package that may have reached Nexus is listed whatever its record", func(t *testing.T) {
		imp := newImport(t, reopened, user)
		if _, _, err := reopened.Begin(user, imp.ID); err != nil {
			t.Fatal(err)
		}
		if err := reopened.Listed(user, imp.ID, 1, pending("p", "l", "m", "s", "n")); err != nil {
			t.Fatal(err)
		}
		ended := []importer.Result{
			result("l", importer.Failed, importer.KindLocal),
			result("m", importer.Failed, importer.KindMismatch),
			result("s", importer.Failed, importer.KindSource),
		}
		for i, r := range ended {
			if err := reopened.Ended(user, imp.ID, 1, i+1, r); err != nil {
				t.Fatal(err)
			}
		}
		// No sweep: p and n are still pending, as in a live or crashed attempt.
		out, err := exec.Command(node, script, filepath.Join(root, user, imp.ID, recordFile)).Output()
		if err != nil {
			t.Fatalf("node: %v", err)
		}
		want := "Published by this import:\n\n" +
			"Possibly published, check each in Nexus first:\n" +
			"p@1.0.0\n  attempt 1: state=pending kind=- reason=- started=<time> ended=-\n" +
			"l@1.0.0\n  attempt 1: state=failed kind=local reason=\"failed\" started=<time> ended=-\n" +
			"n@1.0.0\n  attempt 1: state=pending kind=- reason=- started=<time> ended=-\n\n" +
			"Never uploaded, nothing to remove:\n" +
			"m@1.0.0\n  attempt 1: state=failed kind=mismatch reason=\"failed\" started=<time> ended=-\n" +
			"s@1.0.0\n  attempt 1: state=failed kind=source reason=\"failed\" started=<time> ended=-\n"
		if got := stamps(out); got != want {
			t.Errorf("output:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("a failure written without a kind is possible", func(t *testing.T) {
		rec := `{"formatVersion":1,"attempts":[{"n":1,"status":"ended","report":{"packages":[` +
			`{"name":"o","version":"1.0.0","state":"failed","reason":"interrupted"},` +
			`{"name":"q","version":"1.0.0","state":"failed","reason":"upload failed: 502"}]}}]}`
		file := filepath.Join(t.TempDir(), "import.json")
		if err := os.WriteFile(file, []byte(rec), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, script, file).Output()
		if err != nil {
			t.Fatalf("node: %v", err)
		}
		want := "Published by this import:\n\n" +
			"Possibly published, check each in Nexus first:\n" +
			"o@1.0.0\n  attempt 1: state=failed kind=- reason=\"interrupted\" started=- ended=-\n" +
			"q@1.0.0\n  attempt 1: state=failed kind=- reason=\"upload failed: 502\" started=- ended=-\n\n" +
			"Never uploaded, nothing to remove:\n"
		if got := string(out); got != want {
			t.Errorf("output:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("a package whose every attempt failed before the upload is never uploaded", func(t *testing.T) {
		rec := `{"formatVersion":1,"attempts":[` +
			`{"n":1,"status":"ended","startedAt":"2026-11-19T08:00:00Z","endedAt":"2026-11-19T08:01:00Z","report":{"packages":[` +
			`{"name":"r","version":"1.0.0","state":"failed","kind":"nexus","reason":"repository check failed: 503"},` +
			`{"name":"u","version":"1.0.0","state":"failed","kind":"nexus","reason":"repository check failed: 503"},` +
			`{"name":"w","version":"1.0.0","state":"failed","kind":"nexus","reason":"upload failed: 502"}]}},` +
			`{"n":2,"status":"ended","startedAt":"2026-11-19T09:00:00Z","endedAt":"2026-11-19T09:02:00Z","report":{"packages":[` +
			`{"name":"r","version":"1.0.0","state":"failed","kind":"nexus","reason":"repository check failed: timeout"},` +
			`{"name":"u","version":"1.0.0","state":"failed","kind":"nexus","reason":"upload failed: 502"},` +
			`{"name":"w","version":"1.0.0","state":"failed","kind":"nexus","reason":"repository check failed: 503"}]}}]}`
		file := filepath.Join(t.TempDir(), "import.json")
		if err := os.WriteFile(file, []byte(rec), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, script, file).Output()
		if err != nil {
			t.Fatalf("node: %v", err)
		}
		want := "Published by this import:\n\n" +
			"Possibly published, check each in Nexus first:\n" +
			"u@1.0.0\n" +
			"  attempt 1: state=failed kind=nexus reason=\"repository check failed: 503\" started=2026-11-19T08:00:00Z ended=2026-11-19T08:01:00Z\n" +
			"  attempt 2: state=failed kind=nexus reason=\"upload failed: 502\" started=2026-11-19T09:00:00Z ended=2026-11-19T09:02:00Z\n" +
			"w@1.0.0\n" +
			"  attempt 1: state=failed kind=nexus reason=\"upload failed: 502\" started=2026-11-19T08:00:00Z ended=2026-11-19T08:01:00Z\n" +
			"  attempt 2: state=failed kind=nexus reason=\"repository check failed: 503\" started=2026-11-19T09:00:00Z ended=2026-11-19T09:02:00Z\n\n" +
			"Never uploaded, nothing to remove:\n" +
			"r@1.0.0\n" +
			"  attempt 1: state=failed kind=nexus reason=\"repository check failed: 503\" started=2026-11-19T08:00:00Z ended=2026-11-19T08:01:00Z\n" +
			"  attempt 2: state=failed kind=nexus reason=\"repository check failed: timeout\" started=2026-11-19T09:00:00Z ended=2026-11-19T09:02:00Z\n"
		if got := string(out); got != want {
			t.Errorf("output:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("a file that is not an import record is refused", func(t *testing.T) {
		for _, rec := range []string{`{}`, `{"formatVersion":2,"attempts":[]}`, `[]`} {
			file := filepath.Join(t.TempDir(), "x.json")
			if err := os.WriteFile(file, []byte(rec), 0o600); err != nil {
				t.Fatal(err)
			}
			err := exec.Command(node, script, file).Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 1 {
				t.Errorf("%s: err = %v, want exit 1", rec, err)
			}
		}
	})

	t.Run("no file is a usage error", func(t *testing.T) {
		err := exec.Command(node, script).Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 {
			t.Errorf("err = %v, want exit 2", err)
		}
	})
}
