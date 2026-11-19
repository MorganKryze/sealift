package imports

import (
	"errors"
	"os/exec"
	"path/filepath"
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
	want := "Published by this import:\na@1.0.0\n@scope/e@1.0.0\n\nPossibly published, check each in Nexus first:\nb@1.0.0\n"
	if string(out) != want {
		t.Errorf("output:\n%q\nwant:\n%q", out, want)
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
		want := "Published by this import:\n\nPossibly published, check each in Nexus first:\ng@1.0.0\nh@1.0.0\n"
		if string(out) != want {
			t.Errorf("output:\n%q\nwant:\n%q", out, want)
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
