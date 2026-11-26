package imports

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/importer"
)

func TestStoreRetry(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp := newImport(t, s, "alice")

	t.Run("a queued or running attempt is busy", func(t *testing.T) {
		if _, err := s.Retry("alice", imp.ID); !errors.Is(err, ErrBusy) {
			t.Fatalf("queued: err = %v, want ErrBusy", err)
		}
		if _, _, err := s.Begin("alice", imp.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Retry("alice", imp.ID); !errors.Is(err, ErrBusy) {
			t.Fatalf("running: err = %v, want ErrBusy", err)
		}
		if got, _ := s.Get("alice", imp.ID); len(got.Attempts) != 1 {
			t.Errorf("a refused retry left %d attempts", len(got.Attempts))
		}
	})

	rep := importer.Report{Outcome: importer.OutcomeIncomplete, Reason: "first", Packages: []importer.Result{
		{Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz", State: importer.Failed, Reason: "down"},
	}, Counts: importer.Counts{Failed: 1}}
	if err := s.Finish("alice", imp.ID, 1, rep, nil); err != nil {
		t.Fatal(err)
	}

	t.Run("an ended attempt gets a successor", func(t *testing.T) {
		got, err := s.Retry("alice", imp.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Attempts) != 2 {
			t.Fatalf("%d attempts, want 2", len(got.Attempts))
		}
		first, second := got.Attempts[0], got.Attempts[1]
		if second.N != 2 || second.Status != StatusQueued || second.QueuedAt == nil || second.Outcome != "" {
			t.Errorf("new attempt = %+v", second)
		}
		if first.N != 1 || first.Status != StatusEnded || first.Outcome != importer.OutcomeIncomplete || first.Report.Reason != "first" || len(first.Report.Packages) != 1 {
			t.Errorf("the earlier attempt moved: %+v", first)
		}
		if got.Outcome() != string(StatusQueued) {
			t.Errorf("outcome %q, want queued", got.Outcome())
		}
		stored, _ := s.Get("alice", imp.ID)
		if len(stored.Attempts) != 2 {
			t.Errorf("stored %d attempts, want 2", len(stored.Attempts))
		}
		if _, err := s.Retry("alice", imp.ID); !errors.Is(err, ErrBusy) {
			t.Errorf("second retry: err = %v, want ErrBusy", err)
		}
	})

	t.Run("another user and a bad id are not found", func(t *testing.T) {
		if _, err := s.Retry("bob", imp.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("bob: err = %v", err)
		}
		if _, err := s.Retry("alice", "../x"); !errors.Is(err, ErrNotFound) {
			t.Errorf("bad id: err = %v", err)
		}
	})
}

func TestStoreRefusesALateAttempt(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp := newImport(t, s, "alice")
	if _, n, err := s.Begin("alice", imp.ID); err != nil || n != 1 {
		t.Fatalf("Begin: n = %d, err = %v", n, err)
	}
	if err := s.Finish("alice", imp.ID, 1, importer.Report{Outcome: importer.OutcomeIncomplete}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retry("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	if _, n, err := s.Begin("alice", imp.ID); err != nil || n != 2 {
		t.Fatalf("Begin of the retry: n = %d, err = %v", n, err)
	}
	late := importer.Report{Outcome: importer.OutcomeComplete}
	if err := s.Finish("alice", imp.ID, 1, late, nil); err == nil {
		t.Error("a late Finish of attempt 1 was accepted")
	}
	if err := s.Listed("alice", imp.ID, 1, listedReport()); err == nil {
		t.Error("a late Listed of attempt 1 was accepted")
	}
	if err := s.Ended("alice", imp.ID, 1, 0, importer.Result{}); err == nil {
		t.Error("a late Ended of attempt 1 was accepted")
	}
	got, _ := s.Get("alice", imp.ID)
	if got.Attempts[1].Status != StatusRunning || got.Attempts[0].Outcome != importer.OutcomeIncomplete {
		t.Errorf("attempts after the late calls = %+v", got.Attempts)
	}
}

func TestQueueEndsAStuckRecord(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp := newImport(t, s, "alice")
	// A running attempt that nothing runs: Begin refuses a second start.
	if _, _, err := s.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	ran := false
	q := NewQueue(s, func(context.Context, Import, string, importer.Progress) (importer.Report, Remover) {
		ran = true
		return completeReport(), nil
	}, quietLog())
	t.Cleanup(q.Close)
	q.Submit(imp.User, imp.ID)
	var got Import
	for range 1_000_000 {
		got, _ = s.Get(imp.User, imp.ID)
		if got.Attempts[0].Status == StatusEnded {
			break
		}
		runtime.Gosched()
	}
	q.Close()

	a := got.Attempts[0]
	if ran || a.Status != StatusEnded || a.Outcome != OutcomeInterrupted || a.Report.Reason == "" {
		t.Errorf("ran %v, attempt %+v; want ended interrupted with a reason", ran, a)
	}
	if _, err := s.Retry(imp.User, imp.ID); err != nil {
		t.Errorf("a retry of the stuck record: %v", err)
	}
}

func TestQueueSurvivesAPanic(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	first, second := newImport(t, s, "alice"), newImport(t, s, "alice")
	done := make(chan string, 1)
	q := NewQueue(s, func(_ context.Context, imp Import, _ string, _ importer.Progress) (importer.Report, Remover) {
		if imp.ID == first.ID {
			panic("boom with /secret/path")
		}
		done <- imp.ID
		return completeReport(), nil
	}, quietLog())
	t.Cleanup(q.Close)
	q.Submit(first.User, first.ID)
	q.Submit(second.User, second.ID)
	waitFor(t, done, "the import after the panic")
	q.Close()

	got, _ := s.Get(first.User, first.ID)
	a := got.Attempts[0]
	if a.Status != StatusEnded || a.Outcome != importer.OutcomeIncomplete || a.Report.Reason == "" {
		t.Fatalf("panicked attempt = %+v", a)
	}
	if strings.Contains(a.Report.Reason, "secret") || strings.Contains(a.Report.Reason, "boom") {
		t.Errorf("the reason repeats the panic: %q", a.Report.Reason)
	}
	if again, _ := s.Get(second.User, second.ID); again.Outcome() != importer.OutcomeComplete {
		t.Errorf("the next import ended %q", again.Outcome())
	}
}

func TestQueueSubmitAfterClose(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp := newImport(t, s, "alice")
	q := NewQueue(s, func(context.Context, Import, string, importer.Progress) (importer.Report, Remover) {
		return completeReport(), nil
	}, quietLog())
	if !q.Submit(imp.User, imp.ID) {
		t.Fatal("Submit refused an open queue")
	}
	q.Close()
	if q.Submit(imp.User, imp.ID) {
		t.Error("Submit accepted work after Close")
	}
}

func TestStoreRecordsARemovalOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome string
		n       int
		first   bool
		wantErr bool
	}{
		{"after a complete end", importer.OutcomeComplete, 1, false, false},
		{"for another attempt", importer.OutcomeComplete, 2, false, true},
		{"after an incomplete end", importer.OutcomeIncomplete, 1, false, true},
		{"over a removal already stored", importer.OutcomeComplete, 1, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := openStore(t, testRoot(t))
			imp := newImport(t, s, "alice")
			if _, _, err := s.Begin("alice", imp.ID); err != nil {
				t.Fatal(err)
			}
			var first *Removal
			if tc.first {
				first = &Removal{Reason: "kept"}
			}
			rep := importer.Report{Outcome: tc.outcome, Packages: []importer.Result{}}
			if err := s.Finish("alice", imp.ID, 1, rep, first); err != nil {
				t.Fatal(err)
			}
			err := s.Removed("alice", imp.ID, tc.n, Removal{Removed: true})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Removed error = %v, want error %v", err, tc.wantErr)
			}
			got, _ := s.Get("alice", imp.ID)
			if rem := got.Attempts[0].Removal; tc.wantErr == (rem != nil && rem.Removed) {
				t.Errorf("stored removal = %+v", rem)
			}
		})
	}
}

func TestEndedAttemptsFailPendingPackagesAsInterrupted(t *testing.T) {
	for name, tc := range map[string]struct {
		end     func(s *Store, imp Import) error
		outcome string
		reason  string
	}{
		"abandon": {func(s *Store, imp Import) error { return s.Abandon(imp.User, imp.ID, "stopped") }, OutcomeInterrupted, "interrupted"},
		"break":   {func(s *Store, imp Import) error { return s.Break(imp.User, imp.ID, "panic") }, importer.OutcomeIncomplete, "not reached"},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := openStore(t, testRoot(t))
			imp := newImport(t, s, "alice")
			if _, _, err := s.Begin(imp.User, imp.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.Listed(imp.User, imp.ID, 1, listedReport()); err != nil {
				t.Fatal(err)
			}
			done := pendingResults()[0]
			done.State = importer.Published
			if err := s.Ended(imp.User, imp.ID, 1, 0, done); err != nil {
				t.Fatal(err)
			}
			if err := tc.end(s, imp); err != nil {
				t.Fatal(err)
			}
			got, _ := s.Get(imp.User, imp.ID)
			a := got.Attempts[0]
			if a.Outcome != tc.outcome || len(a.Report.Packages) != 2 {
				t.Fatalf("attempt %+v", a)
			}
			if p := a.Report.Packages[0]; p.State != importer.Published || p.Kind != "" {
				t.Errorf("the published package became %+v", p)
			}
			if p := a.Report.Packages[1]; p.State != importer.Failed || p.Reason != tc.reason || p.Kind != importer.KindInterrupted {
				t.Errorf("the pending package became %+v, want failed %q with kind interrupted", p, tc.reason)
			}
		})
	}
}

// endedWith records an import whose first attempt ended incomplete with left-pad
// failed and zeta published.
func endedWith(t *testing.T, s *Store) Import {
	t.Helper()
	imp := newImport(t, s, "alice")
	if _, _, err := s.Begin(imp.User, imp.ID); err != nil {
		t.Fatal(err)
	}
	pkgs := pendingResults()
	pkgs[0].State, pkgs[0].Kind, pkgs[0].Reason = importer.Failed, importer.KindNexus, "no answer"
	pkgs[1].State = importer.Published
	rep := importer.Report{Outcome: importer.OutcomeIncomplete, Packages: pkgs, Counts: importer.Counts{Published: 1, Failed: 1}}
	if err := s.Finish(imp.User, imp.ID, 1, rep, nil); err != nil {
		t.Fatal(err)
	}
	return imp
}

func TestStoreRetryList(t *testing.T) {
	t.Run("records the files a retry takes", func(t *testing.T) {
		s, _ := openStore(t, testRoot(t))
		imp := endedWith(t, s)
		got, err := s.Retry(imp.User, imp.ID, "left-pad-1.3.0.tgz")
		if err != nil {
			t.Fatal(err)
		}
		stored, _ := s.Get(imp.User, imp.ID)
		for _, i := range []Import{got, stored} {
			if r := i.Attempts[1].Retry; len(r) != 1 || r[0] != "left-pad-1.3.0.tgz" {
				t.Errorf("the new attempt's list = %v", r)
			}
			if i.Attempts[0].Retry != nil {
				t.Errorf("the first attempt has a list: %v", i.Attempts[0].Retry)
			}
		}
	})
	t.Run("records no list for a whole retry", func(t *testing.T) {
		for name, files := range map[string][]string{"nil": nil, "empty": {}} {
			s, _ := openStore(t, testRoot(t))
			imp := endedWith(t, s)
			got, err := s.Retry(imp.User, imp.ID, files...)
			if err != nil {
				t.Fatal(err)
			}
			if got.Attempts[1].Retry != nil {
				t.Errorf("%s: list %v, want none", name, got.Attempts[1].Retry)
			}
			raw, err := os.ReadFile(filepath.Join(s.dir(imp.User, imp.ID), recordFile))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"retry"`) {
				t.Errorf("%s: the record writes a retry list", name)
			}
		}
	})
	t.Run("refuses a list that is not failed packages of the latest attempt", func(t *testing.T) {
		for name, files := range map[string][]string{
			"a published package": {"zeta-2.0.0.tgz"},
			"an unknown file":     {"other-1.0.0.tgz"},
			"a duplicate":         {"left-pad-1.3.0.tgz", "left-pad-1.3.0.tgz"},
			"more than listed":    {"left-pad-1.3.0.tgz", "a", "b"},
		} {
			s, _ := openStore(t, testRoot(t))
			imp := endedWith(t, s)
			if _, err := s.Retry(imp.User, imp.ID, files...); !errors.Is(err, ErrRetryList) {
				t.Errorf("%s: err = %v, want ErrRetryList", name, err)
			}
			if got, _ := s.Get(imp.User, imp.ID); len(got.Attempts) != 1 {
				t.Errorf("%s: a refused list left %d attempts", name, len(got.Attempts))
			}
		}
	})
}
