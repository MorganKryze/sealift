package imports

import (
	"context"
	"errors"
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
	if err := s.Listed("alice", imp.ID, 1, pendingResults()); err == nil {
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
	q := NewQueue(s, func(context.Context, Import, string, importer.Progress) (importer.Report, *Removal) {
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
	q := NewQueue(s, func(_ context.Context, imp Import, _ string, _ importer.Progress) (importer.Report, *Removal) {
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
	q := NewQueue(s, func(context.Context, Import, string, importer.Progress) (importer.Report, *Removal) {
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
