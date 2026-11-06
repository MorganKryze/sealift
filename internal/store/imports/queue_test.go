package imports

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/importer"
)

// waitFor receives from ch or fails the test after a generous deadline.
func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func newImport(t *testing.T, s *Store, user string) Import {
	t.Helper()
	imp, err := s.Create(user, testArchiveObject, testManifestObject, "")
	if err != nil {
		t.Fatal(err)
	}
	return imp
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func completeReport() importer.Report {
	return importer.Report{Outcome: importer.OutcomeComplete, Packages: []importer.Result{}}
}

func TestQueueRunsOneAtATimeInOrder(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imps := []Import{newImport(t, s, "alice"), newImport(t, s, "bob"), newImport(t, s, "alice")}
	started := make(chan string, 3)
	release := map[string]chan struct{}{}
	for _, imp := range imps {
		release[imp.ID] = make(chan struct{})
	}
	var running, most int
	q := NewQueue(s, func(_ context.Context, imp Import, _ string, _ importer.Progress) (importer.Report, *Removal) {
		running++
		most = max(most, running)
		started <- imp.ID
		<-release[imp.ID]
		running--
		return completeReport(), nil
	}, quietLog())
	t.Cleanup(q.Close)
	for _, imp := range imps {
		q.Submit(imp.User, imp.ID)
	}

	for i, imp := range imps {
		if got := waitFor(t, started, "the next import to start"); got != imp.ID {
			t.Fatalf("start %d was %s, want %s", i, got, imp.ID)
		}
		select {
		case extra := <-started:
			t.Fatalf("%s started while %s still ran", extra, imp.ID)
		default:
		}
		close(release[imp.ID])
	}
	q.Close()
	if most != 1 {
		t.Errorf("%d imports ran at once, want 1", most)
	}
	for _, imp := range imps {
		if got, _ := s.Get(imp.User, imp.ID); got.Outcome() != importer.OutcomeComplete {
			t.Errorf("import %s outcome %q, want complete", imp.ID, got.Outcome())
		}
	}
}

func TestQueueOwnsTheEnd(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp := newImport(t, s, "alice")
	inRun, release := make(chan Import, 1), make(chan struct{})
	var dir string
	q := NewQueue(s, func(_ context.Context, i Import, d string, p importer.Progress) (importer.Report, *Removal) {
		dir = d
		p.Listed([]importer.Result{{Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz", State: importer.Pending}})
		p.Ended(0, importer.Result{Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz", State: importer.Published})
		got, _ := s.Get(i.User, i.ID)
		inRun <- got
		<-release
		rep := completeReport()
		rep.Counts.Published = 1
		return rep, nil
	}, quietLog())
	t.Cleanup(q.Close)
	q.Submit(imp.User, imp.ID)

	during := waitFor(t, inRun, "the run to start")
	if during.Outcome() != string(StatusRunning) {
		t.Errorf("outcome during the run = %q, want running", during.Outcome())
	}
	if got := during.Attempts[0].Report.Packages; len(got) != 1 || got[0].State != importer.Published {
		t.Errorf("the package state written during the run = %+v", got)
	}
	if during.Attempts[0].EndedAt != nil {
		t.Error("the attempt had an end while its run was still going")
	}
	close(release)
	q.Close()

	got, err := s.Get(imp.User, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := got.Attempts[0]
	if a.Status != StatusEnded || a.Outcome != importer.OutcomeComplete || a.EndedAt == nil || a.Report.Counts.Published != 1 {
		t.Errorf("attempt after the run = %+v", a)
	}
	if dir == "" {
		t.Error("the run was given no working directory")
	}
}

func TestQueueCloseInterrupts(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	first, second := newImport(t, s, "alice"), newImport(t, s, "alice")
	started := make(chan string, 2)
	q := NewQueue(s, func(ctx context.Context, imp Import, _ string, _ importer.Progress) (importer.Report, *Removal) {
		started <- imp.ID
		<-ctx.Done()
		return importer.Report{Outcome: importer.OutcomeIncomplete, Packages: []importer.Result{}}, &Removal{Removed: true}
	}, quietLog())
	q.Submit(first.User, first.ID)
	q.Submit(second.User, second.ID)
	waitFor(t, started, "the first run")

	q.Close()

	got, _ := s.Get(first.User, first.ID)
	a := got.Attempts[0]
	if got.Outcome() != OutcomeInterrupted || a.Status != StatusEnded || a.EndedAt == nil {
		t.Errorf("first import: outcome %q, attempt %+v; want ended interrupted", got.Outcome(), a)
	}
	if a.Removal != nil {
		t.Errorf("an interrupted attempt kept a removal: %+v", a.Removal)
	}
	if a.Report.Reason == "" {
		t.Error("an interrupted attempt has no reason")
	}
	later, _ := s.Get(second.User, second.ID)
	if later.Outcome() != string(StatusQueued) {
		t.Errorf("second import outcome %q, want queued", later.Outcome())
	}
	select {
	case id := <-started:
		t.Errorf("import %s started after Close", id)
	default:
	}
	q.Submit(second.User, second.ID)
	q.Close()
}

func TestQueueKeepsACompleteReportAfterClose(t *testing.T) {
	s, _ := openStore(t, testRoot(t))
	imp := newImport(t, s, "alice")
	inRun, release := make(chan struct{}), make(chan struct{})
	q := NewQueue(s, func(context.Context, Import, string, importer.Progress) (importer.Report, *Removal) {
		close(inRun)
		<-release
		return completeReport(), nil
	}, quietLog())
	q.Submit(imp.User, imp.ID)
	waitFor(t, inRun, "the run")
	closed := make(chan struct{})
	go func() { q.Close(); close(closed) }()
	close(release)
	waitFor(t, closed, "Close")
	if got, _ := s.Get(imp.User, imp.ID); got.Outcome() != importer.OutcomeComplete {
		t.Errorf("outcome %q: a run that finished every package is complete even when Close came last", got.Outcome())
	}
}
