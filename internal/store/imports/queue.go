package imports

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/MorganKryze/sealift/internal/importer"
)

// RunFunc runs one attempt of imp in dir, a working directory the queue owns,
// and reports each package's state through p. It never writes the attempt's
// end. The Remover it returns is nil unless the attempt may remove the archive.
type RunFunc func(ctx context.Context, imp Import, dir string, p importer.Progress) (importer.Report, Remover)

// Remover deletes the archive and says what became of it. The queue calls it
// only after the attempt's complete end is stored, so a crash during the
// delete leaves a complete attempt and never an interrupted one.
type Remover func(ctx context.Context) *Removal

type queued struct{ user, id string }

// Queue runs submitted attempts on one goroutine, the first submitted first.
// It writes an attempt's start and its end; the run function writes only
// package states.
type Queue struct {
	s    *Store
	run  RunFunc
	log  *slog.Logger
	ctx  context.Context
	stop context.CancelFunc
	done chan struct{}

	mu    sync.Mutex
	items []queued
	wake  chan struct{}
}

// NewQueue starts the queue's worker.
func NewQueue(s *Store, run RunFunc, log *slog.Logger) *Queue {
	ctx, stop := context.WithCancel(context.Background())
	q := &Queue{s: s, run: run, log: log, ctx: ctx, stop: stop, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	go q.loop()
	return q
}

// Submit queues the latest attempt of an import. After Close it queues
// nothing and returns false, so the caller can say the work will not run.
func (q *Queue) Submit(user, id string) bool {
	q.mu.Lock()
	open := q.ctx.Err() == nil
	if open {
		q.items = append(q.items, queued{user, id})
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return open
}

// Close cancels the running attempt, which ends interrupted, and waits for
// the worker to stop. Attempts still queued start nothing; a restart's sweep
// ends them. Close may be called again.
func (q *Queue) Close() {
	q.stop()
	<-q.done
}

func (q *Queue) loop() {
	defer close(q.done)
	for {
		it, ok := q.next()
		if !ok {
			return
		}
		q.process(it)
	}
}

// next waits for the first queued attempt. It returns false once the queue is closed.
func (q *Queue) next() (queued, bool) {
	for {
		q.mu.Lock()
		if q.ctx.Err() != nil {
			q.mu.Unlock()
			return queued{}, false
		}
		if len(q.items) > 0 {
			it := q.items[0]
			q.items = q.items[1:]
			q.mu.Unlock()
			return it, true
		}
		q.mu.Unlock()
		select {
		case <-q.wake:
		case <-q.ctx.Done():
		}
	}
}

// reasonPanic is the reason of an attempt whose run panicked; the panic's own
// text stays out of the record because it may quote a path.
const reasonPanic = "the import stopped on an internal error; see the service log"

func (q *Queue) process(it queued) {
	logf := func(what string, err error) {
		q.log.Error(what, "user", it.user, "id", it.id, "error", err)
	}
	// abandon ends an attempt the queue cannot run, so no record stays queued
	// or running with nothing behind it.
	abandon := func(why string) {
		if err := q.s.Abandon(it.user, it.id, why); err != nil {
			logf("could not end an attempt", err)
		}
	}
	dir, n, err := q.s.Begin(it.user, it.id)
	if err != nil {
		logf("could not start an attempt", err)
		abandon("the import could not be started; see the service log")
		return
	}
	imp, err := q.s.Get(it.user, it.id)
	if err != nil {
		logf("could not read an import to run", err)
		abandon("the import could not be read; see the service log")
		return
	}
	progress := importer.Progress{
		Listed: func(pkgs []importer.Result) {
			if err := q.s.Listed(it.user, it.id, n, pkgs); err != nil {
				logf("could not store the package list", err)
			}
		},
		Ended: func(i int, r importer.Result) {
			if err := q.s.Ended(it.user, it.id, n, i, r); err != nil {
				logf("could not store a package state", err)
			}
		},
	}
	rep, remove := q.guarded(it, imp, dir, progress)
	// A run that was cut short reports incomplete; a report that finished
	// every package stays what it says, even when Close came last.
	if q.ctx.Err() != nil && rep.Outcome == importer.OutcomeIncomplete {
		rep.Outcome, remove = OutcomeInterrupted, nil
		if rep.Reason == "" {
			rep.Reason = OutcomeInterrupted
		}
	}
	if rep.Packages == nil {
		rep.Packages = []importer.Result{}
	}
	if err := q.s.Finish(it.user, it.id, n, rep, nil); err != nil {
		logf("could not store the end of an attempt", err)
		abandon("the end of the import could not be stored; see the service log")
		return
	}
	if remove != nil {
		if rem := remove(q.ctx); rem != nil {
			if err := q.s.Removed(it.user, it.id, n, *rem); err != nil {
				logf("could not store the removal of an archive", err)
			}
		}
	}
	q.log.Info("import attempt ended", "user", it.user, "id", it.id, "outcome", rep.Outcome)
}

// guarded runs one attempt. A panic in the run, in archive parsing for one,
// ends that attempt incomplete and leaves the worker alive for every user.
func (q *Queue) guarded(it queued, imp Import, dir string, p importer.Progress) (rep importer.Report, remove Remover) {
	defer func() {
		if r := recover(); r != nil {
			q.log.Error("an import attempt panicked", "user", it.user, "id", it.id, "panic", fmt.Sprint(r))
			rep, remove = importer.Report{Outcome: importer.OutcomeIncomplete, Reason: reasonPanic, Packages: []importer.Result{}}, nil
		}
	}()
	return q.run(q.ctx, imp, dir, p)
}
