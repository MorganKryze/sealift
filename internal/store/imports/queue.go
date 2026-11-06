package imports

import (
	"context"
	"log/slog"
	"sync"

	"github.com/MorganKryze/sealift/internal/importer"
)

// RunFunc runs one attempt of imp in dir, a working directory the queue owns,
// and reports each package's state through p. It never writes the attempt's end.
type RunFunc func(ctx context.Context, imp Import, dir string, p importer.Progress) (importer.Report, *Removal)

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

// Submit queues the latest attempt of an import. After Close it does nothing.
func (q *Queue) Submit(user, id string) {
	q.mu.Lock()
	if q.ctx.Err() == nil {
		q.items = append(q.items, queued{user, id})
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
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

func (q *Queue) process(it queued) {
	logf := func(what string, err error) {
		q.log.Error(what, "user", it.user, "id", it.id, "error", err)
	}
	dir, err := q.s.Begin(it.user, it.id)
	if err != nil {
		logf("could not start an attempt", err)
		return
	}
	imp, err := q.s.Get(it.user, it.id)
	if err != nil {
		logf("could not read an import to run", err)
		return
	}
	progress := importer.Progress{
		Listed: func(pkgs []importer.Result) {
			if err := q.s.Listed(it.user, it.id, pkgs); err != nil {
				logf("could not store the package list", err)
			}
		},
		Ended: func(i int, r importer.Result) {
			if err := q.s.Ended(it.user, it.id, i, r); err != nil {
				logf("could not store a package state", err)
			}
		},
	}
	rep, rem := q.run(q.ctx, imp, dir, progress)
	// A run that was cut short reports incomplete; a report that finished
	// every package stays what it says, even when Close came last.
	if q.ctx.Err() != nil && rep.Outcome == importer.OutcomeIncomplete {
		rep.Outcome, rem = OutcomeInterrupted, nil
		if rep.Reason == "" {
			rep.Reason = OutcomeInterrupted
		}
	}
	if rep.Packages == nil {
		rep.Packages = []importer.Result{}
	}
	if err := q.s.Finish(it.user, it.id, rep, rem); err != nil {
		logf("could not store the end of an attempt", err)
		return
	}
	q.log.Info("import attempt ended", "user", it.user, "id", it.id, "outcome", rep.Outcome)
}
