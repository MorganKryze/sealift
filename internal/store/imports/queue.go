package imports

import (
	"context"
	"errors"
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

// OutcomeCancelled is the outcome of an attempt its user cancelled.
const OutcomeCancelled = "cancelled"

// reasonCancelled is the reason of a package a cancel kept from Nexus.
const reasonCancelled = "cancelled before it was published"

// ErrEnded answers a cancel of an import whose latest attempt has ended.
var ErrEnded = errors.New("imports: the latest attempt has ended")

// current is the attempt the worker took from the queue. Its fields are
// guarded by the queue's mutex.
type current struct {
	queued
	ctx       context.Context // ends on Close or on a cancel of this attempt
	stop      context.CancelFunc
	cancelled bool // a cancel reached the run before it returned
	returned  bool // the run returned: a cancel comes too late
}

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
	now   *current
	wake  chan struct{}
}

// NewQueue starts the queue's worker.
func NewQueue(s *Store, run RunFunc, log *slog.Logger) *Queue {
	ctx, stop := context.WithCancel(context.Background())
	q := &Queue{s: s, run: run, log: log, ctx: ctx, stop: stop, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	s.mu.Lock()
	s.queue = q
	s.mu.Unlock()
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

// ahead returns how many attempts run or wait before the one of user and
// id, and false when the queue does not hold it waiting.
func (q *Queue) ahead(user, id string) (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, it := range q.items {
		if it.user == user && it.id == id {
			if q.now != nil {
				i++
			}
			return i, true
		}
	}
	return 0, false
}

// The answers of cancel.
type cancelResult int

const (
	cancelUnknown  cancelResult = iota // the queue does not hold the attempt
	cancelTaken                        // taken out of the queue: it never runs
	cancelStopping                     // running: it stops before its next package
	cancelTooLate                      // its run has returned
)

// cancel takes the attempt of user and id out of the queue, or stops its
// run when it is the one running.
func (q *Queue) cancel(user, id string) cancelResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, it := range q.items {
		if it.user == user && it.id == id {
			q.items = append(q.items[:i:i], q.items[i+1:]...)
			return cancelTaken
		}
	}
	if c := q.now; c != nil && c.user == user && c.id == id {
		if c.returned {
			return cancelTooLate
		}
		c.cancelled = true
		c.stop()
		return cancelStopping
	}
	return cancelUnknown
}

func (q *Queue) loop() {
	defer close(q.done)
	for {
		c, ok := q.next()
		if !ok {
			return
		}
		q.process(c)
		c.stop()
		q.mu.Lock()
		q.now = nil
		q.mu.Unlock()
	}
}

// next waits for the first queued attempt and makes it the current one, with
// a context of its own. It returns false once the queue is closed.
func (q *Queue) next() (*current, bool) {
	for {
		q.mu.Lock()
		if q.ctx.Err() != nil {
			q.mu.Unlock()
			return nil, false
		}
		if len(q.items) > 0 {
			ctx, stop := context.WithCancel(q.ctx)
			c := &current{queued: q.items[0], ctx: ctx, stop: stop}
			q.items = q.items[1:]
			q.now = c
			q.mu.Unlock()
			return c, true
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

func (q *Queue) process(c *current) {
	it := c.queued
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
		Listed: func(rep importer.Report) {
			if err := q.s.Listed(it.user, it.id, n, rep); err != nil {
				logf("could not store the package list", err)
			}
		},
		Checked: func() {
			if err := q.s.Checked(it.user, it.id, n); err != nil {
				logf("could not store that the archive passed its checks", err)
			}
		},
		Ended: func(i int, r importer.Result) {
			if err := q.s.Ended(it.user, it.id, n, i, r); err != nil {
				logf("could not store a package state", err)
			}
		},
	}
	rep, remove, panicked := q.guarded(c.ctx, it, imp, dir, progress)
	q.mu.Lock()
	c.returned = true
	cancelled := c.cancelled
	q.mu.Unlock()
	if panicked {
		// The states the run stored stay; only the outcome and the reason are set.
		if err := q.s.Break(it.user, it.id, reasonPanic); err != nil {
			logf("could not end a panicked attempt", err)
			abandon("the end of the import could not be stored; see the service log")
		}
		return
	}
	// A run that was cut short reports incomplete; a report that finished
	// every package stays what it says, even when a cancel or Close came last.
	if rep.Outcome == importer.OutcomeIncomplete {
		switch {
		case cancelled:
			cancelledReport(&rep)
			remove = nil
		case q.ctx.Err() != nil:
			rep.Outcome, remove = OutcomeInterrupted, nil
			if rep.Reason == "" {
				rep.Reason = OutcomeInterrupted
			}
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
// is reported through panicked and leaves the worker alive for every user.
func (q *Queue) guarded(ctx context.Context, it queued, imp Import, dir string, p importer.Progress) (rep importer.Report, remove Remover, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			q.log.Error("an import attempt panicked", "user", it.user, "id", it.id, "panic", fmt.Sprint(r))
			rep, remove, panicked = importer.Report{}, nil, true
		}
	}()
	rep, remove = q.run(ctx, imp, dir, p)
	return rep, remove, false
}

// cancelledReport marks the report of a run a cancel cut short: the packages
// it did not reach say so, and those in Nexus stay as they ended.
func cancelledReport(rep *importer.Report) {
	rep.Outcome = OutcomeCancelled
	if rep.Reason == "" || rep.Reason == OutcomeInterrupted {
		rep.Reason = OutcomeCancelled
	}
	for i, p := range rep.Packages {
		if p.State == importer.Failed && p.Kind == importer.KindInterrupted {
			rep.Packages[i].Reason = reasonCancelled
		}
	}
}

// Ahead returns how many attempts run or wait before the latest attempt of
// the user's import, whoever started them, and false when no queue holds it
// waiting.
func (s *Store) Ahead(user, id string) (n int, queued bool) {
	s.mu.Lock()
	q := s.queue
	s.mu.Unlock()
	if q == nil {
		return 0, false
	}
	return q.ahead(user, id)
}

// Cancel ends the latest attempt of the user's import: a queued one at once,
// a running one before its next package, through its queue. An attempt that
// has ended answers ErrEnded. A store with no queue ends a queued attempt and
// answers ErrBusy for a running one, which it cannot stop.
func (s *Store) Cancel(user, id string) (Import, error) {
	if !ValidUser(user) || !ValidID(id) {
		return Import{}, ErrNotFound
	}
	// The record is read first, so another user's id never reaches the queue.
	if _, err := s.Get(user, id); err != nil {
		return Import{}, err
	}
	s.mu.Lock()
	q := s.queue
	s.mu.Unlock()
	if q != nil {
		switch q.cancel(user, id) {
		case cancelStopping:
			return s.Get(user, id)
		case cancelTooLate:
			return Import{}, ErrEnded
		}
	}
	// Taken out of the queue, or held by none: nothing else starts it now.
	return s.cancelQueued(user, id)
}

// cancelQueued ends a queued latest attempt as cancelled.
func (s *Store) cancelQueued(user, id string) (Import, error) {
	var out Import
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		a := &imp.Attempts[len(imp.Attempts)-1]
		switch a.Status {
		case StatusEnded:
			return "", ErrEnded
		case StatusRunning:
			return "", ErrBusy
		}
		now := s.clock()
		a.Status, a.EndedAt, a.Outcome, a.Removal = StatusEnded, &now, OutcomeCancelled, nil
		a.Report.Outcome, a.Report.Reason = OutcomeCancelled, OutcomeCancelled
		out = normalize(*imp)
		return "", nil
	})
	if err != nil {
		return Import{}, err
	}
	return out, nil
}
