// Package jobs runs analysis and export jobs one at a time and streams
// their events to the interface.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"

	"github.com/MorganKryze/sealift/internal/store"
)

// replayLimit bounds how many of a job's past "log", "progress" and
// "candidate" events a new subscriber replays. "step" events are exempt
// (see appendHistoryLocked): a subscriber that connects mid-run, such as
// a reloaded tab, must replay every step already reached to show it as
// done instead of stuck on its upcoming dot, and there are only a
// handful of those per job regardless of how long it runs.
const replayLimit = 128

// stepHeadroom is generous headroom, on top of replayLimit, for the
// "step" events appendHistoryLocked exempts from trimming: the longest
// job (an analysis) reaches 9, an export 5. It sizes each subscriber
// channel so a full replay never hits the drop path in Subscribe.
const stepHeadroom = 32

// ErrNotFound reports a Cancel call naming a job the queue does not hold,
// neither running nor queued.
var ErrNotFound = errors.New("jobs: job not found")

// ErrClosed reports a Submit call reaching a closed queue.
var ErrClosed = errors.New("jobs: queue is closed")

// Event is one message a job emits while it runs, or the queue emits about
// it. Kind is one of "step", "progress", "candidate", "log" or "end". Job
// is the queue id (assigned per submission, not stable across a server
// restart); StoreID is the directory id the store and the client both
// use, set by Service.Subscribe, since the queue itself never sees it.
type Event struct {
	Kind    string          `json:"kind"`
	Job     string          `json:"job"`
	StoreID string          `json:"storeId,omitempty"`
	Data    json.RawMessage `json:"data"`
}

// Job is a unit of work the queue runs to completion before starting the
// next one. Run must return once ctx is done. Run must not emit its own
// "end" event: the queue appends exactly one, with the state it computed,
// once Run returns.
type Job interface {
	Kind() string
	Run(ctx context.Context, emit func(Event)) error
}

// storeIdentified is a job that knows the store directory id the client
// names it by. The queue stamps that id on every event it emits for the
// job, the end event included, so no lookup can miss it after the job has
// been finalized and dropped from the service's index.
type storeIdentified interface {
	StoreID() string
}

func storeIDOf(j Job) string {
	if s, ok := j.(storeIdentified); ok {
		return s.StoreID()
	}
	return ""
}

type entry struct {
	id  string
	job Job
}

// FinalizeInfo is the bounded, typed shape the queue's finalize hook
// receives: just enough to let a caller commit or reconcile a job's own
// state, never the job's own Event stream, whose raw, arbitrarily sized
// Data a hook could otherwise be tempted to hold onto.
type FinalizeInfo struct {
	ID    string
	Kind  string
	State store.State
}

// FinalizeFunc is the queue's finalize hook. See SetFinalizer.
type FinalizeFunc func(FinalizeInfo) error

type subscriber struct {
	ch chan Event
	// notified tracks whether this subscriber already got a "log" event
	// about a drop, so a run of drops produces one notice, not a flood.
	// It resets once a send to this subscriber succeeds again.
	notified bool
}

// Queue runs Job values one at a time, in submission order, kept in memory
// only: a restart loses the queue and the running job. It is safe for
// concurrent use.
type Queue struct {
	log *slog.Logger

	mu      sync.Mutex
	cond    *sync.Cond
	pending []entry
	closed  bool

	current         *entry
	cancelCurrent   context.CancelFunc
	cancelRequested bool
	history         []Event
	finalize        FinalizeFunc

	subs    map[int]*subscriber
	nextSub int
	nextID  uint64

	done chan struct{}
}

// NewQueue starts the worker goroutine and returns a ready Queue. A nil log
// falls back to slog.Default.
func NewQueue(log *slog.Logger) *Queue {
	if log == nil {
		log = slog.Default()
	}
	q := &Queue{
		log:  log,
		subs: make(map[int]*subscriber),
		done: make(chan struct{}),
	}
	q.cond = sync.NewCond(&q.mu)
	go q.run()
	return q
}

// SetFinalizer registers fn as the queue's one finalize hook, replacing
// any previous one; nil clears it. The queue calls it synchronously, on
// the worker goroutine, exactly once per job: right after that job's
// terminal state is known, and before the queue clears the current job
// and publishes its "end" event. Unlike a Subscribe channel, which
// deliverLocked drops for a subscriber that falls behind, this call is
// never dropped, which is the point: a caller that must commit or
// discard a directory, or reconcile a status file, on every job needs a
// path the queue cannot skip. The queue does not retry a returned error
// and cannot undo a job that already ran, so it only logs it and moves
// on; a hook must therefore treat its own failure as final too.
func (q *Queue) SetFinalizer(fn FinalizeFunc) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finalize = fn
}

// runFinalizer calls the registered finalize hook, if any, logging but
// swallowing its error: see SetFinalizer.
func (q *Queue) runFinalizer(id, kind string, state store.State) {
	q.mu.Lock()
	fn := q.finalize
	q.mu.Unlock()
	if fn == nil {
		return
	}
	if err := fn(FinalizeInfo{ID: id, Kind: kind, State: state}); err != nil {
		q.log.Error("finalize hook failed", "id", id, "kind", kind, "state", state, "error", err)
	}
}

// Submit queues j to run once every earlier job has finished, fifo, and
// returns the id later calls use to name it.
func (q *Queue) Submit(j Job) (id string, err error) {
	return q.SubmitWith(j, nil)
}

// SubmitWith queues a job and calls register with its id before the worker
// can pick the job up. A caller that indexes a job by its queue id must use
// this: registering after Submit returns races a job that has already
// finished, and the finalize hook would then find nothing to finalize,
// leaving the job's directory unpublished and the job indexed forever.
func (q *Queue) SubmitWith(j Job, register func(id string)) (id string, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return "", ErrClosed
	}
	q.nextID++
	id = fmt.Sprintf("%s-%d", j.Kind(), q.nextID)
	if register != nil {
		register(id)
	}
	q.pending = append(q.pending, entry{id: id, job: j})
	q.cond.Signal()
	return id, nil
}

// Current reports the id and kind of the running job, if any. ok is false
// while the queue is idle, even with jobs still waiting. Whenever ok is
// true the job is, by construction, in state running; Current carries no
// separate state value because there is nothing else for it to say.
func (q *Queue) Current() (id, kind string, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.current == nil {
		return "", "", false
	}
	return q.current.id, q.current.job.Kind(), true
}

// Cancel stops the running job by id, or drops a queued one before it
// starts. It returns ErrNotFound when id names neither. Cancelling a
// queued job publishes its "end" event with state cancelled, the same
// signal a subscriber gets for a running job the queue stops: nothing
// else ever tells a caller that job is done.
func (q *Queue) Cancel(id string) error {
	q.mu.Lock()
	if q.current != nil && q.current.id == id {
		q.cancelRequested = true
		cancel := q.cancelCurrent
		q.mu.Unlock()
		cancel()
		return nil
	}
	for i, e := range q.pending {
		if e.id == id {
			q.pending = append(q.pending[:i:i], q.pending[i+1:]...)
			job := e.job
			q.mu.Unlock()
			q.publishCancelled(id, job)
			return nil
		}
	}
	q.mu.Unlock()
	return fmt.Errorf("%w: %s", ErrNotFound, id)
}

// publishCancelled runs the finalize hook and emits the "end" event for a
// job the queue never ran, through the same publish path a finished
// job's own end event takes.
func (q *Queue) publishCancelled(id string, job Job) {
	q.runFinalizer(id, job.Kind(), store.Cancelled)
	data, _ := json.Marshal(struct {
		State store.State `json:"state"`
	}{State: store.Cancelled})
	q.publish(Event{Kind: "end", Job: id, StoreID: storeIDOf(job), Data: data})
}

// Subscribe returns a channel of the current job's events, starting with a
// replay of what it already emitted, followed by live ones, and a function
// that stops delivery. Callers must call it to release the subscription.
//
// A subscriber that stops reading never blocks the worker: past its
// buffer, the queue drops events for it and sends one "log" event saying
// so instead of piling more up.
func (q *Queue) Subscribe() (<-chan Event, func()) {
	// subscriberHeadroom leaves room for at least one live event, and the
	// one "dropped events" notice deliverLocked sends about it, right after
	// a full replay: a channel sized to exactly replayLimit would already
	// be full at that point, and the notice would find no room either.
	const subscriberHeadroom = 2
	ch := make(chan Event, replayLimit+stepHeadroom+subscriberHeadroom)

	q.mu.Lock()
	id := q.nextSub
	q.nextSub++
	for _, e := range q.history {
		// history never holds more than replayLimit non-step entries, plus
		// stepHeadroom's worth of step ones (see appendHistoryLocked), so
		// this never hits the default case.
		select {
		case ch <- e:
		default:
		}
	}
	q.subs[id] = &subscriber{ch: ch}
	q.mu.Unlock()

	unsubscribe := func() {
		q.mu.Lock()
		delete(q.subs, id)
		q.mu.Unlock()
	}
	return ch, unsubscribe
}

// Close drains every queued job, cancels the running one, and waits for the
// worker to stop. It is safe to call more than once.
func (q *Queue) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		<-q.done
		return
	}
	q.closed = true
	q.pending = nil
	cancel := q.cancelCurrent
	q.cond.Signal()
	q.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	<-q.done
}

func (q *Queue) run() {
	defer close(q.done)
	for {
		q.mu.Lock()
		for len(q.pending) == 0 && !q.closed {
			q.cond.Wait()
		}
		if len(q.pending) == 0 && q.closed {
			q.mu.Unlock()
			return
		}
		next := q.pending[0]
		q.pending = q.pending[1:]
		ctx, cancel := context.WithCancel(context.Background())
		q.current = &next
		q.cancelCurrent = cancel
		q.cancelRequested = false
		q.history = nil
		q.mu.Unlock()

		q.log.Info("job started", "id", next.id, "kind", next.job.Kind())
		storeID := storeIDOf(next.job)
		emit := func(e Event) {
			e.Job = next.id
			e.StoreID = storeID
			q.publish(e)
		}
		err := runJob(ctx, q.log, next.job, emit)
		cancel()

		q.mu.Lock()
		state := store.Done
		switch {
		// cancelRequested alone would race a job that returns on its own
		// at the same moment Cancel is called: Cancel can still see this
		// job as current, and set the flag, in the window between Run
		// returning and this lock being taken. Requiring the job's own
		// error to be context.Canceled ties the state to what Run actually
		// did, not to that timing.
		case q.cancelRequested && errors.Is(err, context.Canceled):
			state = store.Cancelled
		case err != nil:
			state = store.Failed
		}
		q.mu.Unlock()

		// Called before the event below, and unlocked: a hook that
		// commits a directory or reconciles a status file must run
		// whether or not any subscriber is still keeping up, since
		// deliverLocked would otherwise drop the "end" event a
		// Subscribe-based caller would have relied on instead.
		q.runFinalizer(next.id, next.job.Kind(), state)

		q.mu.Lock()
		endData, _ := json.Marshal(struct {
			State store.State `json:"state"`
		}{State: state})
		endEvent := Event{Kind: "end", Job: next.id, StoreID: storeID, Data: endData}
		q.appendHistoryLocked(endEvent)
		for _, s := range q.subs {
			q.deliverLocked(s, endEvent)
		}
		q.current = nil
		q.cancelCurrent = nil
		// The queue is idle from here until the next job starts. Clearing
		// history in the same critical section that marks it idle, rather
		// than as a separate step after unlocking, keeps a subscriber that
		// connects right after from ever observing the two out of step: it
		// cannot land in a window where the queue already looks idle but
		// history still holds the event that just ended.
		q.history = nil
		q.mu.Unlock()

		q.log.Info("job finished", "id", next.id, "kind", next.job.Kind(), "state", state)
	}
}

// runJob runs job.Run and recovers a panic into a plain error, so one
// job's bug fails that job instead of taking the worker goroutine, and
// with it the whole server, down.
func runJob(ctx context.Context, log *slog.Logger, job Job, emit func(Event)) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("job panicked", "kind", job.Kind(), "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("jobs: %s panicked: %v", job.Kind(), r)
		}
	}()
	return job.Run(ctx, emit)
}

// publish records e in the replay history and delivers it to every current
// subscriber without blocking on any of them.
func (q *Queue) publish(e Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.appendHistoryLocked(e)
	for _, s := range q.subs {
		q.deliverLocked(s, e)
	}
}

// appendHistoryLocked appends e to q.history and trims it, called with
// q.mu held. Every "step" event is kept regardless of replayLimit: there
// are only a handful per job, and a subscriber that connects mid-run (a
// reloaded tab, or a late one) needs every one of them replayed to show
// the steps it missed as done instead of stuck on their upcoming dot.
// Only "log", "progress" and "candidate" events, which a long
// resolve-candidates run can emit far more of, are trimmed to the newest
// replayLimit among themselves.
func (q *Queue) appendHistoryLocked(e Event) {
	q.history = append(q.history, e)

	nonStep := 0
	for _, h := range q.history {
		if h.Kind != "step" {
			nonStep++
		}
	}
	drop := nonStep - replayLimit
	if drop <= 0 {
		return
	}
	trimmed := make([]Event, 0, len(q.history)-drop)
	for _, h := range q.history {
		if h.Kind != "step" && drop > 0 {
			drop--
			continue
		}
		trimmed = append(trimmed, h)
	}
	q.history = trimmed
}

// deliverLocked sends e to s, dropping it and noting the drop instead of
// blocking when s has stopped keeping up.
func (q *Queue) deliverLocked(s *subscriber, e Event) {
	select {
	case s.ch <- e:
		s.notified = false
		return
	default:
	}
	q.log.Warn("dropping event for a slow subscriber", "job", e.Job, "kind", e.Kind)
	if s.notified {
		return
	}
	notice := Event{
		Kind: "log",
		Job:  e.Job,
		Data: json.RawMessage(`{"line":"dropped events: a subscriber fell behind"}`),
	}
	select {
	case s.ch <- notice:
		s.notified = true
	default:
	}
}
