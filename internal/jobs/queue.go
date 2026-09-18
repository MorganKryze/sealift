// Package jobs runs analysis and export jobs one at a time and streams
// their events to the interface.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/MorganKryze/sealift/internal/store"
)

// replayLimit bounds how many of a job's past events a new subscriber
// replays, and doubles as each subscriber channel's buffer size, so a full
// replay into a fresh channel never hits the drop path below.
const replayLimit = 128

// ErrNotFound reports a Cancel call naming a job the queue does not hold,
// neither running nor queued.
var ErrNotFound = errors.New("jobs: job not found")

// ErrClosed reports a Submit call reaching a closed queue.
var ErrClosed = errors.New("jobs: queue is closed")

// Event is one message a job emits while it runs, or the queue emits about
// it. Kind is one of "step", "progress", "candidate", "log" or "end".
type Event struct {
	Kind string          `json:"kind"`
	Job  string          `json:"job"`
	Data json.RawMessage `json:"data"`
}

// Job is a unit of work the queue runs to completion before starting the
// next one. Run must return once ctx is done. Run must not emit its own
// "end" event: the queue appends exactly one, with the state it computed,
// once Run returns.
type Job interface {
	Kind() string
	Run(ctx context.Context, emit func(Event)) error
}

type entry struct {
	id  string
	job Job
}

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
	state           store.State
	history         []Event

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

// Submit queues j to run once every earlier job has finished, fifo, and
// returns the id later calls use to name it.
func (q *Queue) Submit(j Job) (id string, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return "", ErrClosed
	}
	q.nextID++
	id = fmt.Sprintf("%s-%d", j.Kind(), q.nextID)
	q.pending = append(q.pending, entry{id: id, job: j})
	q.cond.Signal()
	return id, nil
}

// Current reports the running job, if any. ok is false while the queue is
// idle, even with jobs still waiting.
func (q *Queue) Current() (id, kind string, state store.State, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.current == nil {
		return "", "", "", false
	}
	return q.current.id, q.current.job.Kind(), q.state, true
}

// Cancel stops the running job by id, or drops a queued one before it
// starts. It returns ErrNotFound when id names neither.
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
			q.mu.Unlock()
			return nil
		}
	}
	q.mu.Unlock()
	return fmt.Errorf("%w: %s", ErrNotFound, id)
}

// Subscribe returns a channel of the current job's events, starting with a
// replay of what it already emitted, followed by live ones, and a function
// that stops delivery. Callers must call it to release the subscription.
//
// A subscriber that stops reading never blocks the worker: past its
// buffer, the queue drops events for it and sends one "log" event saying
// so instead of piling more up.
func (q *Queue) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, replayLimit)

	q.mu.Lock()
	id := q.nextSub
	q.nextSub++
	for _, e := range q.history {
		// history never holds more than replayLimit entries (see
		// appendHistoryLocked), so this never hits the default case.
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
		q.state = store.Running
		q.history = nil
		q.mu.Unlock()

		q.log.Info("job started", "id", next.id, "kind", next.job.Kind())
		emit := func(e Event) {
			e.Job = next.id
			q.publish(e)
		}
		err := next.job.Run(ctx, emit)
		cancel()

		q.mu.Lock()
		state := store.Done
		switch {
		case q.cancelRequested:
			state = store.Cancelled
		case err != nil:
			state = store.Failed
		}
		q.current = nil
		q.cancelCurrent = nil
		q.mu.Unlock()

		q.log.Info("job finished", "id", next.id, "kind", next.job.Kind(), "state", state)
		endData, _ := json.Marshal(struct {
			State store.State `json:"state"`
		}{State: state})
		q.publish(Event{Kind: "end", Job: next.id, Data: endData})
	}
}

// publish records e in the replay history and delivers it to every current
// subscriber without blocking on any of them.
func (q *Queue) publish(e Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.history = append(q.history, e)
	if len(q.history) > replayLimit {
		q.history = q.history[len(q.history)-replayLimit:]
	}
	for _, s := range q.subs {
		q.deliverLocked(s, e)
	}
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
