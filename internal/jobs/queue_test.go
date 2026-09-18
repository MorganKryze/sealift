package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// fakeJob is a Job whose behavior a test controls through run, and whose
// start a test can observe through started.
type fakeJob struct {
	kind    string
	run     func(ctx context.Context, emit func(Event)) error
	started chan struct{}
}

func (f *fakeJob) Kind() string { return f.kind }

func (f *fakeJob) Run(ctx context.Context, emit func(Event)) error {
	if f.started != nil {
		close(f.started)
	}
	return f.run(ctx, emit)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitIdle polls Current until no job is running, or fails the test after
// timeout. Jobs in these tests finish in microseconds; the timeout only
// catches a genuine deadlock.
func waitIdle(t *testing.T, q *Queue) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := q.Current(); !ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("queue did not go idle in time")
}

func waitRunning(t *testing.T, q *Queue, id string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if cur, _, ok := q.Current(); ok && cur == id {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job %s did not become current in time", id)
}

func TestQueue_FIFOOrder(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	var mu sync.Mutex
	var order []string
	record := func(name string) func(ctx context.Context, emit func(Event)) error {
		return func(_ context.Context, _ func(Event)) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}
	}

	for _, name := range []string{"a", "b", "c"} {
		if _, err := q.Submit(&fakeJob{kind: "fake", run: record(name)}); err != nil {
			t.Fatalf("Submit(%s): %v", name, err)
		}
	}

	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		n := len(order)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the three jobs did not all run in time")
		}
		time.Sleep(time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if got, want := order, []string{"a", "b", "c"}; !equalStrings(got, want) {
		t.Fatalf("run order = %v, want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestQueue_OneAtATime(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	release1 := make(chan struct{})
	job1 := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error {
		<-release1
		return nil
	}}
	job2 := &fakeJob{kind: "fake", started: make(chan struct{}), run: func(_ context.Context, _ func(Event)) error {
		return nil
	}}

	id1, err := q.Submit(job1)
	if err != nil {
		t.Fatalf("Submit(job1): %v", err)
	}
	if _, err := q.Submit(job2); err != nil {
		t.Fatalf("Submit(job2): %v", err)
	}

	waitRunning(t, q, id1)

	select {
	case <-job2.started:
		t.Fatal("job2 started while job1 was still running")
	default:
	}

	close(release1)

	// Waiting for the queue to look idle is not enough: it reports no
	// current job in the window between one job ending and the worker
	// picking up the next one, so job2 may not have started yet.
	select {
	case <-job2.started:
	case <-time.After(2 * time.Second):
		t.Fatal("job2 never started after job1 finished")
	}
	waitIdle(t, q)
}

func TestQueue_CancelRunningAndQueued(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	events, unsubscribe := q.Subscribe()
	defer unsubscribe()

	job1 := &fakeJob{kind: "fake", run: func(ctx context.Context, _ func(Event)) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	job2 := &fakeJob{kind: "fake", started: make(chan struct{}), run: func(_ context.Context, _ func(Event)) error {
		return nil
	}}

	id1, err := q.Submit(job1)
	if err != nil {
		t.Fatalf("Submit(job1): %v", err)
	}
	waitRunning(t, q, id1)

	id2, err := q.Submit(job2)
	if err != nil {
		t.Fatalf("Submit(job2): %v", err)
	}

	if err := q.Cancel(id2); err != nil {
		t.Fatalf("Cancel(queued job2): %v", err)
	}
	if err := q.Cancel(id1); err != nil {
		t.Fatalf("Cancel(running job1): %v", err)
	}

	waitIdle(t, q)

	select {
	case <-job2.started:
		t.Fatal("job2 ran after its cancel dropped it from the queue")
	default:
	}

	var last Event
	found := false
	for {
		select {
		case e := <-events:
			last = e
			found = true
		case <-time.After(50 * time.Millisecond):
			goto checked
		}
	}
checked:
	if !found {
		t.Fatal("subscriber saw no events for the cancelled job")
	}
	if last.Kind != "end" {
		t.Fatalf("last event kind = %q, want %q", last.Kind, "end")
	}
	var data struct{ State store.State }
	if err := json.Unmarshal(last.Data, &data); err != nil {
		t.Fatalf("unmarshal end data: %v", err)
	}
	if data.State != store.Cancelled {
		t.Fatalf("end state = %q, want %q", data.State, store.Cancelled)
	}
}

func TestQueue_CancelQueuedJobEmitsEndEvent(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	events, unsubscribe := q.Subscribe()
	defer unsubscribe()

	release := make(chan struct{})
	job1 := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error {
		<-release
		return nil
	}}
	job2 := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error { return nil }}

	id1, err := q.Submit(job1)
	if err != nil {
		t.Fatalf("Submit(job1): %v", err)
	}
	waitRunning(t, q, id1)

	id2, err := q.Submit(job2)
	if err != nil {
		t.Fatalf("Submit(job2): %v", err)
	}
	if err := q.Cancel(id2); err != nil {
		t.Fatalf("Cancel(queued job2): %v", err)
	}
	close(release)
	waitIdle(t, q)

	var sawQueuedCancel bool
	deadline := time.After(time.Second)
	for !sawQueuedCancel {
		select {
		case e := <-events:
			if e.Job == id2 {
				if e.Kind != "end" {
					t.Fatalf("job2 event kind = %q, want %q", e.Kind, "end")
				}
				var data struct{ State store.State }
				if err := json.Unmarshal(e.Data, &data); err != nil {
					t.Fatalf("unmarshal end data: %v", err)
				}
				if data.State != store.Cancelled {
					t.Fatalf("job2 end state = %q, want %q", data.State, store.Cancelled)
				}
				sawQueuedCancel = true
			}
		case <-deadline:
			t.Fatal("never saw an end event for the queued, cancelled job2")
		}
	}
}

func TestQueue_CancelAfterJobReturnsNilDoesNotReportCancelled(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	finished := make(chan struct{})
	job := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error {
		defer close(finished)
		return nil // finishes on its own, unrelated to any cancel
	}}
	id, err := q.Submit(job)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// Waiting on finished, not just on waitIdle, proves the job actually
	// ran: idle alone cannot tell "already finished" apart from "never
	// picked up yet", which is also reported as idle.
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("job never ran")
	}
	waitIdle(t, q)

	// The job is long gone by now; Cancel must report that, not mark a
	// finished job cancelled just because a caller asked after the fact.
	if err := q.Cancel(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Cancel(finished job) = %v, want ErrNotFound", err)
	}
}

func TestQueue_SubscribeAfterJobEndsGetsNoStaleReplay(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	finished := make(chan struct{})
	job := &fakeJob{kind: "fake", run: func(_ context.Context, emit func(Event)) error {
		defer close(finished)
		emit(Event{Kind: "step", Data: json.RawMessage(`{"name":"resolve"}`)})
		return nil
	}}
	id, err := q.Submit(job)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("job never ran")
	}
	waitIdle(t, q)

	// A subscriber connecting once the queue is idle again must not replay
	// the finished job's own "end" event: that would close its stream at
	// once, as if the job it is about to watch had already finished.
	events, unsubscribe := q.Subscribe()
	defer unsubscribe()

	select {
	case e := <-events:
		t.Fatalf("subscriber after the queue went idle got a stale replayed event: %+v (job %s already ended)", e, id)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestQueue_PanickingJobFailsInsteadOfCrashing(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	events, unsubscribe := q.Subscribe()
	defer unsubscribe()

	job := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error {
		panic("boom")
	}}
	if _, err := q.Submit(job); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitIdle(t, q)

	var last Event
	found := false
	deadline := time.After(time.Second)
	for !found {
		select {
		case e := <-events:
			last = e
			found = e.Kind == "end"
		case <-deadline:
			t.Fatal("never saw an end event for the panicking job")
		}
	}
	var data struct{ State store.State }
	if err := json.Unmarshal(last.Data, &data); err != nil {
		t.Fatalf("unmarshal end data: %v", err)
	}
	if data.State != store.Failed {
		t.Fatalf("end state = %q, want %q", data.State, store.Failed)
	}

	// The worker survived: a second job still runs.
	second := &fakeJob{kind: "fake", started: make(chan struct{}), run: func(_ context.Context, _ func(Event)) error {
		return nil
	}}
	if _, err := q.Submit(second); err != nil {
		t.Fatalf("Submit(second): %v", err)
	}
	select {
	case <-second.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not survive the panic: the second job never started")
	}
}

func TestQueue_CancelUnknownID(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	err := q.Cancel("does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Cancel(unknown) = %v, want ErrNotFound", err)
	}
}

func TestQueue_EndAlwaysLast(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	events, unsubscribe := q.Subscribe()
	defer unsubscribe()

	job := &fakeJob{kind: "fake", run: func(_ context.Context, emit func(Event)) error {
		emit(Event{Kind: "step", Data: json.RawMessage(`{"name":"resolve"}`)})
		emit(Event{Kind: "progress", Data: json.RawMessage(`{"done":1,"total":2}`)})
		emit(Event{Kind: "log", Data: json.RawMessage(`{"line":"hi"}`)})
		return nil
	}}
	if _, err := q.Submit(job); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	var got []Event
	deadline := time.After(time.Second)
	for len(got) < 4 {
		select {
		case e := <-events:
			got = append(got, e)
		case <-deadline:
			t.Fatalf("only got %d events, want 4", len(got))
		}
	}

	kinds := make([]string, len(got))
	for i, e := range got {
		kinds[i] = e.Kind
	}
	if kinds[len(kinds)-1] != "end" {
		t.Fatalf("event kinds = %v, last is not end", kinds)
	}
	for _, k := range kinds[:len(kinds)-1] {
		if k == "end" {
			t.Fatalf("event kinds = %v, end appeared before the last position", kinds)
		}
	}
}

func TestQueue_SlowSubscriberNeverBlocksWorker(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	// Subscribe but never read: every send to this subscriber must find
	// its buffer full soon and get dropped instead of stalling publish,
	// which runs on the worker goroutine.
	_, unsubscribe := q.Subscribe()
	defer unsubscribe()

	const eventCount = 500
	finished := make(chan struct{})
	job := &fakeJob{kind: "fake", run: func(_ context.Context, emit func(Event)) error {
		for i := 0; i < eventCount; i++ {
			emit(Event{Kind: "log", Data: json.RawMessage(`{"line":"x"}`)})
		}
		close(finished)
		return nil
	}}

	start := time.Now()
	if _, err := q.Submit(job); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	select {
	case <-finished:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("job with an unread subscriber never finished emitting, worker looks blocked")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("job with an unread subscriber took %v, worker looks blocked", elapsed)
	}
	waitIdle(t, q)
}

// TestQueue_FinalizerRunsBeforeEndAndSurvivesAnOverflowedSubscriber
// proves SetFinalizer's hook runs synchronously, exactly once, with the
// job's own id, kind and terminal state, and that flooding a
// subscriber's buffer well past capacity, which makes deliverLocked drop
// events (its own "end" event included), never stops the hook from
// running: unlike a Subscribe channel, it is not something the queue can
// drop.
func TestQueue_FinalizerRunsBeforeEndAndSurvivesAnOverflowedSubscriber(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	var mu sync.Mutex
	var calls []FinalizeInfo
	q.SetFinalizer(func(info FinalizeInfo) error {
		mu.Lock()
		calls = append(calls, info)
		mu.Unlock()
		return nil
	})

	// Never read: past its buffer, deliverLocked drops every event for
	// this subscriber, "end" included.
	_, unsubscribe := q.Subscribe()
	defer unsubscribe()

	const eventCount = 500
	finished := make(chan struct{})
	job := &fakeJob{kind: "fake", run: func(_ context.Context, emit func(Event)) error {
		for i := 0; i < eventCount; i++ {
			emit(Event{Kind: "log", Data: json.RawMessage(`{"line":"x"}`)})
		}
		close(finished)
		return nil
	}}
	id, err := q.Submit(job)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// Wait for the job to have actually run, not just for Current to look
	// idle: called too early, that check cannot tell "never started" apart
	// from "already finalized".
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("job never ran")
	}
	waitIdle(t, q)

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("finalize calls = %+v, want exactly 1", calls)
	}
	if calls[0].ID != id || calls[0].Kind != "fake" || calls[0].State != store.Done {
		t.Errorf("finalize call = %+v, want {%q, fake, done}", calls[0], id)
	}
}

// TestQueue_FinalizerRunsForACancelledQueuedJob proves the finalize hook
// also runs for a job the queue drops before it ever starts, through the
// same Cancel path that publishes its "end" event.
func TestQueue_FinalizerRunsForACancelledQueuedJob(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()

	var mu sync.Mutex
	var calls []FinalizeInfo
	q.SetFinalizer(func(info FinalizeInfo) error {
		mu.Lock()
		calls = append(calls, info)
		mu.Unlock()
		return nil
	})

	release := make(chan struct{})
	job1 := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error {
		<-release
		return nil
	}}
	job2 := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error { return nil }}

	id1, err := q.Submit(job1)
	if err != nil {
		t.Fatalf("Submit(job1): %v", err)
	}
	waitRunning(t, q, id1)

	id2, err := q.Submit(job2)
	if err != nil {
		t.Fatalf("Submit(job2): %v", err)
	}
	if err := q.Cancel(id2); err != nil {
		t.Fatalf("Cancel(queued job2): %v", err)
	}
	close(release)
	waitIdle(t, q)

	mu.Lock()
	defer mu.Unlock()
	for _, c := range calls {
		if c.ID == id2 {
			if c.State != store.Cancelled {
				t.Errorf("finalize call for %s = %+v, want state cancelled", id2, c)
			}
			return
		}
	}
	t.Fatalf("finalize calls = %+v, want one naming %s", calls, id2)
}

// TestQueue_FinalizerErrorIsLoggedNotFatal proves a hook's own error never
// takes the worker down: the queue cannot undo a job that already ran,
// so SetFinalizer's contract is to log the error and carry on.
func TestQueue_FinalizerErrorIsLoggedNotFatal(t *testing.T) {
	q := NewQueue(testLogger())
	defer q.Close()
	q.SetFinalizer(func(FinalizeInfo) error { return errors.New("boom") })

	job1 := &fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error { return nil }}
	if _, err := q.Submit(job1); err != nil {
		t.Fatalf("Submit(job1): %v", err)
	}
	waitIdle(t, q)

	job2 := &fakeJob{kind: "fake", started: make(chan struct{}), run: func(_ context.Context, _ func(Event)) error { return nil }}
	if _, err := q.Submit(job2); err != nil {
		t.Fatalf("Submit(job2): %v", err)
	}
	select {
	case <-job2.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not survive a finalize error: job2 never started")
	}
}

func TestQueue_CloseDrains(t *testing.T) {
	q := NewQueue(testLogger())

	canceled := make(chan struct{})
	job1 := &fakeJob{kind: "fake", run: func(ctx context.Context, _ func(Event)) error {
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	}}
	job2 := &fakeJob{kind: "fake", started: make(chan struct{}), run: func(_ context.Context, _ func(Event)) error {
		return nil
	}}

	id1, err := q.Submit(job1)
	if err != nil {
		t.Fatalf("Submit(job1): %v", err)
	}
	waitRunning(t, q, id1)

	if _, err := q.Submit(job2); err != nil {
		t.Fatalf("Submit(job2): %v", err)
	}

	closed := make(chan struct{})
	go func() {
		q.Close()
		close(closed)
	}()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return in time")
	}

	select {
	case <-canceled:
	default:
		t.Fatal("Close did not cancel the running job")
	}
	select {
	case <-job2.started:
		t.Fatal("Close let a drained, queued job run")
	default:
	}

	if _, err := q.Submit(&fakeJob{kind: "fake", run: func(_ context.Context, _ func(Event)) error { return nil }}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Submit after Close = %v, want ErrClosed", err)
	}

	// Close is safe to call again.
	q.Close()
}
