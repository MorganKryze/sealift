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
func waitIdle(t *testing.T, q *Queue, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, _, _, ok := q.Current(); !ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("queue did not go idle in time")
}

func waitRunning(t *testing.T, q *Queue, id string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cur, _, _, ok := q.Current(); ok && cur == id {
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

	waitRunning(t, q, id1, time.Second)

	select {
	case <-job2.started:
		t.Fatal("job2 started while job1 was still running")
	default:
	}

	close(release1)
	waitIdle(t, q, time.Second)

	select {
	case <-job2.started:
	default:
		t.Fatal("job2 never started after job1 finished")
	}
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
	waitRunning(t, q, id1, time.Second)

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

	waitIdle(t, q, time.Second)

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
	waitIdle(t, q, time.Second)
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
	waitRunning(t, q, id1, time.Second)

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
