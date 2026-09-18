package api

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// fakeSubscriptions hands out a single fixed channel, so a test can drive
// exactly what the handler streams without running a real jobs.Queue.
type fakeSubscriptions struct {
	ch chan jobs.Event
}

func (f fakeSubscriptions) Subscribe() (<-chan jobs.Event, func()) {
	return f.ch, func() {}
}

// safeClose closes ch at most once, so a test can close it early on the
// happy path and still register an unconditional cleanup without a
// double-close panic.
func safeClose(ch chan jobs.Event) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

func newEventsServer(t *testing.T, ch chan jobs.Event) (*httptest.Server, func()) {
	t.Helper()
	h := &EventsHandler{Jobs: fakeSubscriptions{ch: ch}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/jobs/current/events", func(w http.ResponseWriter, r *http.Request) {
		resp, err := h.WatchJob(r.Context(), WatchJobRequestObject{})
		if err != nil {
			t.Errorf("WatchJob: %v", err)
			return
		}
		if err := resp.VisitWatchJobResponse(w); err != nil {
			t.Errorf("VisitWatchJobResponse: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	closeCh := safeClose(ch)
	t.Cleanup(srv.Close)
	t.Cleanup(closeCh)
	return srv, closeCh
}

// getResult carries an async http.Get outcome back to the test goroutine,
// so the test can keep driving the fake queue's channel while the request
// is in flight. The server does not flush headers until the handler's
// first write, so a plain synchronous http.Get here would deadlock: it
// would wait for data that only a later line of the same goroutine sends.
type getResult struct {
	resp *http.Response
	err  error
}

func getAsync(url string) <-chan getResult {
	out := make(chan getResult, 1)
	go func() {
		resp, err := http.Get(url)
		out <- getResult{resp: resp, err: err}
	}()
	return out
}

func TestEventsHandler_ContentType(t *testing.T) {
	ch := make(chan jobs.Event, 4)
	srv, closeCh := newEventsServer(t, ch)

	resultCh := getAsync(srv.URL + "/api/jobs/current/events")
	ch <- jobs.Event{Kind: "step", Job: "job-1", Data: json.RawMessage(`{"name":"resolve"}`)}
	closeCh()

	var result getResult
	select {
	case result = <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the response")
	}
	if result.err != nil {
		t.Fatalf("GET: %v", result.err)
	}
	defer result.resp.Body.Close()

	if got := result.resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want %q", got, "text/event-stream")
	}
	if _, err := io.Copy(io.Discard, result.resp.Body); err != nil {
		t.Fatalf("draining the response body: %v", err)
	}
}

func TestEventsHandler_StreamsBeforeJobEnds(t *testing.T) {
	ch := make(chan jobs.Event, 4)
	srv, closeCh := newEventsServer(t, ch)

	resultCh := getAsync(srv.URL + "/api/jobs/current/events")

	start := time.Now()
	ch <- jobs.Event{Kind: "step", Job: "job-1", Data: json.RawMessage(`{"name":"resolve"}`)}

	// The job has not ended yet at this point: only the first event has
	// been sent. A handler that buffers the whole stream instead of
	// flushing per event would only deliver this response once the "end"
	// event below is sent and the channel closes; it is neither yet.
	var result getResult
	select {
	case result = <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the response; the job had not ended yet")
	}
	if result.err != nil {
		t.Fatalf("GET: %v", result.err)
	}
	resp := result.resp
	defer resp.Body.Close()

	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("the response took %v to arrive, looks buffered", elapsed)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want %q", got, "text/event-stream")
	}

	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the first SSE line: %v", err)
	}
	if !strings.HasPrefix(line, "event: step") {
		t.Fatalf("first line = %q, want it to start with %q", line, "event: step")
	}

	// Only now does the job end.
	ch <- jobs.Event{Kind: "end", Job: "job-1", Data: json.RawMessage(`{"state":"done"}`)}
	closeCh()

	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading the rest of the stream: %v", err)
	}
	if !strings.Contains(string(rest), "event: end") {
		t.Fatalf("stream tail = %q, want it to contain the end event", rest)
	}
}
