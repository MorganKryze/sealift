package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// TestRunServesHealthAndStopsOnSignal starts the real wiring on a free port,
// so a broken store, queue or route shows up here rather than in the image.
func TestRunServesHealthAndStopsOnSignal(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "data")
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health check never answered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if _, statErr := os.Stat(filepath.Join(root, "private", "settings.json")); statErr != nil {
		t.Errorf("settings file: %v", statErr)
	}

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
}

// blockingJob emits one "step" event, signals started, then blocks until
// ctx is canceled, standing in for a real analysis or export job whose
// event stream would otherwise stay open for as long as the job runs.
type blockingJob struct{ started chan struct{} }

func (j *blockingJob) Kind() string { return "test" }

func (j *blockingJob) Run(ctx context.Context, emit func(jobs.Event)) error {
	emit(jobs.Event{Kind: "step", Data: json.RawMessage(`{}`)})
	close(j.started)
	<-ctx.Done()
	return ctx.Err()
}

// TestRunCancelsRunningJobBeforeShuttingDownServer proves shutdown does not
// wait out its own timeout on a job's event stream: with a subscriber
// connected to a running job when the signal arrives, run must cancel that
// job before shutting the server down, so the connection goes idle quickly
// and run returns well under the 10 second shutdown timeout.
func TestRunCancelsRunningJobBeforeShuttingDownServer(t *testing.T) {
	started := make(chan struct{})
	onQueueReady = func(q *jobs.Queue) {
		if _, err := q.Submit(&blockingJob{started: started}); err != nil {
			t.Errorf("submit: %v", err)
		}
	}
	defer func() { onQueueReady = nil }()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "data")
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	// Keep-alives off: a pooled idle connection left open by this client
	// would sit outside any request and make the server's own shutdown
	// wait on it, which has nothing to do with what this test checks.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = client.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health check never answered: %v", err)
	}
	resp.Body.Close()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job never started")
	}

	// The subscriber's first Read only returns once the job's "step" event
	// is flushed, so this connection is genuinely established (not just
	// accepted) by the time the signal below arrives.
	streamResp, err := client.Get("http://" + addr + "/api/jobs/current/events")
	if err != nil {
		t.Fatalf("subscribe to event stream: %v", err)
	}
	defer streamResp.Body.Close()

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return well under the 10 second shutdown timeout")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("run took %v to return, want it well under the shutdown timeout", elapsed)
	}
}
