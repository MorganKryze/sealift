package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
)

type slowJob struct{ started chan struct{} }

func (j slowJob) Kind() string { return "analysis" }

func (j slowJob) Run(ctx context.Context, emit func(jobs.Event)) error {
	close(j.started)
	emit(jobs.Event{Kind: "step", Data: json.RawMessage(`{"name":"validate"}`)})
	<-ctx.Done()
	return ctx.Err()
}

var errContentType = errors.New("content type is not text/event-stream")

func TestRoutesHealth(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	rec := httptest.NewRecorder()
	Routes(q).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestRoutesEventStream(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	srv := httptest.NewServer(Routes(q))
	defer srv.Close()

	type result struct {
		line string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get(srv.URL + "/api/jobs/current/events")
		if err != nil {
			got <- result{err: err}
			return
		}
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			got <- result{err: errContentType}
			return
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data:") {
				got <- result{line: sc.Text()}
				return
			}
		}
		got <- result{err: sc.Err()}
	}()

	started := make(chan struct{})
	if _, err := q.Submit(slowJob{started: started}); err != nil {
		t.Fatal(err)
	}
	<-started

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if !strings.Contains(r.line, "validate") {
			t.Errorf("first event = %q", r.line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event reached the client while the job was still running")
	}
}
