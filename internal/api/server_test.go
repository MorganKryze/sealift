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
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
)

// fakeTrivy is a runner.Trivy that never touches a real binary, for tests
// that only need the router to be reachable, not real scan results.
type fakeTrivy struct{}

func (fakeTrivy) ScanSBOM(context.Context, string, string) (string, error) { return "", nil }
func (fakeTrivy) ConvertToCycloneDX(context.Context, string, string) (string, error) {
	return "", nil
}
func (fakeTrivy) UpdateDB(context.Context) (string, error) { return "", nil }

// fakePnpm is a runner.Pnpm that never touches a real binary.
type fakePnpm struct{}

func (fakePnpm) Resolve(context.Context, runner.ResolveInput) (runner.ResolveResult, error) {
	return runner.ResolveResult{}, nil
}

// unroutable is a loopback address nothing listens on, so a request to it
// fails immediately with connection refused instead of a slow real
// network round trip or a timeout.
const unroutable = "http://127.0.0.1:1"

// newTestHandlers builds Handlers against a fresh temporary store, and a
// tools.Manager pointed at addresses nothing answers, so a test that
// exercises GetTools or an analysis' own tool preparation step never
// waits on or depends on the real network (conventions.md: no network in
// a unit test). Pnpm and Trivy runs themselves go through fakes.
func newTestHandlers(t *testing.T, q *jobs.Queue) *Handlers {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	tm.GitHubAPI = unroutable
	tm.NPMRegistry = unroutable
	svc := jobs.NewService(st, q, tm, fakePnpm{}, fakeTrivy{}, &npm.Client{})
	return NewHandlers(st, q, svc, tm, fakeTrivy{})
}

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
	Routes(newTestHandlers(t, q)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
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
	srv := httptest.NewServer(Routes(newTestHandlers(t, q)))
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
