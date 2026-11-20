package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/pip"
)

// fakeUv stands in for uv: it records each input and returns lock, set and
// err, or waits for the cancel when block is set.
type fakeUv struct {
	mu      sync.Mutex
	calls   []runner.CompileInput
	lock    string
	set     []runner.Resolved
	output  string
	err     error
	block   bool
	started chan struct{}
}

func (f *fakeUv) Compile(ctx context.Context, in runner.CompileInput) (runner.CompileResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	f.mu.Unlock()
	if f.block {
		close(f.started)
		<-ctx.Done()
		return runner.CompileResult{Output: "killed"}, ctx.Err()
	}
	if f.err != nil {
		return runner.CompileResult{Output: f.output}, f.err
	}
	return runner.CompileResult{Lock: []byte(f.lock), Set: f.set, Output: f.output}, nil
}

func (f *fakeUv) Calls() []runner.CompileInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// countingIndex answers 404 to everything and counts the requests.
type countingIndex struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func newCountingIndex(t *testing.T) *countingIndex {
	t.Helper()
	c := &countingIndex{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *countingIndex) URL() string { return c.srv.URL + "/simple/" }

// newPipAnalysis creates a pip project holding files, a tools manager that
// reads index and has uv 0.13.7 installed already, and the analysis to run.
func newPipAnalysis(t *testing.T, index string, target store.PipTarget, files ...store.RequirementsFile) (*PipAnalysis, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	proj, err := st.CreatePipProject("Data tools", files, target)
	if err != nil {
		t.Fatalf("CreatePipProject: %v", err)
	}
	pending, err := st.NewDir("analyses", proj.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	bin := filepath.Join(st.Root(), "tools", "uv", store.DefaultPipTarget.UvVer, "uv")
	if err := os.MkdirAll(filepath.Dir(bin), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	t.Cleanup(gh.Close)
	mgr := tools.NewManager(st, &http.Client{Timeout: 10 * time.Second}, nil)
	mgr.GitHubAPI = gh.URL
	mgr.PipIndex = index
	mgr.Arch = "amd64"
	return &PipAnalysis{
		Store:    st,
		Tools:    mgr,
		Uv:       &fakeUv{},
		Trivy:    &fakeTrivy{},
		Index:    &pip.Client{Index: index},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}, st
}

// resolved builds a resolution from name and version pairs.
func resolved(pairs ...string) []runner.Resolved {
	var set []runner.Resolved
	for i := 0; i+1 < len(pairs); i += 2 {
		set = append(set, runner.Resolved{Name: pairs[i], Version: pairs[i+1]})
	}
	return set
}

func reqFile(name, data string) store.RequirementsFile {
	return store.RequirementsFile{Name: name, Data: []byte(data)}
}

// readStatus reads the committed status.json both as statusFile and as raw
// keys.
func readStatus(t *testing.T, st *store.Store, a *PipAnalysis) (statusFile, map[string]json.RawMessage) {
	t.Helper()
	path := filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "status.json")
	var status statusFile
	if err := st.ReadJSON(path, &status); err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := st.ReadJSON(path, &raw); err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	return status, raw
}

func stepNames(steps []stepRecord) []string {
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.Name + ":" + s.State
	}
	return names
}

func TestPipAnalysisWritesTheLock(t *testing.T) {
	idx := newCountingIndex(t)
	a, st := newPipAnalysis(t, idx.URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "requests==2.32.3\n-c constraints.txt\n"),
		reqFile("constraints.txt", "idna==3.10\n"))
	lock := "certifi==2024.8.30\nidna==3.10\nrequests==2.32.3\n"
	uv := &fakeUv{lock: lock, set: resolved("certifi", "2024.8.30", "idna", "3.10", "requests", "2.32.3"), output: "Resolved 3 packages"}
	a.Uv = uv

	var events []Event
	before := time.Now().UTC()
	if err := a.Run(context.Background(), func(e Event) { events = append(events, e) }); err != nil {
		t.Fatalf("Run: %v", err)
	}

	final := strings.TrimSuffix(a.Dir, ".tmp")
	got, err := os.ReadFile(filepath.Join(final, "project", "requirements.lock"))
	if err != nil || string(got) != lock {
		t.Errorf("project/requirements.lock = %q (%v), want uv's lock", got, err)
	}
	for _, name := range []string{"requirements.txt", "constraints.txt"} {
		if _, err := os.Stat(filepath.Join(final, "requirements", name)); err != nil {
			t.Errorf("requirements/%s not copied: %v", name, err)
		}
	}

	status, raw := readStatus(t, st, a)
	if status.State != store.Done {
		t.Errorf("state = %q, want done", status.State)
	}
	if want := []string{"validate:done", "prepare-tools:done", "resolve:done"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Errorf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	if status.UvVersion != "0.13.7" {
		t.Errorf("uvVersion = %q, want 0.13.7", status.UvVersion)
	}
	if status.PipTarget == nil || *status.PipTarget != store.DefaultPipTarget {
		t.Errorf("pipTarget = %+v, want the project's target", status.PipTarget)
	}
	if _, ok := raw["target"]; ok {
		t.Errorf("status.json = %s, carries an npm target", raw["target"])
	}

	calls := uv.Calls()
	if len(calls) != 1 {
		t.Fatalf("uv ran %d times, want once", len(calls))
	}
	in := calls[0]
	if string(in.Requirements) != "requests==2.32.3\n" || string(in.Constraints) != "idna==3.10\n" {
		t.Errorf("uv input = %q and %q, want the requirement and the constraint", in.Requirements, in.Constraints)
	}
	if in.Target != store.DefaultPipTarget || in.Index != idx.URL() {
		t.Errorf("uv target and index = %+v %q", in.Target, in.Index)
	}
	if want := []string{"idna", "requests"}; !slices.Equal(in.Exempt, want) {
		t.Errorf("exempt = %v, want %v", in.Exempt, want)
	}
	if in.ExemptUntil.Before(before.Truncate(time.Second)) || in.ExemptUntil.After(time.Now()) {
		t.Errorf("exempt until %s, want the analysis start", in.ExemptUntil)
	}
	if age := in.ExemptUntil.Sub(in.ExcludeNewer); age != 14*24*time.Hour {
		t.Errorf("exclude newer is %s before the start, want the 14-day release age", age)
	}
	if want := filepath.Join(st.Root(), "tools", "uv", "0.13.7", "uv"); in.Bin != want {
		t.Errorf("uv binary = %q, want %q", in.Bin, want)
	}
	if !strings.HasPrefix(in.Dir, filepath.Join(st.Root(), "cache", "resolve")) {
		t.Errorf("resolve dir = %q, want one under cache/resolve", in.Dir)
	}
	if _, err := os.Stat(in.Dir); !os.IsNotExist(err) {
		t.Errorf("resolve dir still present: %v", err)
	}
	if !slices.ContainsFunc(events, func(e Event) bool { return e.Kind == "log" && strings.Contains(string(e.Data), "Resolved 3 packages") }) {
		t.Error("uv's output never reached the log")
	}
}

func TestPipAnalysisConflictNamesPackagesAndFiles(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "mypy-extensions==1.0.0\n"),
		reqFile("requirements-dev.txt", "mypy==1.11.2\n"))
	cause := "Because mypy==1.11.2 depends on mypy-extensions>=1.1.0 and you require mypy-extensions==1.0.0, we can conclude that your requirements are unsatisfiable."
	a.Uv = &fakeUv{output: "error: No solution found\n  cause: " + cause + "\n", err: errors.New("uv pip compile: No solution found: " + cause + ": exit status 1")}

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want the conflict")
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Failed || len(status.Steps) != 3 || status.Steps[2].Name != "resolve" {
		t.Fatalf("status = %+v, want resolve failed", status)
	}
	msg := status.Steps[2].Error
	for _, want := range []string{cause, "mypy (requirements-dev.txt)", "mypy-extensions (requirements.txt)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("resolve error = %q, want it to hold %q", msg, want)
		}
	}
	if _, err := os.Stat(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "project", "requirements.lock")); !os.IsNotExist(err) {
		t.Errorf("a failed resolve left a lock: %v", err)
	}
}

func TestPipAnalysisFetchesNothingBeforePrepareTools(t *testing.T) {
	idx := newCountingIndex(t)
	a, st := newPipAnalysis(t, idx.URL(), store.DefaultPipTarget, reqFile("requirements.txt", "flask>=3.0\n"))
	if err := os.RemoveAll(filepath.Join(st.Root(), "tools", "uv")); err != nil {
		t.Fatal(err)
	}
	uv := &fakeUv{}
	a.Uv = uv

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want the validation failure")
	}
	status, _ := readStatus(t, st, a)
	if want := []string{"validate:failed"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Errorf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	if msg := status.Steps[0].Error; !strings.Contains(msg, "requirements.txt line 1") || !strings.Contains(msg, "flask>=3.0") {
		t.Errorf("validate error = %q, want the file, line and text", msg)
	}
	if n := idx.hits.Load(); n != 0 {
		t.Errorf("the index got %d requests, want 0", n)
	}
	if n := len(uv.Calls()); n != 0 {
		t.Errorf("uv ran %d times, want 0", n)
	}
}

func TestPipAnalysisValidateNamesTheFirstThreeProblems(t *testing.T) {
	var logged []string
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "a>=1\nb>=1\nc>=1\nd>=1\n"))
	emit := func(e Event) {
		var d logData
		if e.Kind == "log" && json.Unmarshal(e.Data, &d) == nil {
			logged = append(logged, d.Line)
		}
	}
	if err := a.Run(context.Background(), emit); err == nil {
		t.Fatal("Run succeeded, want the validation failure")
	}
	status, _ := readStatus(t, st, a)
	msg := status.Steps[0].Error
	for _, want := range []string{"4 problems", "line 1", "line 2", "line 3"} {
		if !strings.Contains(msg, want) {
			t.Errorf("validate error = %q, want %q", msg, want)
		}
	}
	if strings.Contains(msg, "line 4") {
		t.Errorf("validate error = %q, names a fourth problem", msg)
	}
	for _, want := range []string{"a>=1", "b>=1", "c>=1", "d>=1"} {
		if !slices.ContainsFunc(logged, func(l string) bool { return strings.Contains(l, want) }) {
			t.Errorf("log = %v, misses %q", logged, want)
		}
	}
}

func TestPipAnalysisInstallsTheTargetsUv(t *testing.T) {
	const tag = "py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64"
	cases := []struct {
		name     string
		uploaded time.Time
		wantErr  string
	}{
		{"a month-old release installs", time.Now().Add(-30 * 24 * time.Hour), ""},
		{"a day-old release waits for force", time.Now().Add(-24 * time.Hour), "install it with force"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			ix.Add(piptest.Dist{
				Name: "uv", Version: "0.13.6", Tag: tag, Uploaded: c.uploaded,
				Payload: map[string][]byte{"uv-0.13.6.data/scripts/uv": []byte("#!/bin/sh\n")},
			})
			target := store.DefaultPipTarget
			target.UvVer = "0.13.6"
			a, st := newPipAnalysis(t, ix.URL, target, reqFile("requirements.txt", "requests==2.32.3\n"))
			uv := &fakeUv{lock: "requests==2.32.3\n", set: resolved("requests", "2.32.3")}
			a.Uv = uv

			err := a.Run(context.Background(), func(Event) {})
			if n := ix.Requests("/simple/uv/"); n != 1 {
				t.Errorf("the index served uv's page %d times, want once", n)
			}
			status, _ := readStatus(t, st, a)
			if c.wantErr != "" {
				if err == nil || len(status.Steps) != 2 || !strings.Contains(status.Steps[1].Error, c.wantErr) || !strings.Contains(status.Steps[1].Error, "uv 0.13.6") {
					t.Fatalf("Run = %v, steps %+v, want prepare-tools refusing uv 0.13.6 without force", err, status.Steps)
				}
				if status.UvVersion != "" {
					t.Errorf("uvVersion = %q, want none: uv never installed", status.UvVersion)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			want := filepath.Join(st.Root(), "tools", "uv", "0.13.6", "uv")
			if calls := uv.Calls(); len(calls) != 1 || calls[0].Bin != want {
				t.Errorf("uv calls = %+v, want one with %s", calls, want)
			}
			if status.UvVersion != "0.13.6" {
				t.Errorf("uvVersion = %q, want 0.13.6", status.UvVersion)
			}
		})
	}
}

func TestPipAnalysisRefusesAPinTheResolutionChanged(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		set     []runner.Resolved
		wantErr string
	}{
		{"another version", "requests==2.32.3\n", resolved("requests", "2.32.4"), "requests==2.32.3 (requirements.txt) came back as 2.32.4"},
		{"a pin left out", "requests==2.32.3\nidna==3.10\n", resolved("requests", "2.32.3"), "idna==3.10 (requirements.txt) is missing"},
		{"a constraint changed", "requests==2.32.3\n-c c.txt\n", resolved("idna", "3.9", "requests", "2.32.3"), "idna==3.10 (c.txt) came back as 3.9"},
		{"the same version written another way", "requests==2.32\n", resolved("requests", "2.32.0"), ""},
		{"a pin whose marker is false", "requests==2.32.3\nidna==3.10 ; python_version < \"3.8\"\n", resolved("requests", "2.32.3"), ""},
		{"a constraint nothing needs", "requests==2.32.3\n-c c.txt\n", resolved("requests", "2.32.3"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := []store.RequirementsFile{reqFile("requirements.txt", c.file)}
			if strings.Contains(c.file, "c.txt") {
				files = append(files, reqFile("c.txt", "idna==3.10\n"))
			}
			a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, files...)
			a.Uv = &fakeUv{lock: "x==1\n", set: c.set}

			err := a.Run(context.Background(), func(Event) {})
			status, _ := readStatus(t, st, a)
			lockPath := filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "project", "requirements.lock")
			if c.wantErr == "" {
				if err != nil || status.State != store.Done {
					t.Fatalf("Run = %v, state %q, want done", err, status.State)
				}
				return
			}
			if err == nil || status.State != store.Failed || !strings.Contains(status.Steps[len(status.Steps)-1].Error, c.wantErr) {
				t.Fatalf("Run = %v, steps %+v, want resolve failing with %q", err, status.Steps, c.wantErr)
			}
			if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
				t.Errorf("a refused resolution left a lock: %v", err)
			}
		})
	}
}

func TestPipAnalysisCancelled(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
	uv := &fakeUv{block: true, started: make(chan struct{})}
	a.Uv = uv

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, func(Event) {}) }()
	<-uv.started

	var running statusFile
	if err := st.ReadJSON(filepath.Join(a.Dir, "status.json"), &running); err != nil || running.State != store.Running {
		t.Fatalf("status.json while resolving = %+v (%v), want running", running, err)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("Run returned nil, want the cancellation")
	}

	if _, err := os.Stat(a.Dir); !os.IsNotExist(err) {
		t.Errorf(".tmp directory still present: %v", err)
	}
	final := strings.TrimSuffix(a.Dir, ".tmp")
	if _, err := os.Stat(filepath.Join(final, "log.txt")); err != nil {
		t.Errorf("log.txt missing from the committed directory: %v", err)
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Cancelled {
		t.Errorf("state = %q, want cancelled", status.State)
	}
	if want := []string{"validate:done", "prepare-tools:done", "resolve:cancelled"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Errorf("steps = %v, want %v", stepNames(status.Steps), want)
	}
}

func TestPipAnalysisKind(t *testing.T) {
	a := &PipAnalysis{ID: "20261120T100000Z"}
	if a.Kind() != "analysis" || a.StoreID() != "20261120T100000Z" {
		t.Errorf("Kind, StoreID = %q, %q", a.Kind(), a.StoreID())
	}
}
