package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/pip"
	"github.com/MorganKryze/sealift/rank"
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

// released is an upload time older than any minimum release age the
// settings allow, so a wheel uploaded then counts for any package.
var released = time.Date(2024, time.September, 1, 0, 0, 0, 0, time.UTC)

// serveWheels points a at a fake index that publishes one py3-none-any
// wheel, uploaded on released, for every pin of the project's files and
// every package of set, so check-pins and choose-wheels find a wheel for
// each.
func serveWheels(t *testing.T, a *PipAnalysis, set []runner.Resolved) *piptest.Index {
	t.Helper()
	stored, err := a.Store.ProjectRequirements(a.Project.ID)
	if err != nil {
		t.Fatalf("ProjectRequirements: %v", err)
	}
	files := make([]pip.File, len(stored))
	for i, f := range stored {
		files[i] = pip.File{Name: f.Name, Data: f.Data}
	}
	parsed, _ := pip.ParseFiles(files)
	pkgs := slices.Clone(set)
	for _, p := range slices.Concat(parsed.Requirements, parsed.Constraints) {
		pkgs = append(pkgs, runner.Resolved{Name: p.Key, Version: p.Version})
	}
	ix := piptest.NewIndex(t)
	published := map[string][]string{}
	for _, p := range pkgs {
		key := pip.Normalize(p.Name)
		if slices.ContainsFunc(published[key], func(v string) bool { return pip.SameVersion(v, p.Version) }) {
			continue
		}
		published[key] = append(published[key], p.Version)
		ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
	}
	a.Index = &pip.Client{Index: ix.URL}
	return ix
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
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "requests==2.32.3\n-c constraints.txt\n"),
		reqFile("constraints.txt", "idna==3.10\n"))
	lock := "certifi==2024.8.30\nidna==3.10\nrequests==2.32.3\n"
	uv := &fakeUv{lock: lock, set: resolved("certifi", "2024.8.30", "idna", "3.10", "requests", "2.32.3"), output: "Resolved 3 packages"}
	a.Uv = uv
	ix := serveWheels(t, a, uv.set)

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
	if want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:done", "choose-wheels:done", "scan:done"}; !slices.Equal(stepNames(status.Steps), want) {
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
	if in.Target != store.DefaultPipTarget || in.Index != ix.URL {
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
	serveWheels(t, a, nil)

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want the conflict")
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Failed || len(status.Steps) != 4 || status.Steps[3].Name != "resolve" {
		t.Fatalf("status = %+v, want resolve failed", status)
	}
	msg := status.Steps[3].Error
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
		{"a day-old release is refused until it ages", time.Now().Add(-24 * time.Hour), "pin an older uv"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			ix.Add(piptest.Dist{
				Name: "uv", Version: "0.13.6", Tag: tag, Uploaded: c.uploaded,
				Payload: map[string][]byte{"uv-0.13.6.data/scripts/uv": []byte("#!/bin/sh\n")},
			})
			ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
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
					t.Fatalf("Run = %v, steps %+v, want prepare-tools refusing uv 0.13.6", err, status.Steps)
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
		{"a package another pin needs, under a pin whose marker is false", "zeta==1.0.0\ngamma==1.0.0 ; python_version < \"3.8\"\n", resolved("gamma", "1.1.0", "zeta", "1.0.0"), ""},
		{"a pin whose marker is true", "zeta==1.0.0\ngamma==1.0.0 ; python_version >= \"3.8\"\n", resolved("gamma", "1.1.0", "zeta", "1.0.0"), "gamma==1.0.0 (requirements.txt) came back as 1.1.0"},
		{"a pin whose marker sealift cannot decide", "zeta==1.0.0\ngamma==1.0.0 ; platform_release >= \"5\"\n", resolved("gamma", "1.1.0", "zeta", "1.0.0"), "gamma==1.0.0 (requirements.txt) came back as 1.1.0"},
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
			serveWheels(t, a, c.set)

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

// A pin whose marker is false on the target fixes no version, so its
// package stays held to the release age. A marker sealift cannot decide
// keeps its pin exempt, as uv may hold that pin.
func TestPipAnalysisExemptsOnlyThePinsTheTargetInstalls(t *testing.T) {
	var logged []string
	a, _ := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "zeta==1.0.0\n"+
			"gamma==1.0.0 ; python_version < \"3.8\"\n"+
			"delta==2.0.0 ; sys_platform == \"linux\"\n"+
			"eps==1.0.0 ; platform_release >= \"5\"\n"+
			"-c c.txt\n"),
		reqFile("c.txt", "idna==3.10 ; os_name == \"nt\"\nchardet==5.2.0\n"))
	uv := &fakeUv{lock: "x==1\n", set: resolved("delta", "2.0.0", "zeta", "1.0.0")}
	a.Uv = uv
	serveWheels(t, a, uv.set)
	emit := func(e Event) {
		var d logData
		if e.Kind == "log" && json.Unmarshal(e.Data, &d) == nil {
			logged = append(logged, d.Line)
		}
	}

	if err := a.Run(context.Background(), emit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	calls := uv.Calls()
	if len(calls) != 1 {
		t.Fatalf("uv ran %d times, want once", len(calls))
	}
	if want := []string{"chardet", "delta", "eps", "zeta"}; !slices.Equal(calls[0].Exempt, want) {
		t.Errorf("exempt = %v, want %v", calls[0].Exempt, want)
	}
	if !slices.ContainsFunc(logged, func(l string) bool {
		return strings.Contains(l, "eps==1.0.0 (requirements.txt)") && strings.Contains(l, "marker")
	}) {
		t.Errorf("log = %v, want a line on the marker of eps that was not decided", logged)
	}
}

func TestPipAnalysisCancelled(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
	uv := &fakeUv{block: true, started: make(chan struct{})}
	a.Uv = uv
	serveWheels(t, a, nil)

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
	if want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:cancelled"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Errorf("steps = %v, want %v", stepNames(status.Steps), want)
	}
}

// cannedTrivy answers every scan with report, whatever the SBOM holds,
// and keeps the SBOM it was given.
type cannedTrivy struct {
	report    string
	scanErr   error
	updateErr error
	mu        sync.Mutex
	sbom      []byte
}

func (c *cannedTrivy) ScanSBOM(_ context.Context, sbomPath, outPath string) (string, error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.sbom = data
	c.mu.Unlock()
	if c.scanErr != nil {
		return "FATAL scan failed", c.scanErr
	}
	return "", os.WriteFile(outPath, []byte(c.report), 0o664)
}

func (c *cannedTrivy) ConvertToCycloneDX(context.Context, string, string) (string, error) {
	return "", errors.New("cannedTrivy: ConvertToCycloneDX is not used by the analysis")
}

func (c *cannedTrivy) UpdateDB(context.Context) (string, error) { return "", c.updateErr }

// pipTrivyReport builds a Trivy JSON report from rows of package, version,
// id, severity and fixed version.
func pipTrivyReport(rows ...[5]string) string {
	var vulns []string
	for _, r := range rows {
		vulns = append(vulns, fmt.Sprintf(`{"VulnerabilityID":%q,"PkgName":%q,"InstalledVersion":%q,"Severity":%q,"FixedVersion":%q,"Title":"test finding"}`, r[2], r[0], r[1], r[3], r[4]))
	}
	return `{"SchemaVersion":2,"Results":[{"Target":"project.trivy.json.cdx.json","Class":"lang-pkgs","Type":"python-pkg","Vulnerabilities":[` + strings.Join(vulns, ",") + `]}]}`
}

// readPipResult reads the committed pip-result.json both as PipResult and
// as raw JSON.
func readPipResult(t *testing.T, st *store.Store, a *PipAnalysis) (PipResult, []byte) {
	t.Helper()
	path := filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "pip-result.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pip-result.json: %v", err)
	}
	var res PipResult
	if err := st.ReadJSON(path, &res); err != nil {
		t.Fatalf("read pip-result.json: %v", err)
	}
	return res, raw
}

// pipLog reads the committed analysis's log.txt.
func pipLog(t *testing.T, a *PipAnalysis) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "log.txt"))
	if err != nil {
		t.Fatalf("read log.txt: %v", err)
	}
	return string(data)
}

func TestPipAnalysisRecordsWhereEachPinIs(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "requests==2.32.3\n-r requirements-dev.txt\n-c constraints.txt\n"),
		reqFile("requirements-dev.txt", "# tools\n\nmypy==1.11.2\nrequests==2.32.3 ; python_version >= \"3.8\"\nmypy==1.11.2\n"),
		reqFile("constraints.txt", "idna==3.10\n"))
	set := resolved("certifi", "2024.8.30", "idna", "3.10", "mypy", "1.11.2", "requests", "2.32.3")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)
	want := map[string][]PipPlace{
		"certifi":  nil,
		"idna":     {{File: "constraints.txt", Line: 1}},
		"mypy":     {{File: "requirements-dev.txt", Line: 3}},
		"requests": {{File: "requirements-dev.txt", Line: 4}, {File: "requirements.txt", Line: 1}},
	}
	if len(res.Packages) != len(want) {
		t.Fatalf("packages = %+v, want %d", res.Packages, len(want))
	}
	for _, p := range res.Packages {
		if !reflect.DeepEqual(p.PinnedAt, want[p.Name]) {
			t.Errorf("%s pinnedAt = %+v, want %+v", p.Name, p.PinnedAt, want[p.Name])
		}
	}
	// The parser keeps one pin for a line that repeats another, here mypy
	// on line 5, so its place is the first one.
	if n := strings.Count(string(raw), `"pinnedAt"`); n != 3 {
		t.Errorf("pip-result.json = %s, holds %d pinnedAt keys, want 3: a transitive package has none", raw, n)
	}
}

func TestNoPreviousCrossingRecordsNone(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
	set := resolved("requests", "2.32.3")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)
	for _, key := range []string{`"previous"`, `"removed"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("pip-result.json = %s, holds %s, want it absent", raw, key)
		}
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %q, want none", res.Warnings)
	}
	if log := pipLog(t, a); !strings.Contains(log, "no previous crossing") {
		t.Errorf("log = %q, want a line saying there is no previous crossing", log)
	}
}

func TestPipScanReportsFixingVersions(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "Jinja2==3.1.2\nrequests==2.32.3\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("certifi", "2024.8.30", "jinja2", "3.1.2", "markupsafe", "3.0.2", "requests", "2.32.3")}
	serveWheels(t, a, resolved("certifi", "2024.8.30", "jinja2", "3.1.2", "markupsafe", "3.0.2", "requests", "2.32.3"))
	trivy := &cannedTrivy{report: pipTrivyReport(
		[5]string{"Jinja2", "3.1.2", "CVE-2024-34064", "MEDIUM", "3.1.4"},
		[5]string{"Jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3, 3.0.4"},
		[5]string{"Jinja2", "3.1.2", "CVE-2024-56326", "HIGH", "3.1.5"},
		[5]string{"Jinja2", "3.1.1", "CVE-2024-00001", "CRITICAL", "3.1.2"},
		[5]string{"requests", "2.32.3", "CVE-2024-47081", "LOW", ""},
	)}
	a.Trivy = trivy

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)

	byName := map[string]PipPackage{}
	for _, p := range res.Packages {
		byName[p.Name] = p
	}
	want := []PipFinding{
		{ID: "CVE-2024-56326", Severity: "HIGH", FixedVersions: []string{"3.1.5"}, Title: "test finding"},
		{ID: "CVE-2024-22195", Severity: "MEDIUM", FixedVersions: []string{"3.1.3", "3.0.4"}, Title: "test finding"},
		{ID: "CVE-2024-34064", Severity: "MEDIUM", FixedVersions: []string{"3.1.4"}, Title: "test finding"},
	}
	if got := byName["jinja2"].CVEs; !reflect.DeepEqual(got, want) {
		t.Errorf("jinja2 findings = %+v, want %+v", got, want)
	}
	if got, want := byName["requests"].CVEs, []PipFinding{{ID: "CVE-2024-47081", Severity: "LOW", FixedVersions: []string{}, Title: "test finding"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("requests findings = %+v, want %+v", got, want)
	}
	if got := byName["markupsafe"].CVEs; got == nil || len(got) != 0 {
		t.Errorf("markupsafe findings = %#v, want an empty list", got)
	}
	for _, text := range []string{`"fixedVersions":["3.1.3","3.0.4"]`, `"fixedVersions":[]`, `"cves":[]`} {
		if !strings.Contains(string(compactJSON(t, raw)), text) {
			t.Errorf("pip-result.json = %s, want it to hold %s", raw, text)
		}
	}

	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(trivy.sbom, &doc); err != nil {
		t.Fatalf("decode the scanned SBOM: %v", err)
	}
	var purls []string
	for _, c := range doc.Components {
		purls = append(purls, c.PURL)
	}
	if want := []string{"pkg:pypi/certifi@2024.8.30", "pkg:pypi/jinja2@3.1.2", "pkg:pypi/markupsafe@3.0.2", "pkg:pypi/requests@2.32.3"}; !slices.Equal(purls, want) {
		t.Errorf("scanned purls = %v, want %v", purls, want)
	}
	final := strings.TrimSuffix(a.Dir, ".tmp")
	if _, err := os.Stat(filepath.Join(final, "project.trivy.json")); err != nil {
		t.Errorf("project.trivy.json not kept: %v", err)
	}
}

func compactJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatalf("compact: %v", err)
	}
	return b.Bytes()
}

func TestPipResultHoldsExactlyTheResolvedSet(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "requests==2.32.3\n-c constraints.txt\n"),
		reqFile("dev.txt", "pytest==8.3.3\nrequests==2.32.3\n"),
		reqFile("constraints.txt", "idna==3.10\n"))
	set := resolved("certifi", "2024.8.30", "idna", "3.10", "iniconfig", "2.0.0", "pytest", "8.3.3", "requests", "2.32.3")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)
	a.Trivy = &cannedTrivy{report: pipTrivyReport(
		[5]string{"requests", "2.32.3", "CVE-2024-47081", "MEDIUM", "2.32.4"},
		[5]string{"requests", "2.31.0", "CVE-2024-35195", "MEDIUM", "2.32.0"},
	)}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)

	if res.Target != store.DefaultPipTarget {
		t.Errorf("target = %+v, want the project's", res.Target)
	}
	if want := []string{"requirements.txt", "dev.txt", "constraints.txt"}; !slices.Equal(res.Files, want) {
		t.Errorf("files = %v, want %v", res.Files, want)
	}
	var got []runner.Resolved
	for _, p := range res.Packages {
		got = append(got, runner.Resolved{Name: p.Name, Version: p.Version})
	}
	if !slices.Equal(got, set) {
		t.Errorf("packages = %v, want uv's set %v", got, set)
	}
	wantFiles := map[string][]string{
		"certifi":   {},
		"idna":      {"constraints.txt"},
		"iniconfig": {},
		"pytest":    {"dev.txt"},
		"requests":  {"dev.txt", "requirements.txt"},
	}
	for _, p := range res.Packages {
		if p.Files == nil || !slices.Equal(p.Files, wantFiles[p.Name]) {
			t.Errorf("%s files = %#v, want %v", p.Name, p.Files, wantFiles[p.Name])
		}
		if p.Wheel == nil || p.Wheel.File != p.Name+"-"+p.Version+"-py3-none-any.whl" {
			t.Errorf("%s wheel = %+v, want the one the index publishes", p.Name, p.Wheel)
		}
	}
	for _, p := range res.Packages {
		for _, f := range p.CVEs {
			if f.ID == "CVE-2024-35195" {
				t.Errorf("%s carries %s, reported for another version", p.Name, f.ID)
			}
		}
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if keys := slices.Sorted(maps.Keys(top)); !slices.Equal(keys, []string{"advisories", "blocking", "files", "packages", "target", "warnings"}) {
		t.Errorf("pip-result.json keys = %v", keys)
	}
	if string(top["blocking"]) != "[]" {
		t.Errorf("blocking = %s, want an empty list", top["blocking"])
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "requests@2.31.0") {
		t.Errorf("warnings = %q, want one naming the finding for requests 2.31.0", res.Warnings)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(top["packages"], &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		want := []string{"cves", "files", "name", "version", "wheel"}
		if string(row["files"]) != "[]" {
			want = []string{"cves", "files", "name", "pinnedAt", "version", "wheel"}
		}
		if keys := slices.Sorted(maps.Keys(row)); !slices.Equal(keys, want) {
			t.Errorf("package row keys = %v, want %v: pinnedAt for a pinned package only", keys, want)
		}
	}
	final := strings.TrimSuffix(a.Dir, ".tmp")
	if _, err := os.Stat(filepath.Join(final, "ranking.json")); !os.IsNotExist(err) {
		t.Errorf("a pip analysis wrote ranking.json: %v", err)
	}
}

// The lock names plone.namedfile as plone-namedfile, while Trivy knows it
// only under its published spelling.
func TestPipScanFindsADottedName(t *testing.T) {
	cases := []struct {
		name  string
		trivy runner.Trivy
	}{
		{"under its published spelling", &fakeTrivy{db: map[string][]fakeFinding{
			"plone.namedfile@5.0.0": {{id: "CVE-2023-41048", severity: "LOW", fixed: "5.6.1, 6.0.3"}},
		}}},
		{"once when Trivy reports both spellings", &cannedTrivy{report: pipTrivyReport(
			[5]string{"plone.namedfile", "5.0.0", "CVE-2023-41048", "LOW", "5.6.1, 6.0.3"},
			[5]string{"plone-namedfile", "5.0.0", "CVE-2023-41048", "LOW", "5.6.1, 6.0.3"},
		)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
				reqFile("requirements.txt", "plone.namedfile==5.0.0\n"))
			a.Uv = &fakeUv{lock: "plone.namedfile==5.0.0\n", set: resolved("plone-namedfile", "5.0.0", "six", "1.16.0")}
			serveWheels(t, a, resolved("plone-namedfile", "5.0.0", "six", "1.16.0"))
			a.Trivy = c.trivy

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, _ := readPipResult(t, st, a)
			var names []string
			for _, p := range res.Packages {
				names = append(names, p.Name+"@"+p.Version)
			}
			if want := []string{"plone-namedfile@5.0.0", "six@1.16.0"}; !slices.Equal(names, want) {
				t.Fatalf("packages = %v, want %v", names, want)
			}
			want := []PipFinding{{ID: "CVE-2023-41048", Severity: "LOW", FixedVersions: []string{"5.6.1", "6.0.3"}, Title: "test finding"}}
			if got := res.Packages[0].CVEs; !reflect.DeepEqual(got, want) {
				t.Errorf("plone-namedfile findings = %+v, want %+v", got, want)
			}
			if len(res.Warnings) != 0 {
				t.Errorf("warnings = %q, want none", res.Warnings)
			}
		})
	}
}

func TestPipScanWarnsOnFindingsOutsideTheSet(t *testing.T) {
	cases := []struct {
		name    string
		rows    [][5]string
		want    []string // texts the one warning holds; none means no warning
		notWant []string
	}{
		{"every finding on a package", [][5]string{
			{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"},
		}, nil, nil},
		{"one package outside", [][5]string{
			{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"},
			{"jinja2", "3.1.1", "CVE-2024-22195", "MEDIUM", "3.1.3"},
			{"jinja2", "3.1.1", "CVE-2024-34064", "MEDIUM", "3.1.4"},
		}, []string{"2 Trivy findings matched no package of the resolved set: jinja2@3.1.1"}, []string{"more"}},
		{"five packages outside", [][5]string{
			{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"},
			{"e", "1.0", "CVE-2024-00005", "LOW", ""},
			{"d", "1.0", "CVE-2024-00004", "LOW", ""},
			{"c", "1.0", "CVE-2024-00003", "LOW", ""},
			{"b", "1.0", "CVE-2024-00002", "LOW", ""},
			{"a", "1.0", "CVE-2024-00001", "LOW", ""},
		}, []string{"5 Trivy findings matched no package of the resolved set: a@1.0, b@1.0, c@1.0, and 2 more in the log"}, []string{"d@1.0", "e@1.0"}},
		{"a finding under both spellings of a package counts once", [][5]string{
			{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"},
			{"zope.event", "9.9", "CVE-2024-00009", "LOW", ""},
			{"zope-event", "9.9", "CVE-2024-00009", "LOW", ""},
		}, []string{"1 Trivy finding matched no package of the resolved set: zope-event@9.9"}, []string{"zope.event"}},
		{"a name with control characters, cut to its bound", [][5]string{
			{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"},
			{"evil\u202e\n" + strings.Repeat("x", 300), "1.0", "CVE-2024-00001", "LOW", ""},
		}, []string{"1 Trivy finding matched no package of the resolved set: evil " + strings.Repeat("x", shownNameLimit-5) + "..."}, []string{"\u202e", "\n", strings.Repeat("x", shownNameLimit)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logged []string
			a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
			a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2", "markupsafe", "3.0.2")}
			serveWheels(t, a, resolved("jinja2", "3.1.2", "markupsafe", "3.0.2"))
			a.Trivy = &cannedTrivy{report: pipTrivyReport(c.rows...)}
			emit := func(e Event) {
				var d logData
				if e.Kind == "log" && json.Unmarshal(e.Data, &d) == nil {
					logged = append(logged, d.Line)
				}
			}

			if err := a.Run(context.Background(), emit); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, raw := readPipResult(t, st, a)
			if len(res.Packages) == 0 || len(res.Packages[0].CVEs) != 1 {
				t.Errorf("packages = %+v, want jinja2 3.1.2 to keep its finding", res.Packages)
			}
			if c.want == nil {
				if !strings.Contains(string(compactJSON(t, raw)), `"warnings":[]`) {
					t.Errorf("pip-result.json = %s, want an empty warnings list", raw)
				}
				return
			}
			if len(res.Warnings) != 1 {
				t.Fatalf("warnings = %q, want one", res.Warnings)
			}
			for _, w := range c.want {
				if !strings.Contains(res.Warnings[0], w) {
					t.Errorf("warning = %q, want %q", res.Warnings[0], w)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(res.Warnings[0], w) {
					t.Errorf("warning = %q, holds %q", res.Warnings[0], w)
				}
			}
			for _, r := range c.rows {
				if r[1] == "3.1.2" {
					continue
				}
				key := cleanName(pip.Normalize(r[0]) + "@" + r[1])
				if !slices.ContainsFunc(logged, func(l string) bool { return strings.Contains(l, key) }) {
					t.Errorf("log = %v, misses %s", logged, key)
				}
			}
		})
	}
}

func TestPipScanFailureFailsTheAnalysis(t *testing.T) {
	cases := []struct {
		name    string
		trivy   *cannedTrivy
		wantErr string
	}{
		{"trivy exits with an error", &cannedTrivy{scanErr: errors.New("exit status 1")}, "exit status 1"},
		{"the report is not Trivy's schema", &cannedTrivy{report: `{"SchemaVersion":1,"Results":[]}`}, "schema version 1"},
		{"the report is not JSON", &cannedTrivy{report: "FATAL"}, "read trivy report"},
		{"the report is larger than its bound", &cannedTrivy{report: pipTrivyReport() + strings.Repeat(" ", trivyReportLimit)}, "project.trivy.json is larger than 64 MiB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
			a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2", "markupsafe", "3.0.2")}
			serveWheels(t, a, resolved("jinja2", "3.1.2", "markupsafe", "3.0.2"))
			a.Trivy = c.trivy

			if err := a.Run(context.Background(), func(Event) {}); err == nil {
				t.Fatal("Run succeeded, want the scan failure")
			}
			status, _ := readStatus(t, st, a)
			if want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:done", "choose-wheels:done", "scan:failed"}; !slices.Equal(stepNames(status.Steps), want) {
				t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
			}
			if status.State != store.Failed || !strings.Contains(status.Steps[5].Error, c.wantErr) {
				t.Errorf("state %q, scan error %q, want failed with %q", status.State, status.Steps[5].Error, c.wantErr)
			}
			if _, err := os.Stat(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "pip-result.json")); !os.IsNotExist(err) {
				t.Errorf("a failed scan left pip-result.json: %v", err)
			}
		})
	}
}

func TestPipAnalysisCauseNamesNoDataDirectory(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
	a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2", "markupsafe", "3.0.2")}
	serveWheels(t, a, resolved("jinja2", "3.1.2", "markupsafe", "3.0.2"))
	input := filepath.Join(a.Dir, "scan-input")
	a.Trivy = &cannedTrivy{scanErr: errors.New("trivy fs " + input + ": exit status 1")}

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want the scan failure")
	}
	status, _ := readStatus(t, st, a)
	scan := status.Steps[len(status.Steps)-1]
	rel, _ := filepath.Rel(st.Root(), input)
	if want := "trivy fs " + rel + ": exit status 1"; !strings.HasSuffix(scan.Error, want) || strings.Contains(scan.Error, st.Root()) {
		t.Errorf("scan cause = %q, want it to end %q", scan.Error, want)
	}
}

func TestReadTrivyReportBound(t *testing.T) {
	const limit = 1 << 20
	report := pipTrivyReport([5]string{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"})
	cases := []struct {
		name    string
		size    int
		wantErr string
	}{
		{"a report at the bound is read", limit, ""},
		{"a report one byte over the bound is refused", limit + 1, "project.trivy.json is larger than 1 MiB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "project.trivy.json")
			if err := os.WriteFile(path, []byte(report+strings.Repeat(" ", c.size-len(report))), 0o600); err != nil {
				t.Fatal(err)
			}
			findings, err := readTrivyReport(path, limit)
			if c.wantErr == "" {
				if err != nil || len(findings) != 1 {
					t.Errorf("findings = %+v, err = %v, want the one finding", findings, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want %q", err, c.wantErr)
			}
		})
	}
}

// TestReadTrivyReportReadsOnlyARegularFile gives the read what the tools
// account can leave at the report's path. A FIFO would hold an open that
// no cancel interrupts, and a device such as /dev/zero has no end.
func TestReadTrivyReportReadsOnlyARegularFile(t *testing.T) {
	report := pipTrivyReport([5]string{"jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"})
	for _, c := range []struct {
		name  string
		plant func(path string) error
	}{
		{"a link to a report", func(p string) error {
			target := filepath.Join(filepath.Dir(p), "elsewhere.json")
			if err := os.WriteFile(target, []byte(report), 0o600); err != nil {
				return err
			}
			return os.Symlink(target, p)
		}},
		{"a FIFO", func(p string) error { return syscall.Mkfifo(p, 0o600) }},
		{"a link to a device", func(p string) error { return os.Symlink("/dev/zero", p) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "project.trivy.json")
			if err := c.plant(path); err != nil {
				t.Fatal(err)
			}
			var findings []rank.Finding
			var err error
			returnsPromptly(t, path, func() { findings, err = readTrivyReport(path, 1<<20) })
			if err == nil || !strings.Contains(err.Error(), "project.trivy.json is not a regular file") {
				t.Errorf("findings = %+v, err = %v, want a refusal", findings, err)
			}
		})
	}
}

func TestPipScanWarnsOnAStaleDatabase(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
	a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2")}
	serveWheels(t, a, resolved("jinja2", "3.1.2"))
	a.Trivy = &cannedTrivy{report: pipTrivyReport(), updateErr: errors.New("registry unreachable")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "could not refresh the vulnerability database: registry unreachable") {
		t.Errorf("warnings = %q, want the failed database refresh", res.Warnings)
	}
}

// TestPipScanWarningNamesDataPathsRelative proves a failed database
// refresh whose error names a file under the data directory stores the
// warning with that file's path inside it.
func TestPipScanWarningNamesDataPathsRelative(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
	a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2")}
	serveWheels(t, a, resolved("jinja2", "3.1.2"))
	a.Trivy = &cannedTrivy{report: pipTrivyReport(), updateErr: &fs.PathError{Op: "open", Path: filepath.Join(st.Root(), "tools", "trivy", "db", "metadata.json"), Err: fs.ErrPermission}}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	want := "could not refresh the vulnerability database: open tools/trivy/db/metadata.json: permission denied"
	if len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0], want) {
		t.Errorf("warnings = %q, want one starting %q", res.Warnings, want)
	}
}

func TestPipAnalysisKind(t *testing.T) {
	a := &PipAnalysis{ID: "20261120T100000Z"}
	if a.Kind() != "analysis" || a.StoreID() != "20261120T100000Z" {
		t.Errorf("Kind, StoreID = %q, %q", a.Kind(), a.StoreID())
	}
}

func TestPipAnalysisNeverWritesThroughALink(t *testing.T) {
	for _, rel := range []string{
		"log.txt",
		filepath.Join("requirements", "requirements.txt"),
		filepath.Join("project", "requirements.lock"),
		"project.trivy.json.cdx.json",
	} {
		t.Run(rel, func(t *testing.T) {
			a, _ := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
				reqFile("requirements.txt", "requests==2.32.3\n"))
			uv := &fakeUv{lock: "requests==2.32.3\n", set: resolved("requests", "2.32.3"), output: "Resolved 1 package"}
			a.Uv = uv
			serveWheels(t, a, uv.set)
			victim, held := plantLinkToVictim(t, a.Dir, rel)

			_ = a.Run(context.Background(), func(Event) {})
			if got, err := os.ReadFile(victim); err != nil || string(got) != held {
				t.Errorf("the link's target now holds %d bytes (%v), want it untouched", len(got), err)
			}
		})
	}
}

func TestPipAnalysisAnswersAnAdvisoryForEveryCVEId(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
	a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2", "markupsafe", "3.0.2")}
	serveWheels(t, a, resolved("jinja2", "3.1.2", "markupsafe", "3.0.2"))
	vulns := []string{
		`{"VulnerabilityID":"CVE-2024-22195","PkgName":"Jinja2","InstalledVersion":"3.1.2","Severity":"MEDIUM","FixedVersion":"3.1.3",` +
			`"Title":"jinja2: HTML attribute injection when passing user input as keys to xmlattr filter",` +
			`"Description":"Jinja is an extensible templating engine. The xmlattr filter accepts keys containing spaces.\n\nSee the upstream advisory.",` +
			`"PublishedDate":"2024-01-11T03:15:11.137Z"}`,
		`{"VulnerabilityID":"CVE-2024-56326","PkgName":"Jinja2","InstalledVersion":"3.1.2","Severity":"HIGH","FixedVersion":"3.1.5",` +
			`"Title":"jinja2: Jinja has a sandbox breakout through indirect reference to format method"}`,
		// The same id on a later package of the result, worded otherwise.
		`{"VulnerabilityID":"CVE-2024-22195","PkgName":"markupsafe","InstalledVersion":"3.0.2","Severity":"MEDIUM","FixedVersion":"",` +
			`"Title":"markupsafe: a later wording","Description":"A later description."}`,
		// No title, description or date: nothing to answer.
		`{"VulnerabilityID":"CVE-2024-00007","PkgName":"markupsafe","InstalledVersion":"3.0.2","Severity":"LOW","FixedVersion":""}`,
		// A package outside the set: no cves list names the id.
		`{"VulnerabilityID":"CVE-2024-00008","PkgName":"flask","InstalledVersion":"3.0.0","Severity":"LOW","FixedVersion":"","Title":"flask: outside"}`,
	}
	a.Trivy = &cannedTrivy{report: `{"SchemaVersion":2,"Results":[{"Target":"project.trivy.json.cdx.json","Class":"lang-pkgs","Type":"python-pkg","Vulnerabilities":[` + strings.Join(vulns, ",") + `]}]}`}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)

	want := map[string]Advisory{
		"CVE-2024-22195": {
			Title:     "jinja2: HTML attribute injection when passing user input as keys to xmlattr filter",
			Summary:   "Jinja is an extensible templating engine. The xmlattr filter accepts keys containing spaces.",
			Published: "2024-01-11T03:15:11Z",
		},
		"CVE-2024-56326": {Title: "jinja2: Jinja has a sandbox breakout through indirect reference to format method"},
	}
	if !maps.Equal(res.Advisories, want) {
		t.Errorf("advisories = %+v, want %+v", res.Advisories, want)
	}
	for _, p := range res.Packages {
		for _, c := range p.CVEs {
			if _, ok := res.Advisories[c.ID]; !ok && c.ID != "CVE-2024-00007" {
				t.Errorf("%s names %s, but the table holds no advisory for it", p.Name, c.ID)
			}
		}
	}
	if !strings.Contains(string(compactJSON(t, raw)), `"advisories":{"CVE-2024-22195":{"title":`) {
		t.Errorf("pip-result.json = %s, want an advisories object keyed by id", raw)
	}
}

func TestPipFindingTitleIsCleanedAndBounded(t *testing.T) {
	root := t.TempDir()
	title := "jinja2: \x1b[0mcafé " + strings.Repeat("sandbox ", 30) + "end"
	if n := len([]rune(title)); n != 260 {
		t.Fatalf("the title holds %d code points, want 260", n)
	}
	set := map[string]rank.Finding{"CVE-2024-56326": {ID: "CVE-2024-56326", Severity: rank.High, Title: title}}
	advisories := map[string]Advisory{}

	findings := pipFindingsOf(root, set, advisories, func(rank.Finding) {})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	if got, want := findings[0].Title, advisoryTitle(root, title); got != want {
		t.Errorf("title = %q, want %q", got, want)
	}
	if got := findings[0].Title; strings.ContainsRune(got, '\x1b') || len([]rune(got)) > advisoryTitleLimit {
		t.Errorf("title = %q, want no escape and at most %d code points", got, advisoryTitleLimit)
	}
	if got := advisories["CVE-2024-56326"].Title; got != findings[0].Title {
		t.Errorf("advisory title = %q, want the finding's %q", got, findings[0].Title)
	}
}

// TestPipAnalysisStoresAdvisoryTextWithDataPathsRelative proves a pip
// analysis stores a finding's title, and its advisory's title and summary,
// with every path under the data directory relative to it and every URL
// without its credentials.
func TestPipAnalysisStoresAdvisoryTextWithDataPathsRelative(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
	a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2")}
	serveWheels(t, a, resolved("jinja2", "3.1.2"))
	text := "jinja2: reads " + filepath.Join(st.Root(), "projects", "p", "requirements.txt") +
		" from https://user:secret@index.example/simple"
	vuln, err := json.Marshal(map[string]string{
		"VulnerabilityID": "CVE-2024-22195", "PkgName": "Jinja2", "InstalledVersion": "3.1.2", "Severity": "MEDIUM",
		"Title": text, "Description": text + ".",
	})
	if err != nil {
		t.Fatal(err)
	}
	a.Trivy = &cannedTrivy{report: `{"SchemaVersion":2,"Results":[{"Target":"project.trivy.json.cdx.json","Class":"lang-pkgs","Type":"python-pkg","Vulnerabilities":[` + string(vuln) + `]}]}`}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)

	want := "jinja2: reads " + filepath.Join("projects", "p", "requirements.txt") + " from https://index.example/simple"
	if len(res.Packages) != 1 || len(res.Packages[0].CVEs) != 1 || res.Packages[0].CVEs[0].Title != want {
		t.Errorf("packages = %+v, want one finding titled %q", res.Packages, want)
	}
	if got := res.Advisories["CVE-2024-22195"]; got.Title != want || got.Summary != want+"." {
		t.Errorf("advisory = %+v, want title %q and summary %q", got, want, want+".")
	}
	if bytes.Contains(raw, []byte(st.Root())) || bytes.Contains(raw, []byte("secret")) {
		t.Errorf("pip-result.json = %s, want neither the data directory nor the password", raw)
	}
}

func TestPipScanLogsTheKindsOfCharactersAnAdvisoryDropped(t *testing.T) {
	a, _ := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "jinja2==3.1.2\n"))
	a.Uv = &fakeUv{lock: "jinja2==3.1.2\n", set: resolved("jinja2", "3.1.2")}
	serveWheels(t, a, resolved("jinja2", "3.1.2"))
	vulns, err := json.Marshal([]map[string]string{
		{"VulnerabilityID": "CVE-2026-00004", "PkgName": "Jinja2", "InstalledVersion": "3.1.2", "Severity": "HIGH", "Title": "secret\x1b[31m wording \u202Eevil", "Description": "a\x00b"},
		{"VulnerabilityID": "CVE-2026-00005", "PkgName": "Jinja2", "InstalledVersion": "3.1.2", "Severity": "LOW", "Title": "word\u2060joiner\tand tab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.Trivy = &cannedTrivy{report: `{"SchemaVersion":2,"Results":[{"Target":"project.trivy.json.cdx.json","Class":"lang-pkgs","Type":"python-pkg","Vulnerabilities":` + string(vulns) + `}]}`}

	var lines []string
	emit := func(e Event) {
		if e.Kind != "log" {
			return
		}
		var d logData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if strings.Contains(d.Line, "advisory text dropped") {
			lines = append(lines, d.Line)
		}
	}
	if err := a.Run(context.Background(), emit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"CVE-2026-00004: advisory text dropped bidi, control characters"}
	if !slices.Equal(lines, want) {
		t.Errorf("log = %q, want %q", lines, want)
	}
}

func TestPipResultKeepsTheSpellingTheFilesDeclare(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "Pillow==10.4.0\nSQLAlchemy==2.0.36\nidna==3.10\n"))
	set := resolved("idna", "3.10", "pillow", "10.4.0", "six", "1.16.0", "sqlalchemy", "2.0.36")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	want := map[string]string{"idna": "", "pillow": "Pillow", "six": "", "sqlalchemy": "SQLAlchemy"}
	for _, p := range res.Packages {
		if p.Declared != want[p.Name] {
			t.Errorf("%s declared = %q, want %q", p.Name, p.Declared, want[p.Name])
		}
	}
}

// The declared spelling reaches the screen as written, so a name the pip
// grammar does not allow is never declared, whatever the parser let through.
func TestDeclaredOfKeepsOnlyAValidName(t *testing.T) {
	r := &pipRun{set: pip.Set{Requirements: []pip.Pin{
		{Name: "Pil\u202elow", Key: "pil-low"},
		{Name: "\x1bname", Key: "name"},
		{Name: "Pillow", Key: "pillow"},
	}}}
	for key, want := range map[string]string{"pil-low": "", "name": "", "pillow": "Pillow"} {
		if got := r.declaredOf(key); got != want {
			t.Errorf("declaredOf(%q) = %q, want %q", key, got, want)
		}
	}
}
