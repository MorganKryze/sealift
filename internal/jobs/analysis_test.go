package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
)

// fakePnpm resolves a manifest without running pnpm: it fabricates a
// pnpm-lock.yaml listing every dependency the manifest names, unless that
// dependency's "name@version" key is in fail, or block is set, in which
// case it waits for ctx to be canceled, the way a real pnpm child outlives
// a killed group until the wait bounds it.
type fakePnpm struct {
	mu    sync.Mutex
	fail  map[string]bool
	block bool
	calls int

	// dirs and dirModes record, in call order, the resolution directory
	// each Resolve call ran in and the mode it had at that moment: the
	// directory is removed once (*Analysis).resolve returns, so a test
	// asserting on its mode must capture it here, synchronously, before
	// that happens.
	dirs     []string
	dirModes []os.FileMode
	// targets records, in call order, the target each Resolve call was
	// asked to pin the isolated resolution's workspace file to, so a test
	// can prove which of Project.Target and Settings.Target actually
	// reached pnpm.
	targets []store.Target
	// ages records, in call order, the manifest of each Resolve call and
	// the minimum release age it asked for.
	ages []resolvedAge
}

type resolvedAge struct {
	manifest string
	days     int
}

func (f *fakePnpm) Resolve(ctx context.Context, in runner.ResolveInput) (runner.ResolveResult, error) {
	f.mu.Lock()
	f.calls++
	f.dirs = append(f.dirs, in.Dir)
	f.targets = append(f.targets, in.Target)
	f.ages = append(f.ages, resolvedAge{string(in.Manifest), in.MinReleaseAgeDays})
	if info, statErr := os.Stat(in.Dir); statErr == nil {
		f.dirModes = append(f.dirModes, info.Mode().Perm())
	}
	f.mu.Unlock()

	if f.block {
		<-ctx.Done()
		return runner.ResolveResult{Output: "killed"}, ctx.Err()
	}

	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(in.Manifest, &doc); err != nil {
		return runner.ResolveResult{}, err
	}
	all := map[string]string{}
	for _, m := range []map[string]string{doc.Dependencies, doc.DevDependencies, doc.OptionalDependencies} {
		for name, version := range m {
			all[name] = version
		}
	}
	for name, version := range all {
		if f.fail[name+"@"+version] {
			return runner.ResolveResult{Output: "ERR_PNPM_NO_MATCHING_VERSION  " + name + "@" + version}, errors.New("pnpm install: no matching version")
		}
	}

	var sb strings.Builder
	sb.WriteString("lockfileVersion: '9.0'\npackages:\n")
	for name, version := range all {
		sb.WriteString("  " + name + "@" + version + ":\n    resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==}\n")
	}
	return runner.ResolveResult{Lockfile: []byte(sb.String())}, nil
}

// fakeFinding is one vulnerability fakeTrivy reports for a package version.
type fakeFinding struct {
	id       string
	severity string
	fixed    string
}

// fakeTrivy scans a CycloneDX SBOM by reading the components straight back
// out of it and looking each one up in db, so a test controls findings by
// "name@version" without a real Trivy binary.
type fakeTrivy struct {
	mu        sync.Mutex
	db        map[string][]fakeFinding
	scanCalls int
}

func (f *fakeTrivy) ScanSBOM(_ context.Context, sbomPath, outPath string) (string, error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return "", err
	}
	var doc struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", err
	}

	f.mu.Lock()
	f.scanCalls++
	f.mu.Unlock()

	type vuln struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		FixedVersion     string `json:"FixedVersion"`
		Severity         string `json:"Severity"`
		Title            string `json:"Title"`
	}
	var vulns []vuln
	for _, c := range doc.Components {
		for _, fnd := range f.db[c.Name+"@"+c.Version] {
			vulns = append(vulns, vuln{
				VulnerabilityID: fnd.id, PkgName: c.Name, InstalledVersion: c.Version,
				FixedVersion: fnd.fixed, Severity: fnd.severity, Title: "test finding",
			})
		}
	}
	report := struct {
		SchemaVersion int `json:"SchemaVersion"`
		Results       []struct {
			Vulnerabilities []vuln `json:"Vulnerabilities"`
		} `json:"Results"`
	}{SchemaVersion: 2}
	report.Results = append(report.Results, struct {
		Vulnerabilities []vuln `json:"Vulnerabilities"`
	}{Vulnerabilities: vulns})

	out, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return "", os.WriteFile(outPath, out, 0o664)
}

func (f *fakeTrivy) ConvertToCycloneDX(context.Context, string, string) (string, error) {
	return "", errors.New("fakeTrivy: ConvertToCycloneDX is not used by the analysis job")
}

func (f *fakeTrivy) UpdateDB(context.Context) (string, error) { return "", nil }

// newAnalysisProject creates a project directory holding packageJSON and a
// pending analysis directory to run against it.
func newAnalysisProject(t *testing.T, packageJSON string) (*store.Store, store.Project, *store.Pending) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	proj, err := st.CreateProject("demo", []byte(packageJSON))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	pending, err := st.NewDir("analyses", proj.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	return st, proj, pending
}

// newTestToolsManager returns a Manager whose pnpm version is already
// "installed" (so EnsurePnpm never touches the network) and whose GitHub
// API points at a server that always 404s (so TrivyState's best-effort
// lookup fails fast instead of reaching the real internet).
func newTestToolsManager(t *testing.T, st *store.Store) *tools.Manager {
	t.Helper()
	target := st.Settings().Target
	bin := filepath.Join(st.Root(), "tools", "pnpm", target.PnpmVer, "package", "bin", "pnpm.cjs")
	if err := os.MkdirAll(filepath.Dir(bin), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/usr/bin/env node\n"), 0o664); err != nil {
		t.Fatal(err)
	}

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	t.Cleanup(gh.Close)

	mgr := tools.NewManager(st, http.DefaultClient, nil)
	mgr.GitHubAPI = gh.URL
	return mgr
}

// registryServer serves docs, a map of package name to raw packument JSON.
func registryServer(t *testing.T, docs map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		doc, ok := docs[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAnalysisKind checks the id prefix the queue assigns an Analysis job.
func TestAnalysisKind(t *testing.T) {
	if got := (&Analysis{}).Kind(); got != "analysis" {
		t.Errorf("Kind() = %q, want %q", got, "analysis")
	}
}

// TestAnalysisThatCannotBeginNamesNoServerPath proves the error of a run
// that fails before its first write keeps its cause and drops the path:
// that error becomes the failure the screen shows.
func TestAnalysisThatCannotBeginNamesNoServerPath(t *testing.T) {
	kinds := []struct {
		name string
		job  func(t *testing.T) (Job, string)
	}{
		{"npm", func(t *testing.T) (Job, string) {
			st, proj, pending := newAnalysisProject(t, `{"name":"demo"}`)
			return &Analysis{Store: st, Project: proj, Dir: pending.Path(), ID: pending.ID()}, pending.Path()
		}},
		{"pip", func(t *testing.T) (Job, string) {
			a, _ := newPipAnalysis(t, "http://127.0.0.1:1/simple/", store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
			return a, a.Dir
		}},
	}
	for _, kind := range kinds {
		for _, blocked := range []string{"log.txt", "status.json"} {
			t.Run(kind.name+" "+blocked, func(t *testing.T) {
				job, dir := kind.job(t)
				// A directory where the run expects a file fails the open
				// or the rename with an error that carries the path.
				if err := os.Mkdir(filepath.Join(dir, blocked), 0o770); err != nil {
					t.Fatal(err)
				}
				err := job.Run(context.Background(), func(Event) {})
				if err == nil {
					t.Fatal("Run returned nil, want the error of the blocked write")
				}
				if strings.Contains(err.Error(), filepath.Base(dir)) {
					t.Errorf("error %q names the analysis directory", err)
				}
				if !strings.Contains(err.Error(), blocked) {
					t.Errorf("error %q does not name %s", err, blocked)
				}
			})
		}
	}
}

// TestRunStepRecordsTheFailureMessage proves a failed step's own error
// reaches status.json instead of staying only in log.txt: runStep must
// set stepRecord.Error to err.Error() whenever the step's state is
// Failed.
func TestRunStepRecordsTheFailureMessage(t *testing.T) {
	r := &run{a: &Analysis{}, stepLog: stepLog{ctx: context.Background(), emit: func(Event) {}}}

	err := r.runStep("boom-step", func() error { return errors.New("boom") })
	if err == nil {
		t.Fatal("runStep returned nil, want the step function's own error")
	}
	if len(r.steps) != 1 {
		t.Fatalf("steps = %+v, want exactly one", r.steps)
	}
	if r.steps[0].State != string(store.Failed) {
		t.Errorf("steps[0].State = %q, want %q", r.steps[0].State, store.Failed)
	}
	if r.steps[0].Error != "boom" {
		t.Errorf("steps[0].Error = %q, want %q", r.steps[0].Error, "boom")
	}
}

// TestRunStepKeepsTheDataDirectoryOutOfTheCause proves a failed step's
// cause names a path under the data directory relative to it, in
// status.json and in the step event, whatever kind of error named it.
func TestRunStepKeepsTheDataDirectoryOutOfTheCause(t *testing.T) {
	root := t.TempDir()
	var events []Event
	r := &run{a: &Analysis{}, stepLog: stepLog{ctx: context.Background(), root: root, emit: func(e Event) { events = append(events, e) }}}
	replaced := filepath.Join(root, "projects", "p", "analyses", "a.tmp", "status.json")

	_ = r.runStep("write", func() error { return fmt.Errorf("store: %s was replaced while it was written", replaced) })

	const want = "store: projects/p/analyses/a.tmp/status.json was replaced while it was written"
	if len(r.steps) != 1 || r.steps[0].Error != want {
		t.Errorf("steps = %+v, want one failed step with cause %q", r.steps, want)
	}
	var d stepData
	if len(events) != 1 || json.Unmarshal(events[0].Data, &d) != nil || d.Error != want {
		t.Errorf("step event = %+v, want cause %q", events, want)
	}
}

func TestCauseDropsOnlyTheDataDirectory(t *testing.T) {
	cases := []struct {
		name, root, err, want string
	}{
		{"a path under the root", "/data", "open /data/projects/p/log.txt: denied", "open projects/p/log.txt: denied"},
		{"every path under the root", "/data/", "rename /data/a.tmp /data/a: exists", "rename a.tmp a: exists"},
		{"a sibling of the root", "/data", "open /data2/x: denied", "open /data2/x: denied"},
		{"no root", "", "open /data/x: denied", "open /data/x: denied"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cause(c.root, errors.New(c.err)); got != c.want {
				t.Errorf("cause(%q, %q) = %q, want %q", c.root, c.err, got, c.want)
			}
		})
	}
}

// TestRunStepLeavesErrorEmptyOnSuccess proves a done step never carries a
// stray error message.
func TestRunStepLeavesErrorEmptyOnSuccess(t *testing.T) {
	r := &run{a: &Analysis{}, stepLog: stepLog{ctx: context.Background(), emit: func(Event) {}}}

	if err := r.runStep("ok-step", func() error { return nil }); err != nil {
		t.Fatalf("runStep: %v", err)
	}
	if r.steps[0].Error != "" {
		t.Errorf("steps[0].Error = %q, want empty", r.steps[0].Error)
	}
}

const fooDoc = `{"name":"foo","versions":{
	"1.0.0":{"version":"1.0.0"},
	"1.1.0":{"version":"1.1.0"}
},"time":{"1.0.0":"2020-01-01T00:00:00.000Z","1.1.0":"2020-02-01T00:00:00.000Z"}}`

const barDoc = `{"name":"bar","versions":{
	"2.0.0":{"version":"2.0.0"},
	"2.1.0":{"version":"2.1.0"}
},"time":{"2.0.0":"2020-01-01T00:00:00.000Z","2.1.0":"2020-02-01T00:00:00.000Z"}}`

// TestAnalysis_HappyPathAndCandidateFailure runs a two-dependency project
// through the whole job via the real Queue: foo has a newer version that
// resolves and fixes its only vulnerability (the best candidate), bar has a
// newer version that fails to resolve.
// It also checks the event sequence: every step exactly once, "end" last.
func TestAnalysis_HappyPathAndCandidateFailure(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0","bar":"2.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	registry := registryServer(t, map[string]string{"foo": fooDoc, "bar": barDoc})

	pnpm := &fakePnpm{fail: map[string]bool{"bar@2.1.0": true}}
	trivy := &fakeTrivy{db: map[string][]fakeFinding{
		"foo@1.0.0": {{id: "CVE-2020-1", severity: "HIGH", fixed: "1.1.0"}},
	}}

	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     pnpm,
		Trivy:    trivy,
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	q := NewQueue(testLogger())
	defer q.Close()
	events, unsubscribe := q.Subscribe()
	defer unsubscribe()

	if _, err := q.Submit(a); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	var got []Event
	deadline := time.After(10 * time.Second)
loop:
	for {
		select {
		case e := <-events:
			got = append(got, e)
			if e.Kind == "end" {
				break loop
			}
		case <-deadline:
			t.Fatalf("timed out waiting for end, got %d events: %+v", len(got), got)
		}
	}

	if got[len(got)-1].Kind != "end" {
		t.Fatalf("last event kind = %q, want end", got[len(got)-1].Kind)
	}
	var steps []string
	seen := map[string]bool{}
	for _, e := range got {
		if e.Kind != "step" {
			continue
		}
		var d stepData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			t.Fatalf("unmarshal step data: %v", err)
		}
		if seen[d.Name] {
			t.Fatalf("step %q emitted more than once", d.Name)
		}
		seen[d.Name] = true
		steps = append(steps, d.Name)
	}
	wantSteps := []string{
		"validate", "prepare-tools", "resolve-project", "scan-project",
		"list-candidates", "resolve-candidates", "scan-candidates", "rank", "check-combined",
	}
	if !equalStrings(steps, wantSteps) {
		t.Fatalf("steps = %v, want %v", steps, wantSteps)
	}

	var end struct{ State store.State }
	if err := json.Unmarshal(got[len(got)-1].Data, &end); err != nil {
		t.Fatalf("unmarshal end data: %v", err)
	}
	if end.State != store.Done {
		t.Fatalf("end state = %q, want done", end.State)
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	for _, rel := range []string{
		"status.json", "package.json", "log.txt",
		filepath.Join("project", "pnpm-lock.yaml"), "project.trivy.json",
		"candidates.json", "candidates.trivy.json", "ranking.json",
		filepath.Join("candidates", "foo@1.0.0", "pnpm-lock.yaml"),
		filepath.Join("candidates", "foo@1.1.0", "pnpm-lock.yaml"),
		filepath.Join("candidates", "bar@2.0.0", "pnpm-lock.yaml"),
		filepath.Join("combined", "pnpm-lock.yaml"), "combined.trivy.json",
	} {
		if _, err := os.Stat(filepath.Join(finalDir, rel)); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(finalDir, "candidates", "bar@2.1.0")); !os.IsNotExist(err) {
		t.Errorf("candidates/bar@2.1.0 exists despite a failed resolution: %v", err)
	}

	var result Result
	if err := st.ReadJSON(filepath.Join(finalDir, "ranking.json"), &result); err != nil {
		t.Fatalf("read ranking.json: %v", err)
	}
	if result.Before != (Vector{0, 1, 0, 0, 0}) {
		t.Errorf("Before = %v, want one high", result.Before)
	}
	if result.After == nil || *result.After != (Vector{0, 0, 0, 0, 0}) {
		t.Errorf("After = %v, want a measured zero vector (step 9 resolved and scanned foo's fix cleanly)", result.After)
	}

	var foo, bar *DependencyResult
	for i := range result.Dependencies {
		switch result.Dependencies[i].Name {
		case "foo":
			foo = &result.Dependencies[i]
		case "bar":
			bar = &result.Dependencies[i]
		}
	}
	if foo == nil || foo.Best != "1.1.0" {
		t.Fatalf("foo.Best = %+v, want 1.1.0", foo)
	}
	if bar == nil || bar.Best != "" {
		t.Fatalf("bar.Best = %+v, want none: a candidate that fails to resolve must not become best", bar)
	}
	if len(bar.Candidates) != 1 || bar.Candidates[0].Resolved {
		t.Fatalf("bar.Candidates = %+v, want one unresolved candidate", bar.Candidates)
	}
	var hasUnresolvable bool
	for _, s := range bar.Candidates[0].Signals {
		if s.Name == "does-not-resolve" {
			hasUnresolvable = true
		}
	}
	if !hasUnresolvable {
		t.Fatalf("bar's candidate signals = %+v, want does-not-resolve", bar.Candidates[0].Signals)
	}
}

// TestAnalysis_UsesProjectTargetNotSettingsTarget proves an analysis
// resolves and scans for the project's own target even once it no longer
// matches the settings target, the same target /api/projects/{p}/target
// persists to Project.Target and export already filters and reports by.
func TestAnalysis_UsesProjectTargetNotSettingsTarget(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	registry := registryServer(t, map[string]string{"foo": fooDoc})

	projectTarget := proj.Target
	projectTarget.CPU = "arm64"
	projectTarget.Libc = "musl"
	projectTarget.Node = "20.11.0"
	if err := st.SetProjectTarget(proj.ID, projectTarget); err != nil {
		t.Fatalf("SetProjectTarget: %v", err)
	}
	proj, err := st.Project(proj.ID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if proj.Target == st.Settings().Target {
		t.Fatal("project target equals settings target, want them to differ for this test to mean anything")
	}

	pnpm := &fakePnpm{}
	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     pnpm,
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(pnpm.targets) == 0 {
		t.Fatal("pnpm never resolved anything")
	}
	for i, target := range pnpm.targets {
		if target != proj.Target {
			t.Errorf("pnpm resolution %d ran with target %+v, want the project's own %+v", i, target, proj.Target)
		}
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	var status statusFile
	if err := st.ReadJSON(filepath.Join(finalDir, "status.json"), &status); err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	if status.Target != proj.Target {
		t.Errorf("status.json target = %+v, want the project's own %+v", status.Target, proj.Target)
	}
}

// TestAnalysis_EveryResolutionHoldsToTheReleaseAge proves the minimum release
// age reaches every resolution: any of their lockfiles can reach an archive.
func TestAnalysis_EveryResolutionHoldsToTheReleaseAge(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	registry := registryServer(t, map[string]string{"foo": fooDoc})
	settings := st.Settings()
	settings.MinReleaseAgeDays = 21

	pnpm := &fakePnpm{}
	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     pnpm,
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: settings,
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(pnpm.ages) == 0 {
		t.Fatal("pnpm never resolved anything")
	}
	for _, r := range pnpm.ages {
		if r.days != 21 {
			t.Errorf("resolved with age %d, want 21: %s", r.days, r.manifest)
		}
	}
}

// TestAnalysis_CandidateWriteFailureFailsTheJob proves a filesystem
// failure writing one candidate's lockfile (step 6, resolve-candidates)
// fails the whole analysis instead of finishing done with a partial
// candidates directory: a later export reading a missing lockfile would
// otherwise fail deep inside with a bare "no such file or directory",
// long after the job itself claimed success.
func TestAnalysis_CandidateWriteFailureFailsTheJob(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permissions this test relies on")
	}

	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	registry := registryServer(t, map[string]string{"foo": fooDoc})

	// Pre-create "candidates" read-only, so step 6's os.MkdirAll for the
	// first candidate it tries to write fails, the same way a permission
	// or disk problem would in production.
	candidatesDir := filepath.Join(pending.Path(), "candidates")
	if err := os.MkdirAll(candidatesDir, 0o500); err != nil {
		t.Fatalf("mkdir candidates: %v", err)
	}

	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     &fakePnpm{},
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run returned nil, want an error from the candidate write failure")
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	var status statusFile
	if rerr := st.ReadJSON(filepath.Join(finalDir, "status.json"), &status); rerr != nil {
		t.Fatalf("read status.json: %v", rerr)
	}
	if status.State != store.Failed {
		t.Fatalf("status.json state = %q, want %q", status.State, store.Failed)
	}
	failed := status.Steps[len(status.Steps)-1]
	if failed.Name != "resolve-candidates" || !strings.Contains(failed.Error, "candidates") || strings.Contains(failed.Error, st.Root()) {
		t.Errorf("failed step = %+v, want resolve-candidates naming candidates/ without %s", failed, st.Root())
	}
}

// projectManifestPnpm resolves like fakePnpm except a manifest named
// "project" (buildFullManifest's own package name, the shape both step 3
// and step 9 resolve) carrying dep at failVersion is treated as a
// conflict. Naming it "project" rather than checking the dependency alone
// is what isolates step 9's own resolution from step 6's identically
// versioned but differently shaped ("probe") isolated resolution of the
// same candidate, which must keep succeeding for step 9 to run at all.
type projectManifestPnpm struct {
	fakePnpm
	dep, failVersion string
}

func (f *projectManifestPnpm) Resolve(ctx context.Context, in runner.ResolveInput) (runner.ResolveResult, error) {
	var doc struct {
		Name         string            `json:"name"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(in.Manifest, &doc); err == nil && doc.Name == "project" && doc.Dependencies[f.dep] == f.failVersion {
		return runner.ResolveResult{Output: "ERR_PNPM_PEER_DEP  conflict"}, errors.New("pnpm install: peer conflict")
	}
	return f.fakePnpm.Resolve(ctx, in)
}

// TestAnalysis_CombinedCheckConflictLeavesAfterNil proves a step 9
// (check-combined) conflict leaves Result.After nil, both in ranking.json
// on disk and in its JSON encoding, rather than the zero vector a caller
// could mistake for a measured, clean result.
func TestAnalysis_CombinedCheckConflictLeavesAfterNil(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	registry := registryServer(t, map[string]string{"foo": fooDoc})

	pnpm := &projectManifestPnpm{dep: "foo", failVersion: "1.1.0"}
	trivy := &fakeTrivy{db: map[string][]fakeFinding{
		"foo@1.0.0": {{id: "CVE-2020-1", severity: "HIGH", fixed: "1.1.0"}},
	}}

	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     pnpm,
		Trivy:    trivy,
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v, want the job to finish despite the combined conflict", err)
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	raw, err := os.ReadFile(filepath.Join(finalDir, "ranking.json"))
	if err != nil {
		t.Fatalf("read ranking.json: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal ranking.json fields: %v", err)
	}
	if after, ok := fields["after"]; !ok || string(after) != "null" {
		t.Errorf("ranking.json after = %s (present=%v), want an explicit null", after, ok)
	}

	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal Result: %v", err)
	}
	if result.After != nil {
		t.Errorf("Result.After = %v, want nil", result.After)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("Warnings is empty, want a warning about the combined conflict")
	}
}

// TestAnalysis_RegistryUnreachable covers a dependency whose registry
// metadata never answers: the job marks it and continues, rather than
// failing outright.
func TestAnalysis_RegistryUnreachable(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"baz":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)

	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer unreachable.Close()

	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     &fakePnpm{},
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: unreachable.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v, want the job to continue despite unreachable metadata", err)
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	var result Result
	if err := st.ReadJSON(filepath.Join(finalDir, "ranking.json"), &result); err != nil {
		t.Fatalf("read ranking.json: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("Warnings is empty, want a warning about baz's unreachable metadata")
	}
	if len(result.Dependencies) != 1 || result.Dependencies[0].Name != "baz" || len(result.Dependencies[0].Candidates) != 0 {
		t.Fatalf("Dependencies = %+v, want one dependency with no candidates", result.Dependencies)
	}
}

const quxDoc = `{"name":"qux","versions":{
	"1.0.0":{"version":"1.0.0"}
},"time":{"1.0.0":"2020-01-01T00:00:00.000Z"}}`

// TestAnalysis_NoWarningsOrCandidatesSerialiseAsEmptyArrays proves the fix
// for G3: qux is already at the only version its packument lists, so it
// raises no warning and offers no candidate. warnings, dependencies and
// candidates are contract-required arrays; a client that trusts the
// contract crashes on null, so ranking.json (and, through it, the API's
// own response) must hold [] for each, never null.
func TestAnalysis_NoWarningsOrCandidatesSerialiseAsEmptyArrays(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"qux":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	registry := registryServer(t, map[string]string{"qux": quxDoc})

	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     &fakePnpm{},
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	raw, err := os.ReadFile(filepath.Join(finalDir, "ranking.json"))
	if err != nil {
		t.Fatalf("read ranking.json: %v", err)
	}
	text := string(raw)
	if strings.Contains(text, "null") {
		t.Errorf("ranking.json = %s, want no null array for a required contract field", text)
	}
	for _, want := range []string{`"warnings": []`, `"candidates": []`} {
		if !strings.Contains(text, want) {
			t.Errorf("ranking.json = %s, want it to contain %s", text, want)
		}
	}

	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal ranking.json: %v", err)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", result.Warnings)
	}
	if len(result.Dependencies) != 1 || result.Dependencies[0].Name != "qux" || len(result.Dependencies[0].Candidates) != 0 {
		t.Fatalf("Dependencies = %+v, want exactly qux with no candidates", result.Dependencies)
	}
}

// TestAnalysis_CancelledRunLeavesDirectory covers a run cancelled
// mid-flight: the directory and its log stay on disk, and status.json
// records the cancellation.
func TestAnalysis_CancelledRunLeavesDirectory(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)

	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     &fakePnpm{block: true},
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, func(Event) {}) }()

	// Give stepResolveProject time to reach the blocking fake pnpm call
	// before cancelling, so the cancellation lands mid-step, not before it.
	time.Sleep(50 * time.Millisecond)

	// While still blocked, status.json must already exist with state
	// running, written at the start of Run: without that early write,
	// store.MarkRunningInterrupted's restart sweep never finds anything
	// to flip, since commit only ever writes a terminal state.
	var running statusFile
	if err := st.ReadJSON(filepath.Join(a.Dir, "status.json"), &running); err != nil {
		t.Fatalf("read status.json while still running: %v", err)
	}
	if running.State != store.Running {
		t.Fatalf("status.json state while still running = %q, want %q", running.State, store.Running)
	}

	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned nil, want an error from the cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	finalDir := strings.TrimSuffix(a.Dir, ".tmp")
	if _, err := os.Stat(finalDir); err != nil {
		t.Fatalf("committed directory missing: %v", err)
	}
	if _, err := os.Stat(a.Dir); !os.IsNotExist(err) {
		t.Fatalf(".tmp directory still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(finalDir, "log.txt")); err != nil {
		t.Errorf("log.txt missing from the cancelled directory: %v", err)
	}

	var status statusFile
	if err := st.ReadJSON(filepath.Join(finalDir, "status.json"), &status); err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	if status.State != store.Cancelled {
		t.Fatalf("status.State = %q, want %q", status.State, store.Cancelled)
	}
}

// TestLogStripsURLCredentials proves the job log, both log.txt and the
// emitted "log" event, drops the user and password of a URL while keeping
// its host and path.
func TestLogStripsURLCredentials(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "log.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []Event
	r := &run{stepLog: stepLog{logFile: f, emit: func(e Event) { events = append(events, e) }}}

	r.log("pnpm: fetch http://alice:s3cr3t@10.0.0.1:4873/x failed")

	written, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	for name, got := range map[string]string{"log.txt": string(written), "event": string(events[0].Data)} {
		if strings.Contains(got, "alice") || strings.Contains(got, "s3cr3t") {
			t.Errorf("%s = %q, still holds the credentials", name, got)
		}
		if !strings.Contains(got, "://10.0.0.1:4873/x") {
			t.Errorf("%s = %q, lost the host or path", name, got)
		}
	}
}

// plantLinkToVictim puts a link at dir/rel to a file the server alone can
// read and returns that file's path and bytes. The tools account can write
// every job directory.
func plantLinkToVictim(t *testing.T, dir, rel string) (string, string) {
	t.Helper()
	victim := filepath.Join(t.TempDir(), "signing-key.pem")
	const held = "a file the server owns"
	if err := os.WriteFile(victim, []byte(held), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(link), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	return victim, held
}

func TestAnalysisNeverWritesThroughALink(t *testing.T) {
	for _, rel := range []string{
		"log.txt",
		"package.json",
		filepath.Join("project", "pnpm-lock.yaml"),
		"project.trivy.json.cdx.json",
		filepath.Join("candidates", "foo@1.1.0", "pnpm-lock.yaml"),
		"candidates.trivy.json",
		filepath.Join("combined", "pnpm-lock.yaml"),
	} {
		t.Run(rel, func(t *testing.T) {
			st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0","bar":"2.0.0"}}`)
			registry := registryServer(t, map[string]string{"foo": fooDoc, "bar": barDoc})
			a := &Analysis{
				Store: st,
				Tools: newTestToolsManager(t, st),
				// The candidate that does not resolve writes a line to the log.
				Pnpm: &fakePnpm{fail: map[string]bool{"bar@2.1.0": true}},
				Trivy: &fakeTrivy{db: map[string][]fakeFinding{
					"foo@1.0.0": {{id: "CVE-2020-1", severity: "HIGH", fixed: "1.1.0"}},
				}},
				Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
				Project:  proj,
				Settings: st.Settings(),
				Dir:      pending.Path(),
				ID:       pending.ID(),
			}
			victim, held := plantLinkToVictim(t, a.Dir, rel)

			_ = a.Run(context.Background(), func(Event) {})
			if got, err := os.ReadFile(victim); err != nil || string(got) != held {
				t.Errorf("the link's target now holds %d bytes (%v), want it untouched", len(got), err)
			}
		})
	}
}

// A name listed in two dependency groups resolves each candidate twice,
// into one directory.
func TestAnalysisResolvesANameListedInTwoGroups(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"},"devDependencies":{"foo":"1.0.0"}}`)
	registry := registryServer(t, map[string]string{"foo": fooDoc})
	a := &Analysis{
		Store:    st,
		Tools:    newTestToolsManager(t, st),
		Pnpm:     &fakePnpm{},
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "candidates", "foo@1.0.0", "pnpm-lock.yaml")); err != nil {
		t.Errorf("candidates/foo@1.0.0/pnpm-lock.yaml: %v", err)
	}
}

// assertNowhere fails when a regular file under root holds secret.
func assertNowhere(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("%s holds the secret", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// pnpm runs as the tools account, which can replace the lockfile it writes
// with a link to the signing key.
func TestAnalysisCopiesNoLinkedLockfile(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY----- a key the tools account must never read"
	key := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(key, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte("#!/bin/sh\nln -s '"+key+"' pnpm-lock.yaml\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	registry := registryServer(t, map[string]string{"foo": fooDoc})
	a := &Analysis{
		Store:    st,
		Tools:    newTestToolsManager(t, st),
		Pnpm:     runner.NewPnpmCLI(t.TempDir(), "", nil),
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	var events []Event
	err := a.Run(context.Background(), func(e Event) { events = append(events, e) })
	if err == nil {
		t.Fatal("Run succeeded, want the lockfile refused")
	}
	if !strings.Contains(err.Error(), "pnpm-lock.yaml is not a regular file") {
		t.Errorf("Run error = %q, want the lockfile refused", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("Run error %q quotes the secret", err)
	}
	for _, e := range events {
		if strings.Contains(string(e.Data), secret) {
			t.Errorf("event %s quotes the secret", e.Kind)
		}
	}
	assertNowhere(t, st.Root(), secret)
}

// A project whose target names another pnpm than the default target runs
// that pnpm for every resolution, never the default one.
func TestAnalysisRunsThePnpmOfTheProjectTarget(t *testing.T) {
	st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
	mgr := newTestToolsManager(t, st)
	ran := filepath.Join(t.TempDir(), "ran.txt")
	lock := "lockfileVersion: '9.0'\npackages:\n  foo@1.0.0:\n    resolution: {integrity: sha512-" + strings.Repeat("A", 86) + "==}\n"
	const other = "9.15.9"
	for _, version := range []string{st.Settings().Target.PnpmVer, other} {
		bin := filepath.Join(st.Root(), "tools", "pnpm", version, "package", "bin", "pnpm.cjs")
		if err := os.MkdirAll(filepath.Dir(bin), 0o770); err != nil {
			t.Fatal(err)
		}
		script := "echo " + version + " >> '" + ran + "'\nprintf '%s' \"" + lock + "\" > pnpm-lock.yaml\n"
		if err := os.WriteFile(bin, []byte(script), 0o664); err != nil {
			t.Fatal(err)
		}
	}
	node := t.TempDir()
	if err := os.WriteFile(filepath.Join(node, "node"), []byte("#!/bin/sh\nexec /bin/sh \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", node+string(os.PathListSeparator)+os.Getenv("PATH"))

	proj.Target.PnpmVer = other
	registry := registryServer(t, map[string]string{"foo": fooDoc})
	a := &Analysis{
		Store:    st,
		Tools:    mgr,
		Pnpm:     runner.NewPnpmCLI(t.TempDir(), "", nil),
		Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
		Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
		Project:  proj,
		Settings: st.Settings(),
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := os.ReadFile(ran)
	if err != nil {
		t.Fatalf("no pnpm ran: %v", err)
	}
	lines := strings.Fields(string(got))
	if len(lines) == 0 {
		t.Fatal("no pnpm ran")
	}
	for _, v := range lines {
		if v != other {
			t.Fatalf("pnpm versions that ran = %q, want only %s", lines, other)
		}
	}
}

// lockSwap answers the resolutions match picks with lock instead.
type lockSwap struct {
	*fakePnpm
	match func(manifest string) bool
	lock  []byte
}

func (l lockSwap) Resolve(ctx context.Context, in runner.ResolveInput) (runner.ResolveResult, error) {
	res, err := l.fakePnpm.Resolve(ctx, in)
	if err == nil && l.match(string(in.Manifest)) {
		res.Lockfile = l.lock
	}
	return res, err
}

func TestAnalysisWritesNoLockfileItCannotParse(t *testing.T) {
	const secret = "a value no lockfile may carry to disk"
	notProbe := func(m string) bool { return !strings.Contains(m, `"name":"probe"`) }
	for _, tc := range []struct {
		rel   string
		match func(string) bool
	}{
		{filepath.Join("project", "pnpm-lock.yaml"), func(m string) bool { return notProbe(m) && strings.Contains(m, `"foo":"1.0.0"`) }},
		{filepath.Join("combined", "pnpm-lock.yaml"), func(m string) bool { return notProbe(m) && strings.Contains(m, `"foo":"1.1.0"`) }},
	} {
		t.Run(tc.rel, func(t *testing.T) {
			st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"foo":"1.0.0"}}`)
			registry := registryServer(t, map[string]string{"foo": fooDoc})
			a := &Analysis{
				Store: st,
				Tools: newTestToolsManager(t, st),
				Pnpm:  lockSwap{fakePnpm: &fakePnpm{}, match: tc.match, lock: []byte("lockfileVersion: '5.4'\nleak: " + secret + "\n")},
				Trivy: &fakeTrivy{db: map[string][]fakeFinding{
					"foo@1.0.0": {{id: "CVE-2020-1", severity: "HIGH", fixed: "1.1.0"}},
				}},
				Registry: &npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
				Project:  proj,
				Settings: st.Settings(),
				Dir:      pending.Path(),
				ID:       pending.ID(),
			}
			_ = a.Run(context.Background(), func(Event) {})
			assertNowhere(t, st.Root(), secret)
		})
	}
}

// The tools account writes the project's files and the analysis's scan
// reports. A FIFO it leaves there must not hold the analysis.
func TestAnalysisReadsNoFIFOTheToolsAccountLeft(t *testing.T) {
	t.Run("at the project's package.json", func(t *testing.T) {
		st, proj, pending := newAnalysisProject(t, `{"name":"demo","dependencies":{"baz":"1.0.0"}}`)
		fifo := replaceWithFIFO(t, filepath.Join(proj.Dir, "package.json"))
		a := &Analysis{
			Store:    st,
			Tools:    newTestToolsManager(t, st),
			Pnpm:     &fakePnpm{},
			Trivy:    &fakeTrivy{db: map[string][]fakeFinding{}},
			Registry: &npm.Client{Registry: "http://127.0.0.1:1", Attempts: 1, Backoff: func(int) time.Duration { return 0 }},
			Project:  proj,
			Settings: st.Settings(),
			Dir:      pending.Path(),
			ID:       pending.ID(),
		}
		var err error
		returnsPromptly(t, fifo, func() { err = a.Run(context.Background(), func(Event) {}) })
		if err == nil || !strings.Contains(err.Error(), "package.json is not a regular file") {
			t.Fatalf("Run = %v, want package.json refused", err)
		}
	})
	t.Run("at a scan's report", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "project.trivy.json")
		a := &Analysis{Trivy: fifoTrivy{&exportTrivy{cannedTrivy: &cannedTrivy{}}}}
		var err error
		returnsPromptly(t, out, func() { _, err = a.scanPackages(context.Background(), nil, out) })
		if err == nil || !strings.Contains(err.Error(), "project.trivy.json is not a regular file") {
			t.Fatalf("scanPackages = %v, want the report refused", err)
		}
	})
	t.Run("at a report to merge", func(t *testing.T) {
		dir := t.TempDir()
		key := filepath.Join(dir, "candidates.trivy.key.json")
		if err := syscall.Mkfifo(key, 0o660); err != nil {
			t.Fatal(err)
		}
		var err error
		returnsPromptly(t, key, func() { err = mergeTrivyReports([]string{key}, filepath.Join(dir, "candidates.trivy.json")) })
		if err == nil || !strings.Contains(err.Error(), "candidates.trivy.key.json is not a regular file") {
			t.Fatalf("mergeTrivyReports = %v, want the report refused", err)
		}
	})
}
