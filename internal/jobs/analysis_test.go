package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
}

func (f *fakePnpm) Resolve(ctx context.Context, in runner.ResolveInput) (runner.ResolveResult, error) {
	f.mu.Lock()
	f.calls++
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
// newer version that fails to resolve (spec section 4, step 6 failure).
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
	if result.After != (Vector{0, 0, 0, 0, 0}) {
		t.Errorf("After = %v, want none", result.After)
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

// TestAnalysis_RegistryUnreachable covers a dependency whose registry
// metadata never answers (spec section 4, step 5 failure): the job marks it
// and continues, rather than failing outright.
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

// TestAnalysis_CancelledRunLeavesDirectory covers a run cancelled mid-flight
// (spec section 4, "Cancel and restart"): the directory and its log stay on
// disk, and status.json records the cancellation.
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
