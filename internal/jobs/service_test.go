package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/pip"
)

// noopPnpm and noopTrivy are runner.Pnpm and runner.Trivy that never touch
// a real binary. Service.QueueAnalysis and QueueExport only build a job
// and hand it to the queue; what a real Analysis or Export does with
// these once running belongs to their own tests, not this one.
type noopPnpm struct{}

func (noopPnpm) Resolve(context.Context, runner.ResolveInput) (runner.ResolveResult, error) {
	return runner.ResolveResult{}, nil
}

type noopTrivy struct{}

func (noopTrivy) ScanSBOM(context.Context, string, string) (string, error)           { return "", nil }
func (noopTrivy) ConvertToCycloneDX(context.Context, string, string) (string, error) { return "", nil }
func (noopTrivy) UpdateDB(context.Context) (string, error)                           { return "", nil }

// unroutable is a loopback address nothing listens on, so tools.Manager
// calls that would otherwise reach GitHub or the npm registry fail at
// once instead of depending on network access.
const unroutable = "http://127.0.0.1:1"

func newTestService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	q := NewQueue(testLogger())
	t.Cleanup(q.Close)
	tm := tools.NewManager(st, nil, nil)
	tm.GitHubAPI = unroutable
	tm.NPMRegistry = unroutable
	svc := NewService(st, q, tm, noopPnpm{}, noopTrivy{}, &npm.Client{})
	return svc, st
}

func TestQueueAnalysisReturnsQueuedAndTracksLiveState(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	if info.State != store.Queued {
		t.Errorf("State = %q, want %q", info.State, store.Queued)
	}
	if info.ProjectID != project.ID {
		t.Errorf("ProjectID = %q, want %q", info.ProjectID, project.ID)
	}

	if state, _, ok := svc.LiveState(project.ID, "analysis", info.ID); !ok || (state != store.Queued && state != store.Running) {
		t.Errorf("LiveState(%s) = (%q, %v), want a live queued or running state", info.ID, state, ok)
	}

	waitForTerminal(t, svc, project.ID, "analysis", info.ID)

	if _, _, ok := svc.LiveState(project.ID, "analysis", info.ID); ok {
		t.Errorf("LiveState after the job ended = tracked, want Service to have released it")
	}
}

func TestQueueAnalysisUnknownProjectReturnsErrNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.QueueAnalysis("does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("QueueAnalysis(unknown project) = %v, want ErrNotFound", err)
	}
}

func TestQueueAnalysisPicksTheJobByEcosystem(t *testing.T) {
	statusKeys := func(t *testing.T, st *store.Store, projectID, id string) map[string]json.RawMessage {
		t.Helper()
		var raw map[string]json.RawMessage
		if err := st.ReadJSON(filepath.Join(st.Root(), "projects", projectID, "analyses", id, "status.json"), &raw); err != nil {
			t.Fatalf("read status.json: %v", err)
		}
		return raw
	}
	pipFiles := []store.RequirementsFile{{Name: "requirements.txt", Data: []byte("requests==2.32.3\n")}}

	t.Run("npm runs the npm analysis", func(t *testing.T) {
		svc, st := newTestService(t)
		svc.SetPip(&fakeUv{}, &pip.Client{Index: unroutable})
		project := mustCreateProject(t, st)
		info, err := svc.QueueAnalysis(project.ID)
		if err != nil {
			t.Fatalf("QueueAnalysis: %v", err)
		}
		waitForTerminal(t, svc, project.ID, "analysis", info.ID)
		raw := statusKeys(t, st, project.ID, info.ID)
		if raw["target"] == nil || raw["pipTarget"] != nil {
			t.Errorf("status.json = %v, want the npm target and no pip target", raw)
		}
	})
	t.Run("pip runs the pip analysis", func(t *testing.T) {
		svc, st := newTestService(t)
		svc.tools.PipIndex = unroutable
		svc.SetPip(&fakeUv{}, &pip.Client{Index: unroutable})
		project, err := st.CreatePipProject("Data tools", pipFiles, store.DefaultPipTarget)
		if err != nil {
			t.Fatalf("CreatePipProject: %v", err)
		}
		info, err := svc.QueueAnalysis(project.ID)
		if err != nil {
			t.Fatalf("QueueAnalysis: %v", err)
		}
		waitForTerminal(t, svc, project.ID, "analysis", info.ID)
		raw := statusKeys(t, st, project.ID, info.ID)
		if raw["pipTarget"] == nil || raw["target"] != nil {
			t.Errorf("status.json = %v, want the pip target and no npm target", raw)
		}
	})
	t.Run("pip without a resolver is refused", func(t *testing.T) {
		svc, st := newTestService(t)
		project, err := st.CreatePipProject("Data tools", pipFiles, store.DefaultPipTarget)
		if err != nil {
			t.Fatalf("CreatePipProject: %v", err)
		}
		if _, err := svc.QueueAnalysis(project.ID); err == nil || !strings.Contains(err.Error(), "pip") {
			t.Fatalf("QueueAnalysis = %v, want a refusal naming pip", err)
		}
		if analyses, err := st.Analyses(project.ID); err != nil || len(analyses) != 0 {
			t.Errorf("analyses = %+v (%v), want none reserved", analyses, err)
		}
	})
}

// foo's only fix, 2.0.0, leaves major 1, so only a review that allows other
// majors proposes it.
func TestQueueAnalysisAppliesTheServicesReviewRules(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	project, err := st.CreateProject("demo", []byte(`{"name":"demo","dependencies":{"foo":"1.0.0"}}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	registry := registryServer(t, map[string]string{"foo": `{"name":"foo","versions":{
	"1.0.0":{"version":"1.0.0"},
	"2.0.0":{"version":"2.0.0"}
},"time":{"1.0.0":"2020-01-01T00:00:00.000Z","2.0.0":"2020-02-01T00:00:00.000Z"}}`})
	trivy := &fakeTrivy{db: map[string][]fakeFinding{
		"foo@1.0.0": {{id: "CVE-2020-1", severity: "HIGH", fixed: "2.0.0"}},
	}}
	q := NewQueue(testLogger())
	t.Cleanup(q.Close)
	svc := NewService(st, q, newTestToolsManager(t, st), &fakePnpm{}, trivy,
		&npm.Client{Registry: registry.URL, Attempts: 1, Backoff: func(int) time.Duration { return 0 }})
	svc.Review = policy.DefaultReview()
	svc.Review.ProposeOtherMajors = true

	events, unsubscribe := svc.Subscribe()
	defer unsubscribe()
	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	for deadline := time.After(10 * time.Second); ; {
		select {
		case e := <-events:
			if e.Kind != "end" {
				continue
			}
		case <-deadline:
			t.Fatal("the analysis never ended")
		}
		break
	}
	waitForTerminal(t, svc, project.ID, "analysis", info.ID)

	var result Result
	if err := st.ReadJSON(filepath.Join(st.Root(), "projects", project.ID, "analyses", info.ID, "ranking.json"), &result); err != nil {
		t.Fatalf("read ranking.json: %v", err)
	}
	if len(result.Dependencies) != 1 || result.Dependencies[0].Best != "2.0.0" {
		t.Errorf("dependencies = %+v, want foo to propose 2.0.0, as the service's review allows other majors", result.Dependencies)
	}
}

func TestQueueExportRefusesAnAnalysisNotDone(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	analysisDir := filepath.Join(st.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"failed"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}

	if _, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{}}); !errors.Is(err, ErrAnalysisNotDone) {
		t.Fatalf("QueueExport on a failed analysis = %v, want ErrAnalysisNotDone", err)
	}
}

func TestQueueExportNeedsNoKey(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(st.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}

	info, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport with no setting beyond the defaults: %v", err)
	}
	waitForTerminal(t, svc, project.ID, "export", info.ID)
}

func TestQueueExportBuildsAndQueuesAJobOnceReady(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(st.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}

	// An empty selection is refused on its own (see the test below); the
	// current tree still gives this export something to pack.
	info, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	if info.State != store.Queued || info.AnalysisID != "20260917T101502Z" {
		t.Fatalf("ExportInfo = %+v, want state queued for analysis 20260917T101502Z", info)
	}
	waitForTerminal(t, svc, project.ID, "export", info.ID)
}

func TestQueueExportRefusesAnUnknownSelectionEntry(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],` +
		`"dependencies":[{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"candidates":[{"version":"1.3.1","vector":[0,0,0,0,0],"signals":[],"key":true,"resolved":true}]}],"warnings":[]}`
	analysisDir := filepath.Join(st.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}

	// "1.9.9" is neither left-pad's current version nor one of its
	// candidates: the analysis never resolved it.
	_, err = svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{"left-pad": {"1.9.9"}}})
	var invalid *ErrInvalidSelection
	if !errors.As(err, &invalid) {
		t.Fatalf("QueueExport(unknown selection) = %v, want *ErrInvalidSelection", err)
	}
	if len(invalid.Bad) != 1 || invalid.Bad[0] != "left-pad@1.9.9" {
		t.Fatalf("invalid.Bad = %v, want [%q]", invalid.Bad, "left-pad@1.9.9")
	}

	// Validation happens before any directory is reserved: a rejected
	// export leaves nothing behind to clean up.
	exports, err := st.Exports(project.ID)
	if err != nil {
		t.Fatalf("Exports: %v", err)
	}
	if len(exports) != 0 {
		t.Fatalf("Exports() = %v, want none: a rejected selection must reserve nothing", exports)
	}
	entries, err := os.ReadDir(filepath.Join(st.Root(), "projects", project.ID, "exports"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadDir exports: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("exports dir = %v, want empty, no stray .tmp directory", entries)
	}
}

func TestLiveForProjectReportsAndClearsTheTrackedJob(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	if _, _, _, _, ok := svc.LiveForProject(project.ID); ok {
		t.Fatal("LiveForProject before anything is queued: want ok = false")
	}

	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	id, kind, state, _, ok := svc.LiveForProject(project.ID)
	if !ok || id != info.ID || kind != "analysis" || (state != store.Queued && state != store.Running) {
		t.Fatalf("LiveForProject = (%q, %q, %q, %v), want (%q, \"analysis\", queued or running, true)", id, kind, state, ok, info.ID)
	}

	waitForTerminal(t, svc, project.ID, "analysis", info.ID)

	if _, _, _, _, ok := svc.LiveForProject(project.ID); ok {
		t.Error("LiveForProject after the job ended = tracked, want Service to have released it")
	}
}

// TestServiceReconcilesAnalysisStatusToTheQueuesOwnOutcome simulates the
// exact disagreement IMPORTANT C guards against: a job that finishes on
// its own (Run returns nil) but, racing its own best-effort read of
// ctx.Err(), commits a status.json claiming state cancelled. The queue
// says the job actually completed; Service's finalizer must make that
// the status.json the store reads back, not the job's own guess.
func TestServiceReconcilesAnalysisStatusToTheQueuesOwnOutcome(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	pending, err := st.NewDir("analyses", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	job := &fakeJob{kind: "analysis", run: func(_ context.Context, _ func(Event)) error {
		// The job's own best-effort account, written the way Analysis.Run
		// does in its defer: wrong here, on purpose, to prove the queue's
		// account wins.
		body := []byte(`{"state":"cancelled","step":"resolve"}`)
		if err := os.WriteFile(filepath.Join(pending.Path(), "status.json"), body, 0o664); err != nil {
			return err
		}
		return os.Rename(pending.Path(), pending.Final())
	}}
	// Registered inside Submit, as the service does: tracking afterwards
	// races a job that finishes first.
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "analysis", project.ID, "", pending)
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	waitForTerminal(t, svc, project.ID, "analysis", pending.ID())

	var status struct {
		State string `json:"state"`
		Step  string `json:"step"`
	}
	if err := st.ReadJSON(filepath.Join(pending.Final(), "status.json"), &status); err != nil {
		t.Fatalf("ReadJSON status.json: %v", err)
	}
	if status.State != string(store.Done) {
		t.Errorf("status.json state = %q, want %q (the queue's own outcome, Run returned nil)", status.State, store.Done)
	}
	if status.Step != "resolve" {
		t.Errorf("status.json step = %q, want it untouched (%q)", status.Step, "resolve")
	}
}

// TestServiceFinalizesEvenWhenASubscriberNeverReadsAndEventsOverflow
// proves Service's finalize hook, not a Subscribe channel, is what
// commits a job's directory and reconciles its status.json. With a
// subscriber that never reads, and enough events emitted to overflow its
// buffer well past its own "end" event, a Subscribe-based finalizer
// would have dropped every one of them for this job, including the
// event that told it the job was even over.
func TestServiceFinalizesEvenWhenASubscriberNeverReadsAndEventsOverflow(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	pending, err := st.NewDir("analyses", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	_, unsubscribe := svc.queue.Subscribe()
	defer unsubscribe()

	const eventCount = 500
	job := &fakeJob{kind: "analysis", run: func(_ context.Context, emit func(Event)) error {
		for i := 0; i < eventCount; i++ {
			emit(Event{Kind: "log", Data: json.RawMessage(`{"line":"x"}`)})
		}
		// The job's own best-effort account, wrong here on purpose (as in
		// TestServiceReconcilesAnalysisStatusToTheQueuesOwnOutcome above),
		// to prove the queue's own outcome is what status.json ends up
		// holding.
		body := []byte(`{"state":"cancelled","step":"resolve"}`)
		if err := os.WriteFile(filepath.Join(pending.Path(), "status.json"), body, 0o664); err != nil {
			return err
		}
		return os.Rename(pending.Path(), pending.Final())
	}}
	// Registered inside Submit, as the service does: tracking afterwards
	// races a job that finishes first.
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "analysis", project.ID, "", pending)
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	waitForTerminal(t, svc, project.ID, "analysis", pending.ID())

	if _, err := os.Stat(pending.Final()); err != nil {
		t.Fatalf("committed analysis directory missing: %v", err)
	}

	var status struct{ State string }
	if err := st.ReadJSON(filepath.Join(pending.Final(), "status.json"), &status); err != nil {
		t.Fatalf("ReadJSON status.json: %v", err)
	}
	if status.State != string(store.Done) {
		t.Errorf("status.json state = %q, want %q (the queue's own outcome, Run returned nil)", status.State, store.Done)
	}
}

// TestSubscribeCarriesTheStoreIDIncludingOnTheEndEvent proves Subscribe
// fills in StoreID on every event, including "end": finalize untracks the
// job (removing it from byQueueID) before the queue publishes that event,
// so a lookup made only at delivery time would find nothing left to map
// the queue id back to.
func TestSubscribeCarriesTheStoreIDIncludingOnTheEndEvent(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	pending, err := st.NewDir("analyses", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	events, unsubscribe := svc.Subscribe()
	defer unsubscribe()

	// Analysis and Export carry their store id, and the queue stamps it on
	// every event. A job without one would depend on the service's index,
	// which the finalizer empties before the end event goes out.
	job := storeIDJob{fakeJob: &fakeJob{kind: "analysis", run: func(_ context.Context, emit func(Event)) error {
		emit(Event{Kind: "step", Data: json.RawMessage(`{"name":"resolve","state":"running"}`)})
		return os.Rename(pending.Path(), pending.Final())
	}}, id: pending.ID()}
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "analysis", project.ID, "", pending)
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	var step, end Event
	for step.Kind == "" || end.Kind == "" {
		select {
		case e := <-events:
			switch e.Kind {
			case "step":
				step = e
			case "end":
				end = e
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for the step and end events")
		}
	}

	if step.StoreID != pending.ID() {
		t.Errorf("step event StoreID = %q, want %q", step.StoreID, pending.ID())
	}
	if end.StoreID != pending.ID() {
		t.Errorf("end event StoreID = %q, want %q", end.StoreID, pending.ID())
	}
}

func TestCancelUntrackedIDReturnsErrNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Cancel("no-such-project", "analysis", "no-such-id"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Cancel(untracked) = %v, want ErrNotFound", err)
	}
}

// TestLiveStateKeysByProjectKindAndID proves the fix for the id collision
// store.NewDir's own defense does not cover: it only retries within one
// project's one kind directory, so two different projects can get the
// exact same analysis id when both are queued in the same second. Both
// must stay independently addressable by their own project, not have the
// second registration silently replace the first.
func TestLiveStateKeysByProjectKindAndID(t *testing.T) {
	svc, st := newTestService(t)
	projectA := mustCreateProject(t, st)
	projectB, err := st.CreateProject("right-pad", []byte(`{"name":"right-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	pendingA, pendingB := sameSecondPendings(t, st, "analyses", projectA.ID, "analyses", projectB.ID)
	svc.track("fake-queue-a", "analysis", projectA.ID, "", pendingA)
	svc.track("fake-queue-b", "analysis", projectB.ID, "", pendingB)

	if state, _, ok := svc.LiveState(projectA.ID, "analysis", pendingA.ID()); !ok || state != store.Queued {
		t.Fatalf("LiveState(project A) = (%q, %v), want (queued, true): its id collided with project B's, it must still be addressable", state, ok)
	}
	if state, _, ok := svc.LiveState(projectB.ID, "analysis", pendingB.ID()); !ok || state != store.Queued {
		t.Fatalf("LiveState(project B) = (%q, %v), want (queued, true): tracking it must not have dropped project A's entry", state, ok)
	}
}

// TestCancelRejectsAKindMismatch proves the matching hole G1 closes in
// Cancel: an id tracked under one kind must not be reachable through
// another kind's route, even though both would share the same lookup key
// if it ignored kind, such as an export cancelled through the analyses
// route.
func TestCancelRejectsAKindMismatch(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	pending, err := st.NewDir("exports", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	svc.track("fake-queue-id", "export", project.ID, "", pending)

	if _, err := svc.Cancel(project.ID, "analysis", pending.ID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Cancel(analysis route, an export's id) = %v, want ErrNotFound", err)
	}
	if state, _, ok := svc.LiveState(project.ID, "export", pending.ID()); !ok || state != store.Queued {
		t.Fatalf("LiveState(export route) = (%q, %v), want (queued, true): the mismatched cancel above must not have removed it", state, ok)
	}
}

// sameSecondPendings retries store.NewDir for the two kind/project pairs
// until both land on the same id, forcing the exact collision
// store.NewDir's own defense does not cover (two different projects, or
// an analysis and an export, reserved in the same second). The retry
// loop makes the test deterministic instead of waiting on a real clock
// boundary; in practice it resolves on the first attempt.
func sameSecondPendings(t *testing.T, st *store.Store, kindA, projectA, kindB, projectB string) (*store.Pending, *store.Pending) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a, err := st.NewDir(kindA, projectA)
		if err != nil {
			t.Fatalf("NewDir(%s, %s): %v", kindA, projectA, err)
		}
		b, err := st.NewDir(kindB, projectB)
		if err != nil {
			t.Fatalf("NewDir(%s, %s): %v", kindB, projectB, err)
		}
		if a.ID() == b.ID() {
			return a, b
		}
		_ = a.Discard()
		_ = b.Discard()
	}
	t.Fatal("could not force two directories into the same second within the deadline")
	return nil, nil
}

func TestFinalizePendingDiscardsAnEmptyDirectory(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	pending, err := st.NewDir("analyses", mustCreateProject(t, st).ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}

	if err := finalizePending(pending); err != nil {
		t.Fatalf("finalizePending: %v", err)
	}

	if _, err := os.Stat(pending.Path()); !os.IsNotExist(err) {
		t.Fatalf("pending path after finalize: err = %v, want it discarded", err)
	}
}

func TestFinalizePendingCommitsANonEmptyDirectory(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	pending, err := st.NewDir("exports", mustCreateProject(t, st).ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pending.Path(), "packages_npm.tar.gz"), []byte("data"), 0o664); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	if err := finalizePending(pending); err != nil {
		t.Fatalf("finalizePending: %v", err)
	}

	if _, err := os.Stat(pending.Path()); !os.IsNotExist(err) {
		t.Fatalf("pending .tmp path still exists after finalize, want it committed")
	}
	final := pending.Path()[:len(pending.Path())-len(".tmp")]
	if _, err := os.Stat(filepath.Join(final, "packages_npm.tar.gz")); err != nil {
		t.Fatalf("committed archive: %v", err)
	}
}

func mustCreateProject(t *testing.T, st *store.Store) store.Project {
	t.Helper()
	p, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	return p
}

// waitForTerminal polls LiveState until Service is no longer tracking id
// under project and kind, meaning the finalizer has already reacted to
// its "end" event.
func waitForTerminal(t *testing.T, svc *Service, projectID, kind, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := svc.LiveState(projectID, kind, id); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s was still tracked after the deadline", id)
}

// storeIDJob is a fakeJob that knows its store directory id, as Analysis
// and Export do.
type storeIDJob struct {
	*fakeJob
	id string
}

func (j storeIDJob) StoreID() string { return j.id }

// A selection with no version and no current tree packs an archive with
// no package in it, which a user would carry through the kiosk believing
// it fixed every CVE. It says so before it asks a reason for lodash's CVE,
// which nothing would carry.
func TestQueueExportRefusesAnExportWithNothingToPack(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,1,0,0,0],"after":[0,1,0,0,0],` +
		`"dependencies":[{"name":"lodash","current":"4.17.20","vector":[0,1,0,0,0],"cves":[{"id":"CVE-2021-23337","severity":"HIGH"}],"candidates":[]}],"warnings":[]}`
	analysisDir := filepath.Join(st.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}

	for name, sel := range map[string]map[string][]string{
		"nil":                nil,
		"empty":              {},
		"only empty entries": {"lodash": {}},
	} {
		if _, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: sel}); !errors.Is(err, ErrNothingToExport) {
			t.Errorf("%s selection: QueueExport = %v, want ErrNothingToExport", name, err)
		}
	}
}

// noExportReserved fails t when the project holds an export directory.
func noExportReserved(t *testing.T, project store.Project) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(project.Dir, "exports"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("exports/ holds %d entries, want none reserved", len(entries))
	}
}

func TestQueueExportQueuesAPipExport(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	events, unsubscribe := f.svc.Subscribe()
	defer unsubscribe()
	queued, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: map[string][]string{}})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	if queued.State != store.Queued || queued.AnalysisID != f.ref.ID {
		t.Errorf("queued = %+v, want queued for analysis %s", queued, f.ref.ID)
	}
	for e := range events {
		if e.Kind == "end" && e.StoreID == queued.ID {
			break
		}
	}
	info, err := f.st.ExportInfo(f.project.ID, queued.ID)
	if err != nil {
		t.Fatalf("ExportInfo: %v", err)
	}
	if info.State != store.Done {
		t.Fatalf("export state = %s (%+v), want done", info.State, info.Failure)
	}
	if want := pipExportFiles; !slices.Equal(info.Files, want) {
		t.Errorf("files = %v, want %v", info.Files, want)
	}
}

func TestQueueExportRefusesASelectionForPip(t *testing.T) {
	tests := []struct {
		name      string
		selection map[string][]string
	}{
		{"a version of a package", map[string][]string{"requests": {"2.32.3"}}},
		{"a package with no version", map[string][]string{"requests": {}}},
	}
	f := donePipAnalysis(t, piptest.NewIndex(t))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: tc.selection, IncludeProject: true})
			if !errors.Is(err, ErrPipSelection) || !strings.Contains(err.Error(), "carries the analysis's whole set and takes no selection") {
				t.Fatalf("QueueExport = %v, want ErrPipSelection", err)
			}
			noExportReserved(t, f.project)
		})
	}
}

// A cancel that lands after the scan step leaves a complete pip-result.json
// in an analysis that is not done, so the state alone must refuse it.
func TestQueueExportRefusesAPipAnalysisNotDone(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	statusPath := filepath.Join(f.ref.Dir, "status.json")
	var status map[string]any
	if err := f.st.ReadJSON(statusPath, &status); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.ref.Dir, "pip-result.json")); err != nil {
		t.Fatalf("the analysis has no pip-result.json: %v", err)
	}
	for _, state := range []store.State{store.Failed, store.Cancelled, store.Interrupted} {
		t.Run(string(state), func(t *testing.T) {
			status["state"] = state
			if err := f.st.WriteJSON(statusPath, status); err != nil {
				t.Fatal(err)
			}
			_, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: map[string][]string{}})
			if want := "analysis " + f.ref.ID + " is " + string(state); !errors.Is(err, ErrAnalysisNotDone) || !strings.Contains(err.Error(), want) {
				t.Fatalf("QueueExport = %v, want ErrAnalysisNotDone saying %q", err, want)
			}
			noExportReserved(t, f.project)
		})
	}
}

func TestQueueExportRefusesAPipAnalysisWithoutEveryWheel(t *testing.T) {
	tests := []struct {
		name   string
		result func(PipResult) any
		reason string
	}{
		{"one package without a wheel", func(r PipResult) any {
			r.Packages = clonePipPackages(r.Packages)
			r.Packages[1].Wheel = nil
			return r
		}, "1 of 3 packages has no wheel"},
		{"two packages without a wheel", func(r PipResult) any {
			r.Packages = clonePipPackages(r.Packages)
			r.Packages[0].Wheel, r.Packages[2].Wheel = nil, nil
			return r
		}, "2 of 3 packages have no wheel"},
		{"a result that is no JSON object", func(PipResult) any { return []string{"not", "a", "result"} }, "has no readable result"},
	}
	f := donePipAnalysis(t, piptest.NewIndex(t))
	path := filepath.Join(f.ref.Dir, "pip-result.json")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.st.WriteJSON(path, tc.result(f.ref.Result)); err != nil {
				t.Fatal(err)
			}
			_, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: map[string][]string{}})
			if !errors.Is(err, ErrPipNotExportable) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("QueueExport = %v, want ErrPipNotExportable saying %q", err, tc.reason)
			}
			noExportReserved(t, f.project)
		})
	}
}

func TestQueueExportRefusesPipWithoutTheIndex(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	f.svc.SetPip(nil, nil)
	_, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: map[string][]string{}})
	if err == nil || !strings.Contains(err.Error(), "not set up to export pip projects") {
		t.Fatalf("QueueExport = %v, want a refusal saying the server cannot export pip", err)
	}
	noExportReserved(t, f.project)
}

// The import refuses a manifest that lists no package, so an archive of an
// empty set would cross the air gap only to be refused at the kiosk.
func TestQueueExportRefusesAnEmptyPipAnalysis(t *testing.T) {
	f := runPipAnalysis(t, piptest.NewIndex(t).URL, "# nothing pinned\n", nil)
	if n := len(f.ref.Result.Packages); n != 0 {
		t.Fatalf("the analysis lists %d packages, want none", n)
	}
	_, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: map[string][]string{}})
	if want := "analysis " + f.ref.ID + " lists no package"; !errors.Is(err, ErrPipNotExportable) || !strings.Contains(err.Error(), want) {
		t.Fatalf("QueueExport = %v, want ErrPipNotExportable saying %q", err, want)
	}
	noExportReserved(t, f.project)
}

// statusFIFOTrivy converts as exportTrivy does, after leaving a FIFO at
// status.json in the export directory, as the tools account could.
type statusFIFOTrivy struct{ *exportTrivy }

func (x statusFIFOTrivy) ConvertToCycloneDX(ctx context.Context, inPath, outPath string) (string, error) {
	if err := syscall.Mkfifo(filepath.Join(filepath.Dir(outPath), "status.json"), 0o660); err != nil {
		return "", err
	}
	return x.exportTrivy.ConvertToCycloneDX(ctx, inPath, outPath)
}

// A done export writes no status.json, so the finalize hook finds the FIFO
// the tools account left there. Reading it must not hold the serial queue.
func TestServiceRunsTheNextJobAfterAnExportLeftAFIFOAtStatusJSON(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	f.svc.trivy = statusFIFOTrivy{&exportTrivy{cannedTrivy: &cannedTrivy{report: pipTrivyReport()}}}
	queued, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Selection: map[string][]string{}})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	next := make(chan struct{})
	if _, err := f.svc.queue.Submit(&fakeJob{kind: "analysis", started: next, run: func(context.Context, func(Event)) error { return nil }}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	fifo := filepath.Join(f.project.Dir, "exports", queued.ID, "status.json")
	select {
	case <-next:
	case <-time.After(5 * time.Second):
		// Let the held read end, so the queue can close with the test.
		for {
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
			select {
			case <-next:
				t.Fatal("the next job waited on the export's FIFO")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	if st, err := os.Lstat(fifo); err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("status.json = %v, %v, want the FIFO left as it was", st, err)
	}
}

// TestCancellingAQueuedAnalysisKeepsACancelledRecord proves an analysis
// the queue drops before it ever starts still leaves a directory the
// store lists as cancelled, with a log to open and the project's target,
// instead of vanishing, for an npm project and a pip one alike.
func TestCancellingAQueuedAnalysisKeepsACancelledRecord(t *testing.T) {
	pipFiles := []store.RequirementsFile{{Name: "requirements.txt", Data: []byte("requests==2.32.3\n")}}
	tests := []struct {
		name      string
		create    func(t *testing.T, st *store.Store) store.Project
		targetKey string
	}{
		{"npm", mustCreateProject, "target"},
		{"pip", func(t *testing.T, st *store.Store) store.Project {
			project, err := st.CreatePipProject("Data tools", pipFiles, store.DefaultPipTarget)
			if err != nil {
				t.Fatalf("CreatePipProject: %v", err)
			}
			return project
		}, "pipTarget"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, st := newTestService(t)
			svc.SetPip(&fakeUv{}, &pip.Client{Index: "http://127.0.0.1:1"})
			project := tc.create(t, st)

			blockQueue(t, svc)

			info, err := svc.QueueAnalysis(project.ID)
			if err != nil {
				t.Fatalf("QueueAnalysis: %v", err)
			}
			if _, err := svc.Cancel(project.ID, "analysis", info.ID); err != nil {
				t.Fatalf("Cancel: %v", err)
			}
			waitForTerminal(t, svc, project.ID, "analysis", info.ID)

			analyses, err := st.Analyses(project.ID)
			if err != nil {
				t.Fatalf("Analyses: %v", err)
			}
			var found *store.AnalysisInfo
			for i := range analyses {
				if analyses[i].ID == info.ID {
					found = &analyses[i]
				}
			}
			if found == nil {
				t.Fatalf("Analyses holds no record for the cancelled queued analysis %s", info.ID)
			}
			if found.State != store.Cancelled {
				t.Errorf("State = %q, want %q", found.State, store.Cancelled)
			}
			var status map[string]json.RawMessage
			if err := st.ReadJSON(filepath.Join(project.Dir, "analyses", info.ID, "status.json"), &status); err != nil {
				t.Fatalf("read status.json: %v", err)
			}
			if status[tc.targetKey] == nil {
				t.Errorf("status.json = %v, want the project's %s", status, tc.targetKey)
			}
			f, err := st.AnalysisLog(project.ID, info.ID)
			if err != nil {
				t.Fatalf("AnalysisLog: %v", err)
			}
			f.Close()
		})
	}
}

// TestCancellingAQueuedAnalysisNeverPublishesAStaleQueuedRecord proves a
// queued analysis whose state cannot be rewritten is not published as
// "queued": nothing runs it, so nothing would ever move it on.
func TestCancellingAQueuedAnalysisNeverPublishesAStaleQueuedRecord(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)

	blockQueue(t, svc)

	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	pendingDir := filepath.Join(project.Dir, "analyses", info.ID+".tmp")
	if err := os.Chmod(pendingDir, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(pendingDir, 0o755)
		_ = os.Chmod(strings.TrimSuffix(pendingDir, ".tmp"), 0o755)
	})

	if _, err := svc.Cancel(project.ID, "analysis", info.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	waitForTerminal(t, svc, project.ID, "analysis", info.ID)

	analyses, err := st.Analyses(project.ID)
	if err != nil {
		t.Fatalf("Analyses: %v", err)
	}
	for _, a := range analyses {
		if a.ID == info.ID && a.State == store.Queued {
			t.Errorf("analysis %s was published as %q with no job behind it", info.ID, a.State)
		}
	}
}

// TestAnalysisThatFailedBeforeItBeganKeepsItsCause proves a run that fails
// before its first write, such as one that cannot open its log, is
// published with a failed step and the run's error, so the screen can say
// what went wrong.
func TestAnalysisThatFailedBeforeItBeganKeepsItsCause(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	pending, err := st.NewDir("analyses", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	createdAt, _ := store.JobCreatedAt(pending.ID())
	if err := svc.seedPending(pending, createdAt, project); err != nil {
		t.Fatalf("seedPending: %v", err)
	}

	const cause = "jobs: open log.txt: permission denied"
	job := &fakeJob{kind: "analysis", run: func(context.Context, func(Event)) error {
		return errors.New(cause)
	}}
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "analysis", project.ID, "", pending)
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitForTerminal(t, svc, project.ID, "analysis", pending.ID())

	info, err := st.AnalysisInfo(project.ID, pending.ID())
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if info.State != store.Failed {
		t.Errorf("State = %q, want %q", info.State, store.Failed)
	}
	want := store.StepFailure{Step: "prepare", Message: cause}
	if info.Failure == nil || *info.Failure != want {
		t.Errorf("Failure = %+v, want %+v", info.Failure, want)
	}
	var status map[string]json.RawMessage
	if err := st.ReadJSON(filepath.Join(pending.Final(), "status.json"), &status); err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	if status["target"] == nil || status["createdAt"] == nil {
		t.Errorf("status.json = %v, want the queued record's target and creation time kept", status)
	}
}

// TestAnalysisThatFailedAfterItBeganKeepsItsSteps proves the prepare step
// is written only for a run that never started: a run that wrote its own
// steps, then failed without committing itself, keeps them and the cause
// its failed step recorded.
func TestAnalysisThatFailedAfterItBeganKeepsItsSteps(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	pending, err := st.NewDir("analyses", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	createdAt, _ := store.JobCreatedAt(pending.ID())
	if err := svc.seedPending(pending, createdAt, project); err != nil {
		t.Fatalf("seedPending: %v", err)
	}

	steps := []stepRecord{
		{Name: "validate", State: string(store.Done), DurationMs: 3},
		{Name: "prepare-tools", State: string(store.Done), DurationMs: 40},
		{Name: "resolve-project", State: string(store.Failed), DurationMs: 900, Error: "pnpm install: exit status 1"},
	}
	job := &fakeJob{kind: "analysis", run: func(context.Context, func(Event)) error {
		status := statusFile{State: store.Running, CreatedAt: createdAt, Target: project.Target, Steps: steps}
		if err := st.WriteJSON(filepath.Join(pending.Path(), "status.json"), status); err != nil {
			return err
		}
		// Returns without renaming, as Analysis.Run does when its own
		// commit fails.
		return errors.New("jobs: write status.json: no space left on device")
	}}
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "analysis", project.ID, "", pending)
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitForTerminal(t, svc, project.ID, "analysis", pending.ID())

	info, err := st.AnalysisInfo(project.ID, pending.ID())
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if info.State != store.Failed {
		t.Errorf("State = %q, want %q", info.State, store.Failed)
	}
	want := store.StepFailure{Step: "resolve-project", Message: "pnpm install: exit status 1"}
	if info.Failure == nil || *info.Failure != want {
		t.Errorf("Failure = %+v, want %+v", info.Failure, want)
	}
	var status statusFile
	if err := st.ReadJSON(filepath.Join(pending.Final(), "status.json"), &status); err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	if !slices.Equal(status.Steps, steps) {
		t.Errorf("steps = %+v, want the run's own %+v", status.Steps, steps)
	}
}

// TestAnalysisThatRanKeepsItsRunWhenItsStateCannotBeReconciled proves the
// finalizer never discards an analysis that wrote something. Its own
// commit can fail (a full volume fails the status write there and again
// in the reconcile), leaving the pending directory with the log and the
// ranking: that run explains the failure, so it is published, not removed.
func TestAnalysisThatRanKeepsItsRunWhenItsStateCannotBeReconciled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	for _, tc := range []struct {
		name string
		// afterRun runs on the pending directory once the job has written
		// its files.
		afterRun func(dir string) error
	}{
		{"unreadable status.json", func(dir string) error {
			return os.Chmod(filepath.Join(dir, "status.json"), 0)
		}},
		{"running status.json", func(string) error { return nil }},
		// The reconcile reads the state, then cannot write it back, as on
		// a full volume.
		{"running status.json that cannot be rewritten", func(dir string) error {
			return os.Chmod(dir, 0o555)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st := newTestService(t)
			project := mustCreateProject(t, st)
			pending, err := st.NewDir("analyses", project.ID)
			if err != nil {
				t.Fatalf("NewDir: %v", err)
			}
			t.Cleanup(func() {
				_ = os.Chmod(pending.Path(), 0o755)
				_ = os.Chmod(pending.Final(), 0o755)
			})

			job := &fakeJob{kind: "analysis", run: func(context.Context, func(Event)) error {
				files := map[string]string{
					"log.txt":      "resolving\n",
					"ranking.json": "{}",
					"status.json":  `{"state":"running"}`,
				}
				for file, body := range files {
					if err := os.WriteFile(filepath.Join(pending.Path(), file), []byte(body), 0o664); err != nil {
						return err
					}
				}
				if err := tc.afterRun(pending.Path()); err != nil {
					return err
				}
				// Returns without renaming, as Analysis.Run does when its
				// own commit fails.
				return errors.New("jobs: write status.json: no space left on device")
			}}
			if _, err := svc.queue.SubmitWith(job, func(queueID string) {
				svc.track(queueID, "analysis", project.ID, "", pending)
			}); err != nil {
				t.Fatalf("Submit: %v", err)
			}
			waitForTerminal(t, svc, project.ID, "analysis", pending.ID())

			for _, file := range []string{"log.txt", "ranking.json"} {
				if _, err := os.Stat(filepath.Join(pending.Final(), file)); err != nil {
					t.Errorf("the analysis that ran lost %s: %v", file, err)
				}
			}
		})
	}
}

// TestServiceKeepsAnExportCancelledWhileQueued proves an export dropped
// before it ever ran is committed as a cancelled export, not discarded: the
// export screen and the export list both need the record.
func TestServiceKeepsAnExportCancelledWhileQueued(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)

	blockQueue(t, svc)

	pending, err := st.NewDir("exports", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	const analysisID = "20260917T101502Z"
	queued := storeIDJob{fakeJob: &fakeJob{kind: "export", run: func(context.Context, func(Event)) error { return nil }}, id: pending.ID()}
	if _, err := svc.queue.SubmitWith(queued, func(queueID string) {
		svc.track(queueID, "export", project.ID, analysisID, pending)
	}); err != nil {
		t.Fatalf("Submit(export): %v", err)
	}

	if _, err := svc.Cancel(project.ID, "export", pending.ID()); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	waitForTerminal(t, svc, project.ID, "export", pending.ID())

	info, err := st.ExportInfo(project.ID, pending.ID())
	if err != nil {
		t.Fatalf("ExportInfo after a queued cancel = %v, want the cancelled record", err)
	}
	if info.State != store.Cancelled || info.AnalysisID != analysisID {
		t.Errorf("ExportInfo = %+v, want state cancelled for analysis %s", info, analysisID)
	}
}

// An export cancelled while running has already written its own
// status.json, with the steps it got through. The queued-cancel record must
// not overwrite it: the run's steps and failure cause would be lost.
func TestServiceKeepsTheStepsOfAnExportCancelledWhileRunning(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)

	pending, err := st.NewDir("exports", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	const analysisID = "20260917T101502Z"
	steps := []stepRecord{{Name: "download", State: string(store.Failed), DurationMs: 12, Error: "registry unreachable"}}
	started := make(chan struct{})
	run := func(ctx context.Context, _ func(Event)) error {
		close(started)
		<-ctx.Done()
		status := exportStatusFile{State: store.Cancelled, AnalysisID: analysisID, Steps: steps}
		if err := st.WriteJSON(filepath.Join(pending.Path(), "status.json"), status); err != nil {
			t.Errorf("WriteJSON: %v", err)
		}
		return ctx.Err()
	}
	job := storeIDJob{fakeJob: &fakeJob{kind: "export", run: run}, id: pending.ID()}
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "export", project.ID, analysisID, pending)
	}); err != nil {
		t.Fatalf("Submit(export): %v", err)
	}
	<-started

	if _, err := svc.Cancel(project.ID, "export", pending.ID()); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	waitForTerminal(t, svc, project.ID, "export", pending.ID())

	info, err := st.ExportInfo(project.ID, pending.ID())
	if err != nil {
		t.Fatalf("ExportInfo: %v", err)
	}
	if info.State != store.Cancelled || info.AnalysisID != analysisID {
		t.Errorf("ExportInfo = %+v, want state cancelled for analysis %s", info, analysisID)
	}
	if info.Failure == nil || info.Failure.Step != "download" || info.Failure.Message != "registry unreachable" {
		t.Errorf("ExportInfo.Failure = %+v, want the download step's failure kept", info.Failure)
	}
}

// blockQueue occupies the queue's one worker until the test ends, so a job
// submitted after it stays queued.
func blockQueue(t *testing.T, svc *Service) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	blocker := &fakeJob{kind: "fake", started: make(chan struct{}), run: func(ctx context.Context, _ func(Event)) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}}
	if _, err := svc.queue.Submit(blocker); err != nil {
		t.Fatalf("Submit(blocker): %v", err)
	}
	<-blocker.started
}

// occupyComingSeconds creates a committed directory under dir for every
// id the next minute could produce, so the store has to add its suffix to
// the next id it allocates there.
func occupyComingSeconds(t *testing.T, dir string) {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Second)
	for i := range 60 {
		id := start.Add(time.Duration(i) * time.Second).Format("20060102T150405Z")
		if err := os.MkdirAll(filepath.Join(dir, id), 0o770); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
}

// suffixedIDTime checks that id carries the store's suffix and returns the
// time its timestamp part names.
func suffixedIDTime(t *testing.T, id string) time.Time {
	t.Helper()
	stamp, suffix, ok := strings.Cut(id, "-")
	if !ok || len(suffix) != 6 {
		t.Fatalf("id = %q, want a timestamp with a six-digit suffix", id)
	}
	want, err := time.Parse("20060102T150405Z", stamp)
	if err != nil {
		t.Fatalf("parse %q: %v", stamp, err)
	}
	return want
}

func TestQueuedJobWithASuffixedIDKeepsItsCreationTime(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	projectDir := filepath.Join(st.Root(), "projects", project.ID)
	analysisDir := filepath.Join(projectDir, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	occupyComingSeconds(t, filepath.Join(projectDir, "analyses"))
	occupyComingSeconds(t, filepath.Join(projectDir, "exports"))
	blockQueue(t, svc)

	analysis, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	defer waitForTerminal(t, svc, project.ID, "analysis", analysis.ID)
	defer func() { _, _ = svc.Cancel(project.ID, "analysis", analysis.ID) }()
	want := suffixedIDTime(t, analysis.ID)
	if !analysis.CreatedAt.Equal(want) {
		t.Errorf("QueueAnalysis CreatedAt = %v, want %v", analysis.CreatedAt, want)
	}
	var status statusFile
	if err := st.ReadJSON(filepath.Join(projectDir, "analyses", analysis.ID+".tmp", "status.json"), &status); err != nil {
		t.Fatalf("read queued status.json: %v", err)
	}
	if !status.CreatedAt.Equal(want) {
		t.Errorf("queued status.json createdAt = %v, want %v", status.CreatedAt, want)
	}

	export, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	defer waitForTerminal(t, svc, project.ID, "export", export.ID)
	defer func() { _, _ = svc.Cancel(project.ID, "export", export.ID) }()
	if want := suffixedIDTime(t, export.ID); !export.CreatedAt.Equal(want) {
		t.Errorf("QueueExport CreatedAt = %v, want %v", export.CreatedAt, want)
	}
}
