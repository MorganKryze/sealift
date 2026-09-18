package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
)

// noopPnpm and noopTrivy are runner.Pnpm and runner.Trivy that never touch
// a real binary. Service.QueueAnalysis and QueueExport only build a job
// and hand it to the queue; what a real Analysis or Export does with
// these once running is area 1 and area 2's own tests.
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

	if state, ok := svc.LiveState(project.ID, "analysis", info.ID); !ok || (state != store.Queued && state != store.Running) {
		t.Errorf("LiveState(%s) = (%q, %v), want a live queued or running state", info.ID, state, ok)
	}

	waitForTerminal(t, svc, project.ID, "analysis", info.ID)

	if _, ok := svc.LiveState(project.ID, "analysis", info.ID); ok {
		t.Errorf("LiveState after the job ended = tracked, want Service to have released it")
	}
}

func TestQueueAnalysisUnknownProjectReturnsErrNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.QueueAnalysis("does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("QueueAnalysis(unknown project) = %v, want ErrNotFound", err)
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

func TestQueueExportRefusesAnEmptySignatureKey(t *testing.T) {
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

	// The store's own settings still hold the empty default signatureKey.
	if _, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{}}); !errors.Is(err, ErrSignatureKeyMissing) {
		t.Fatalf("QueueExport with an empty signatureKey = %v, want ErrSignatureKeyMissing", err)
	}
}

func TestQueueExportBuildsAndQueuesAJobOnceReady(t *testing.T) {
	svc, st := newTestService(t)
	project, err := st.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	settings := st.Settings()
	settings.SignatureKey = "top-secret"
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
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

	info, err := svc.QueueExport(project.ID, "20260917T101502Z", ExportRequest{Selection: map[string][]string{}})
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
	settings := st.Settings()
	settings.SignatureKey = "top-secret"
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
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

	if _, _, _, ok := svc.LiveForProject(project.ID); ok {
		t.Fatal("LiveForProject before anything is queued: want ok = false")
	}

	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	id, kind, state, ok := svc.LiveForProject(project.ID)
	if !ok || id != info.ID || kind != "analysis" || (state != store.Queued && state != store.Running) {
		t.Fatalf("LiveForProject = (%q, %q, %q, %v), want (%q, \"analysis\", queued or running, true)", id, kind, state, ok, info.ID)
	}

	waitForTerminal(t, svc, project.ID, "analysis", info.ID)

	if _, _, _, ok := svc.LiveForProject(project.ID); ok {
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
	queueID, err := svc.queue.Submit(job)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	svc.track(queueID, "analysis", project.ID, pending)

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
	queueID, err := svc.queue.Submit(job)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	svc.track(queueID, "analysis", project.ID, pending)

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

func TestCancelUntrackedIDReturnsErrNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Cancel("no-such-project", "analysis", "no-such-id"); !errors.Is(err, store.ErrNotFound) {
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
	svc.track("fake-queue-a", "analysis", projectA.ID, pendingA)
	svc.track("fake-queue-b", "analysis", projectB.ID, pendingB)

	if state, ok := svc.LiveState(projectA.ID, "analysis", pendingA.ID()); !ok || state != store.Queued {
		t.Fatalf("LiveState(project A) = (%q, %v), want (queued, true): its id collided with project B's, it must still be addressable", state, ok)
	}
	if state, ok := svc.LiveState(projectB.ID, "analysis", pendingB.ID()); !ok || state != store.Queued {
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
	svc.track("fake-queue-id", "export", project.ID, pending)

	if err := svc.Cancel(project.ID, "analysis", pending.ID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Cancel(analysis route, an export's id) = %v, want ErrNotFound", err)
	}
	if state, ok := svc.LiveState(project.ID, "export", pending.ID()); !ok || state != store.Queued {
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
		if _, ok := svc.LiveState(projectID, kind, id); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s was still tracked after the deadline", id)
}
