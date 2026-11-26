package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
)

// holdWorker keeps the queue's worker busy with a job of no project until
// the returned release runs, so every job queued meanwhile stays queued.
func holdWorker(t *testing.T, svc *Service) (release func()) {
	t.Helper()
	started := make(chan struct{})
	done := make(chan struct{})
	job := &fakeJob{kind: "hold", started: started, run: func(ctx context.Context, _ func(Event)) error {
		select {
		case <-done:
		case <-ctx.Done():
		}
		return nil
	}}
	if _, err := svc.queue.Submit(job); err != nil {
		t.Fatalf("Submit(hold): %v", err)
	}
	<-started
	var once sync.Once
	release = func() { once.Do(func() { close(done) }) }
	t.Cleanup(release)
	return release
}

// A directory a job left behind, with no job queued or running, does not
// keep the project: the delete removes it with the rest.
func TestDeleteProjectRemovesALeftoverJobDirectory(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	for _, kind := range []string{"analyses", "exports"} {
		if _, err := st.NewDir(kind, project.ID); err != nil {
			t.Fatalf("NewDir(%s): %v", kind, err)
		}
	}
	if err := svc.DeleteProject(project.ID); err != nil {
		t.Fatalf("DeleteProject with leftover directories: %v", err)
	}
	if _, err := os.Stat(project.Dir); !os.IsNotExist(err) {
		t.Fatalf("project directory after the delete: err = %v, want it gone", err)
	}
}

func TestDeleteProjectUnknownReturnsErrNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.DeleteProject("does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteProject(unknown) = %v, want ErrNotFound", err)
	}
}

func TestDeleteProjectRefusesWhileAJobIsQueued(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	release := holdWorker(t, svc)
	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	if state, _, ok := svc.LiveState(project.ID, "analysis", info.ID); !ok || state != store.Queued {
		t.Fatalf("LiveState = (%q, %v), want queued", state, ok)
	}

	if err := svc.DeleteProject(project.ID); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("DeleteProject with a queued analysis = %v, want ErrBusy", err)
	}
	if _, err := st.Project(project.ID); err != nil {
		t.Fatalf("project after a refused delete: %v", err)
	}

	release()
	waitForTerminal(t, svc, project.ID, "analysis", info.ID)
	if err := svc.DeleteProject(project.ID); err != nil {
		t.Fatalf("DeleteProject once the analysis ended: %v", err)
	}
}

func TestDeleteProjectRefusesWhileAJobRuns(t *testing.T) {
	for _, kind := range []string{"analysis", "export"} {
		t.Run(kind, func(t *testing.T) {
			svc, st := newTestService(t)
			project := mustCreateProject(t, st)
			dirKind := "exports"
			if kind == "analysis" {
				dirKind = "analyses"
			}
			pending, err := st.NewDir(dirKind, project.ID)
			if err != nil {
				t.Fatalf("NewDir: %v", err)
			}
			started := make(chan struct{})
			release := make(chan struct{})
			job := &fakeJob{kind: kind, started: started, run: func(ctx context.Context, _ func(Event)) error {
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				return os.WriteFile(filepath.Join(pending.Path(), "status.json"), []byte(`{"state":"done"}`), 0o664)
			}}
			if _, err := svc.queue.SubmitWith(job, func(queueID string) {
				svc.track(queueID, kind, project.ID, "", pending)
			}); err != nil {
				t.Fatalf("SubmitWith: %v", err)
			}
			<-started

			if err := svc.DeleteProject(project.ID); !errors.Is(err, store.ErrBusy) {
				t.Fatalf("DeleteProject with a running %s = %v, want ErrBusy", kind, err)
			}
			if _, err := st.Project(project.ID); err != nil {
				t.Fatalf("project after a refused delete: %v", err)
			}

			close(release)
			waitForTerminal(t, svc, project.ID, kind, pending.ID())
			if err := svc.DeleteProject(project.ID); err != nil {
				t.Fatalf("DeleteProject once the %s ended: %v", kind, err)
			}
			if _, err := os.Stat(project.Dir); !os.IsNotExist(err) {
				t.Fatalf("project directory after the delete: err = %v, want it gone", err)
			}
		})
	}
}

// An analysis queued at the same moment as the delete either lands first,
// and the delete answers busy, or finds the project gone. It never
// recreates the deleted project's directory, even once it runs.
func TestDeleteProjectAndAConcurrentAnalysisNeverOverlap(t *testing.T) {
	const rounds = 50
	svc, st := newTestService(t)
	release := holdWorker(t, svc)

	type outcome struct {
		project store.Project
		queued  store.AnalysisInfo
	}
	var deleted, kept []outcome
	for round := range rounds {
		project, err := st.CreateProject(fmt.Sprintf("p%d", round), []byte(`{"name":"p"}`))
		if err != nil {
			t.Fatalf("CreateProject: %v", err)
		}
		var (
			wg                  sync.WaitGroup
			queued              store.AnalysisInfo
			queueErr, deleteErr error
		)
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			queued, queueErr = svc.QueueAnalysis(project.ID)
		}()
		go func() {
			defer wg.Done()
			<-start
			deleteErr = svc.DeleteProject(project.ID)
		}()
		close(start)
		wg.Wait()

		switch {
		case deleteErr == nil:
			if !errors.Is(queueErr, store.ErrNotFound) {
				t.Fatalf("round %d: the delete went through and QueueAnalysis = (%+v, %v), want ErrNotFound", round, queued, queueErr)
			}
			deleted = append(deleted, outcome{project: project})
		case errors.Is(deleteErr, store.ErrBusy):
			if queueErr != nil {
				t.Fatalf("round %d: the delete answered busy and QueueAnalysis = %v, want the analysis queued", round, queueErr)
			}
			kept = append(kept, outcome{project: project, queued: queued})
		default:
			t.Fatalf("round %d: DeleteProject = %v, want nil or ErrBusy", round, deleteErr)
		}
		if _, err := os.Stat(project.Dir); deleteErr == nil && !os.IsNotExist(err) {
			t.Fatalf("round %d: project directory after the delete: err = %v, want it gone", round, err)
		}
	}

	release()
	for _, o := range kept {
		waitForTerminal(t, svc, o.project.ID, "analysis", o.queued.ID)
		if _, err := st.Project(o.project.ID); err != nil {
			t.Errorf("project %s kept by a busy delete: %v", o.project.ID, err)
		}
	}
	for _, o := range deleted {
		if _, err := os.Stat(o.project.Dir); !os.IsNotExist(err) {
			t.Errorf("deleted project %s has a directory again: err = %v", o.project.ID, err)
		}
	}
	t.Logf("%d deleted, %d kept", len(deleted), len(kept))
}

// A cancelled job that was the project's latest leaves an earlier one
// queued, and that earlier job still keeps the project.
func TestDeleteProjectRefusesWhileAnEarlierJobOutlivesACancelledOne(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	release := holdWorker(t, svc)
	first, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis(first): %v", err)
	}
	second, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis(second): %v", err)
	}
	if _, err := svc.Cancel(project.ID, "analysis", second.ID); err != nil {
		t.Fatalf("Cancel(second): %v", err)
	}
	waitForTerminal(t, svc, project.ID, "analysis", second.ID)

	if err := svc.DeleteProject(project.ID); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("DeleteProject with the first analysis still queued = %v, want ErrBusy", err)
	}
	release()
	waitForTerminal(t, svc, project.ID, "analysis", first.ID)
}

// writeDoneAnalysis gives project a done analysis with nothing to export
// beyond the project itself, and returns its id.
func writeDoneAnalysis(t *testing.T, st *store.Store, project store.Project) string {
	t.Helper()
	const id = "20260917T101502Z"
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	dir := filepath.Join(st.Root(), "projects", project.ID, "analyses", id)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, body := range map[string]string{
		"status.json":        `{"state":"done"}`,
		"ranking.json":       ranking,
		"project.trivy.json": emptyProjectScan,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o664); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return id
}

// An export queued at the same moment as the delete either lands first,
// and the delete answers busy, or finds the project gone. It never
// recreates the deleted project's directory.
func TestDeleteProjectAndAConcurrentExportNeverOverlap(t *testing.T) {
	const rounds = 50
	svc, st := newTestService(t)
	release := holdWorker(t, svc)

	type outcome struct {
		project store.Project
		queued  store.ExportInfo
	}
	var deleted, kept []outcome
	for round := range rounds {
		project, err := st.CreateProject(fmt.Sprintf("p%d", round), []byte(`{"name":"p"}`))
		if err != nil {
			t.Fatalf("CreateProject: %v", err)
		}
		analysisID := writeDoneAnalysis(t, st, project)
		var (
			wg                  sync.WaitGroup
			queued              store.ExportInfo
			queueErr, deleteErr error
		)
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			queued, queueErr = svc.QueueExport(project.ID, analysisID, ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
		}()
		go func() {
			defer wg.Done()
			<-start
			deleteErr = svc.DeleteProject(project.ID)
		}()
		close(start)
		wg.Wait()

		switch {
		case deleteErr == nil:
			if !errors.Is(queueErr, store.ErrNotFound) {
				t.Fatalf("round %d: the delete went through and QueueExport = (%+v, %v), want ErrNotFound", round, queued, queueErr)
			}
			deleted = append(deleted, outcome{project: project})
		case errors.Is(deleteErr, store.ErrBusy):
			if queueErr != nil {
				t.Fatalf("round %d: the delete answered busy and QueueExport = %v, want the export queued", round, queueErr)
			}
			kept = append(kept, outcome{project: project, queued: queued})
		default:
			t.Fatalf("round %d: DeleteProject = %v, want nil or ErrBusy", round, deleteErr)
		}
		if _, err := os.Stat(project.Dir); deleteErr == nil && !os.IsNotExist(err) {
			t.Fatalf("round %d: project directory after the delete: err = %v, want it gone", round, err)
		}
	}

	release()
	for _, o := range kept {
		waitForTerminal(t, svc, o.project.ID, "export", o.queued.ID)
	}
	for _, o := range deleted {
		if _, err := os.Stat(o.project.Dir); !os.IsNotExist(err) {
			t.Errorf("deleted project %s has a directory again: err = %v", o.project.ID, err)
		}
	}
	t.Logf("%d deleted, %d kept", len(deleted), len(kept))
}
