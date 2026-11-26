package jobs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// writeCache gives the shared caches one file and returns its path.
func writeCache(t *testing.T, st *store.Store) string {
	t.Helper()
	cached := filepath.Join(st.Root(), "cache", "tarballs", "x.tgz")
	if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cached
}

// sweepLater runs the ephemeral sweep of svc as if two hours had
// passed, so every project is past the one-hour idle delay.
func sweepLater(svc *Service) store.Sweep {
	return svc.SweepEphemeral(time.Hour, time.Now().Add(2*time.Hour))
}

// A job directory a failed commit left, with no job behind it, keeps
// neither the project nor the caches.
func TestSweepEphemeralErasesAProjectLeftWithAJobDirectoryOnly(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	if _, err := st.NewDir("exports", project.ID); err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	cached := writeCache(t, st)

	if r := sweepLater(svc); r != (store.Sweep{Deleted: 1, Purged: true}) {
		t.Errorf("sweep = %+v, want the project deleted and the caches purged", r)
	}
	if _, err := os.Stat(project.Dir); !os.IsNotExist(err) {
		t.Errorf("project directory after the sweep: err = %v, want it gone", err)
	}
	if _, err := os.Stat(cached); !os.IsNotExist(err) {
		t.Errorf("the tarball cache survived the sweep: %v", err)
	}
	if purged, err := svc.PurgeIfIdle(); err != nil || purged {
		t.Errorf("PurgeIfIdle after the sweep = %v, %v; want nothing left to purge", purged, err)
	}
}

func TestSweepEphemeralKeepsAProjectWhileItsJobIsQueued(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	release := holdWorker(t, svc)
	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	cached := writeCache(t, st)

	if r := sweepLater(svc); r != (store.Sweep{}) {
		t.Errorf("sweep with a queued analysis = %+v, want nothing done", r)
	}
	if purged, err := svc.PurgeIfIdle(); err != nil || purged {
		t.Errorf("PurgeIfIdle with a queued analysis = %v, %v; want false, nil", purged, err)
	}
	if _, err := st.Project(project.ID); err != nil {
		t.Errorf("project with a queued analysis: %v", err)
	}
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("the caches went while an analysis was queued: %v", err)
	}

	release()
	waitForTerminal(t, svc, project.ID, "analysis", info.ID)
	if r := sweepLater(svc); r.Deleted != 1 || !r.Purged {
		t.Errorf("sweep once the analysis ended = %+v, want the project deleted and the caches purged", r)
	}
}

func TestSweepEphemeralKeepsAProjectWhileItsJobRuns(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	pending, err := st.NewDir("exports", project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	job := &fakeJob{kind: "export", started: started, run: func(ctx context.Context, _ func(Event)) error {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}}
	if _, err := svc.queue.SubmitWith(job, func(queueID string) {
		svc.track(queueID, "export", project.ID, "", pending)
	}); err != nil {
		t.Fatalf("SubmitWith: %v", err)
	}
	<-started
	cached := writeCache(t, st)

	if r := sweepLater(svc); r != (store.Sweep{}) {
		t.Errorf("sweep with a running export = %+v, want nothing done", r)
	}
	if _, err := st.Project(project.ID); err != nil {
		t.Errorf("project with a running export: %v", err)
	}
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("the caches went while an export ran: %v", err)
	}

	close(release)
	waitForTerminal(t, svc, project.ID, "export", pending.ID())
	if r := sweepLater(svc); r.Deleted != 1 || !r.Purged {
		t.Errorf("sweep once the export ended = %+v, want the project deleted and the caches purged", r)
	}
}

// A purge that starts once an analysis has its directory, before the
// service tracks it, waits for the analysis to be queued, then sees it.
func TestPurgeIfIdleWaitsForAJobBeingQueued(t *testing.T) {
	svc, st := newTestService(t)
	project := mustCreateProject(t, st)
	release := holdWorker(t, svc)
	writeCache(t, st)

	type result struct {
		purged bool
		err    error
	}
	purge := make(chan result, 1)
	svc.afterNewDir = func() {
		go func() {
			purged, err := svc.PurgeIfIdle()
			purge <- result{purged, err}
		}()
		// Long enough for a purge that does not wait to finish.
		select {
		case r := <-purge:
			purge <- r
		case <-time.After(50 * time.Millisecond):
		}
	}
	info, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	r := <-purge
	if r.err != nil {
		t.Fatalf("PurgeIfIdle: %v", r.err)
	}
	if r.purged {
		t.Error("the purge emptied the caches under an analysis being queued")
	}
	release()
	waitForTerminal(t, svc, project.ID, "analysis", info.ID)
}

// Queueing and purging at once ends with the caches kept whenever the
// purge saw the job, and gone only when it did not.
func TestPurgeIfIdleRacingQueueAnalysis(t *testing.T) {
	svc, st := newTestService(t)
	release := holdWorker(t, svc)
	project := mustCreateProject(t, st)
	cached := writeCache(t, st)
	start := make(chan struct{})
	queued := make(chan store.AnalysisInfo, 1)
	go func() {
		<-start
		info, err := svc.QueueAnalysis(project.ID)
		if err != nil {
			t.Errorf("QueueAnalysis: %v", err)
		}
		queued <- info
	}()
	close(start)
	purged, err := svc.PurgeIfIdle()
	if err != nil {
		t.Fatalf("PurgeIfIdle: %v", err)
	}
	info := <-queued
	if _, statErr := os.Stat(cached); purged == (statErr == nil) {
		t.Errorf("purged = %v but the cache stat says %v", purged, statErr)
	}
	release()
	waitForTerminal(t, svc, project.ID, "analysis", info.ID)
}
