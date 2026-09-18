package jobs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
)

// idLayout is the time.Parse layout analysis and export IDs use: a UTC
// timestamp with second precision (spec section 3), the same one
// internal/store parses committed directory names with.
const idLayout = "20060102T150405Z"

// ErrInvalidSelection reports a QueueExport call whose selection names one
// or more versions the analysis did not resolve. Bad holds every
// offending "name@version" entry, spec section 4 step 1's precedent for a
// validation failure: list every offense, not just the first.
type ErrInvalidSelection struct {
	Bad []string
}

func (e *ErrInvalidSelection) Error() string {
	return fmt.Sprintf("jobs: selection names versions the analysis did not resolve: %s", strings.Join(e.Bad, ", "))
}

// trackedJob is one analysis or export Service has submitted to the queue
// and has not yet finalized. It is shared, by pointer, across every index
// Service looks it up by, so a single finalize step removes it from all
// of them together.
type trackedJob struct {
	queueID   string
	kind      string // "analysis" or "export"
	storeID   string
	projectID string
	pending   *store.Pending
}

// jobKey identifies a tracked job the way a route does: its project, its
// kind and its directory id. The directory id alone is not unique across
// projects or kinds, since store.NewDir only guards against a collision
// within one project's one kind directory; two projects analysed in the
// same second, or an analysis and an export in the same second, can share
// one. Keying on the triple is what lets Cancel and LiveState tell those
// apart and refuse a lookup made through the wrong route.
type jobKey struct {
	projectID string
	kind      string
	storeID   string
}

// Service turns an HTTP request into a queued job. Handlers hold a
// *Service and never touch the queue or the store layout themselves.
//
// Analysis commits its own directory on every path, including failure and
// cancellation, but Export leaves a successful run's directory pending for
// its caller to commit, and neither job ever runs when the queue drops it
// before it starts (cancelled while still queued). Service's background
// goroutine is what finalizes that directory once the queue reports the
// job done: an empty one (never started) gets discarded, a non-empty one
// Export left ready gets committed, and a directory a job already
// committed or discarded itself is simply gone by the time this looks.
// The same step reconciles an analysis' status.json to the queue's own
// account of how the job ended: the queue, not the job, has the last
// word, since the job derives its own guess from ctx.Err() alone and can
// race the same cancel/natural-finish ambiguity queue.go's own state
// derivation exists to avoid.
type Service struct {
	store *store.Store
	queue *Queue
	tools *tools.Manager
	pnpm  runner.Pnpm
	trivy runner.Trivy
	reg   *npm.Client

	mu          sync.Mutex
	byQueueID   map[string]*trackedJob
	byJobKey    map[jobKey]*trackedJob
	byProjectID map[string]*trackedJob // the one job Service is tracking for a project, queued or running
}

// NewService builds a Service and registers it as the queue's finalize
// hook (see Queue.SetFinalizer): every job's directory and, for an
// analysis, its status.json get finalized synchronously as part of the
// queue's own worker step, not through a Subscribe channel a slow reader
// could make the queue drop.
func NewService(st *store.Store, q *Queue, tm *tools.Manager, pnpm runner.Pnpm, trivy runner.Trivy, reg *npm.Client) *Service {
	s := &Service{
		store:       st,
		queue:       q,
		tools:       tm,
		pnpm:        pnpm,
		trivy:       trivy,
		reg:         reg,
		byQueueID:   make(map[string]*trackedJob),
		byJobKey:    make(map[jobKey]*trackedJob),
		byProjectID: make(map[string]*trackedJob),
	}
	q.SetFinalizer(s.finalize)
	return s
}

// QueueAnalysis reserves a directory for a new analysis of project and
// submits it to the queue, returning its queued state at once. The
// analysis job itself owns committing that directory, on every path
// including failure and cancellation.
func (s *Service) QueueAnalysis(projectID string) (store.AnalysisInfo, error) {
	project, err := s.store.Project(projectID)
	if err != nil {
		return store.AnalysisInfo{}, err
	}
	settings := s.store.Settings()

	pending, err := s.store.NewDir("analyses", projectID)
	if err != nil {
		return store.AnalysisInfo{}, err
	}

	job := &Analysis{
		Store:    s.store,
		Tools:    s.tools,
		Pnpm:     s.pnpm,
		Trivy:    s.trivy,
		Registry: s.reg,
		Project:  project,
		Settings: settings,
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	queueID, err := s.queue.Submit(job)
	if err != nil {
		_ = pending.Discard()
		return store.AnalysisInfo{}, err
	}
	s.track(queueID, "analysis", projectID, pending)

	createdAt, _ := time.Parse(idLayout, pending.ID())
	return store.AnalysisInfo{ID: pending.ID(), ProjectID: projectID, State: store.Queued, CreatedAt: createdAt}, nil
}

// QueueExport reserves a directory for a new export of analysisID and
// submits it to the queue, returning its queued state at once. analysisID
// must name a done analysis with a readable ranking.json: the export never
// resolves anything itself, so it has nothing to fall back to otherwise.
// The selection is validated against that analysis' own result before
// anything is reserved: spec section 4 step 1's validation-blocks-the-
// start precedent applies here too, so a bad selection never reaches the
// queue only to fail deep inside the job once the HTTP response is gone.
// Unlike Analysis, Export leaves a successful run's directory for
// Service's finalizer to commit.
func (s *Service) QueueExport(projectID, analysisID string, req ExportRequest) (store.ExportInfo, error) {
	project, err := s.store.Project(projectID)
	if err != nil {
		return store.ExportInfo{}, err
	}
	analysisInfo, err := s.store.AnalysisInfo(projectID, analysisID)
	if err != nil {
		return store.ExportInfo{}, err
	}
	if analysisInfo.State != store.Done {
		return store.ExportInfo{}, fmt.Errorf("jobs: analysis %s is %s, not done", analysisID, analysisInfo.State)
	}
	var result Result
	if err := json.Unmarshal(analysisInfo.Result, &result); err != nil {
		return store.ExportInfo{}, fmt.Errorf("jobs: analysis %s has no usable ranking result: %w", analysisID, err)
	}
	if bad := ValidateSelection(result, req.Selection); len(bad) > 0 {
		return store.ExportInfo{}, &ErrInvalidSelection{Bad: bad}
	}

	settings := s.store.Settings()
	if settings.SignatureKey == "" {
		return store.ExportInfo{}, ErrSignatureKeyMissing
	}

	pending, err := s.store.NewDir("exports", projectID)
	if err != nil {
		return store.ExportInfo{}, err
	}

	job := &Export{
		Store:    s.store,
		Registry: s.reg,
		Trivy:    s.trivy,
		Project:  project,
		Settings: settings,
		Analysis: AnalysisRef{ID: analysisID, Dir: filepath.Join(project.Dir, "analyses", analysisID), Result: result},
		Request:  req,
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	queueID, err := s.queue.Submit(job)
	if err != nil {
		_ = pending.Discard()
		return store.ExportInfo{}, err
	}
	s.track(queueID, "export", projectID, pending)

	createdAt, _ := time.Parse(idLayout, pending.ID())
	return store.ExportInfo{
		ID: pending.ID(), ProjectID: projectID, AnalysisID: analysisID, State: store.Queued, CreatedAt: createdAt,
	}, nil
}

// Cancel stops the analysis or export named id under project projectID,
// translating it to the queue's own job id. kind must be "analysis" or
// "export", the route id was reached through. It reports
// store.ErrNotFound once the job has ended and Service is no longer
// tracking it, and equally when id is tracked but under a different
// project or kind: the store, not Service, holds the truth once a job
// has ended, and a route must never cancel a job that belongs to another
// kind just because the two share a directory id.
func (s *Service) Cancel(projectID, kind, id string) error {
	s.mu.Lock()
	tj, ok := s.byJobKey[jobKey{projectID: projectID, kind: kind, storeID: id}]
	s.mu.Unlock()
	if !ok {
		return store.ErrNotFound
	}
	return s.queue.Cancel(tj.queueID)
}

// LiveState reports the state of the analysis or export named id under
// project projectID and kind ("analysis" or "export"): running while the
// queue's current job is it, queued otherwise. ok is false once the job
// has ended, at which point the store holds whatever became of its
// directory, and equally when id is tracked but under a different
// project or kind.
func (s *Service) LiveState(projectID, kind, id string) (state store.State, ok bool) {
	s.mu.Lock()
	tj, tracked := s.byJobKey[jobKey{projectID: projectID, kind: kind, storeID: id}]
	s.mu.Unlock()
	if !tracked {
		return "", false
	}
	if curID, _, curOK := s.queue.Current(); curOK && curID == tj.queueID {
		return store.Running, true
	}
	return store.Queued, true
}

// LiveForProject reports the one analysis or export Service is still
// tracking for projectID, if any: its id, whether it is an "analysis" or
// an "export", and its live state. A project can in principle have more
// than one job queued behind each other; this reports only the most
// recently queued one, which is enough for a project page to show that
// something is happening without a second index keyed by project and
// time.
func (s *Service) LiveForProject(projectID string) (id, kind string, state store.State, ok bool) {
	s.mu.Lock()
	tj, tracked := s.byProjectID[projectID]
	s.mu.Unlock()
	if !tracked {
		return "", "", "", false
	}
	state, ok = s.LiveState(tj.projectID, tj.kind, tj.storeID)
	if !ok {
		return "", "", "", false
	}
	return tj.storeID, tj.kind, state, true
}

// track records a just-submitted job under every index the rest of
// Service needs it by.
func (s *Service) track(queueID, kind, projectID string, pending *store.Pending) {
	tj := &trackedJob{queueID: queueID, kind: kind, storeID: pending.ID(), projectID: projectID, pending: pending}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byQueueID[queueID] = tj
	s.byJobKey[jobKey{projectID: projectID, kind: kind, storeID: tj.storeID}] = tj
	s.byProjectID[projectID] = tj
}

// finalize is the queue's finalize hook (see Queue.SetFinalizer). It runs
// synchronously on the queue's own worker goroutine, once per job, so a
// directory commit or a status.json reconciliation can never be dropped
// the way an event on a Subscribe channel can once a slow reader falls
// behind.
//
// The tracked job is only removed from every index once its directory
// has been finalized and, for an analysis, its status.json reconciled:
// a caller polling LiveState until it reports untracked, such as a test
// that then removes the whole data volume, needs that to mean the
// filesystem has genuinely gone quiet, not just that the maps have.
func (s *Service) finalize(info FinalizeInfo) error {
	s.mu.Lock()
	tj, ok := s.byQueueID[info.ID]
	s.mu.Unlock()
	if !ok {
		return nil
	}

	err := finalizePending(tj.pending)
	if tj.kind == "analysis" {
		reconcileAnalysisStatus(s.store, tj.pending, info.State)
	}

	s.mu.Lock()
	delete(s.byQueueID, info.ID)
	delete(s.byJobKey, jobKey{projectID: tj.projectID, kind: tj.kind, storeID: tj.storeID})
	// A newer job for the same project may already have replaced this
	// entry; only clear it if it is still the one this finalize call is
	// about.
	if s.byProjectID[tj.projectID] == tj {
		delete(s.byProjectID, tj.projectID)
	}
	s.mu.Unlock()
	return err
}

// reconcileAnalysisStatus overwrites a committed analysis' status.json
// "state" field with the queue's own authoritative outcome, leaving every
// other field untouched. It is a no-op when the job never started (the
// queue dropped it while still queued, so nothing was ever committed) or
// status.json is otherwise unreadable.
func reconcileAnalysisStatus(st *store.Store, pending *store.Pending, state store.State) {
	path := filepath.Join(pending.Final(), "status.json")
	var fields map[string]json.RawMessage
	if err := st.ReadJSON(path, &fields); err != nil {
		return
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return
	}
	fields["state"] = encoded
	_ = st.WriteJSON(path, fields)
}

// finalizePending decides what a job leaves behind once it has ended,
// returning any error committing or discarding it hit so the caller can
// log it: a failed commit here loses a finished export outright, so it
// must not disappear silently. Analysis always commits itself, whatever
// the outcome, so this only ever finds one of its directories when the
// job never started (the queue dropped it while still queued): empty,
// and discarded here. Export leaves a successful run's directory
// non-empty for exactly this to commit, and removes it itself on
// failure, so this never sees a failed export's directory at all.
func finalizePending(pending *store.Pending) error {
	entries, err := os.ReadDir(pending.Path())
	if err != nil {
		return nil // already committed or discarded by the job itself
	}
	if len(entries) == 0 {
		return pending.Discard()
	}
	return pending.Commit()
}
