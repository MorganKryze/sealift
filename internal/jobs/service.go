package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/pip"
	"github.com/MorganKryze/sealift/rank"
)

// ErrAnalysisNotDone reports a QueueExport call naming an analysis that
// has not reached state done: queued, running, failed or cancelled all
// leave nothing ranked yet to select from.
var ErrAnalysisNotDone = errors.New("jobs: analysis is not done")

// ErrNoProjectScan reports an export of the project tree whose analysis
// has no readable scan of the project's lockfile, so the CVEs it ships
// cannot be checked against the review policy.
var ErrNoProjectScan = errors.New("jobs: no readable project scan")

// ErrNothingToExport reports a QueueExport call that selects no version and
// leaves out the current tree: the archive would hold no package at all.
var ErrNothingToExport = errors.New("jobs: the export selects no version and leaves out the current project, so it would pack nothing")

// ErrInvalidSelection reports a QueueExport call whose selection names one
// or more versions the analysis did not resolve. Bad holds every
// offending "name@version" entry: a validation failure lists every
// offense, not just the first.
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
	queueID    string
	kind       string // "analysis" or "export"
	storeID    string
	projectID  string
	analysisID string // set for kind "export"; the analysis it was exported from
	pending    *store.Pending
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
// job done: an analysis that never started holds the queued record
// QueueAnalysis seeded, an export that never started gets a cancelled
// record, and both are committed so the cancel stays on screen; a
// non-empty directory Export left ready gets committed too, and a
// directory a job already committed itself is gone by the time this looks.
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

	// Review holds the policy's review rules, copied into each analysis
	// the Service queues. Set it before the first one.
	Review policy.Review

	mu          sync.Mutex
	uv          runner.Uv   // nil until SetPip
	index       *pip.Client // nil until SetPip
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

// SetPip gives the Service what a pip analysis needs: the resolver and the
// package index. Without it, QueueAnalysis refuses a pip project.
func (s *Service) SetPip(uv runner.Uv, index *pip.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uv, s.index = uv, index
}

// QueueAnalysis reserves a directory for a new analysis of project and
// submits it to the queue, returning its queued state at once. The
// project's ecosystem picks the job. The analysis job itself owns
// committing that directory, on every path including failure and
// cancellation.
func (s *Service) QueueAnalysis(projectID string) (store.AnalysisInfo, error) {
	project, err := s.store.Project(projectID)
	if err != nil {
		return store.AnalysisInfo{}, err
	}
	settings := s.store.Settings()
	s.mu.Lock()
	uv, index := s.uv, s.index
	s.mu.Unlock()
	if project.Ecosystem == store.Pip && (uv == nil || index == nil) {
		return store.AnalysisInfo{}, errors.New("jobs: this server is not set up to analyse pip projects")
	}

	pending, err := s.store.NewDir("analyses", projectID)
	if err != nil {
		return store.AnalysisInfo{}, err
	}

	// A job the queue drops while still queued never runs, so nothing else
	// writes into the directory. Leaving it empty would have finalizePending
	// discard it and the analysis vanish; a queued status.json and an empty
	// log.txt make it a record the reconciler turns into "cancelled". A
	// running job overwrites status.json and appends to log.txt itself.
	createdAt, _ := store.JobCreatedAt(pending.ID())
	if err := s.seedPending(pending, createdAt, project); err != nil {
		_ = pending.Discard()
		return store.AnalysisInfo{}, err
	}

	var job Job = &Analysis{
		Store:    s.store,
		Tools:    s.tools,
		Pnpm:     s.pnpm,
		Trivy:    s.trivy,
		Registry: s.reg,
		Project:  project,
		Settings: settings,
		Review:   s.Review,
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	if project.Ecosystem == store.Pip {
		job = &PipAnalysis{
			Store:    s.store,
			Tools:    s.tools,
			Uv:       uv,
			Trivy:    s.trivy,
			Index:    index,
			Project:  project,
			Settings: settings,
			Dir:      pending.Path(),
			ID:       pending.ID(),
		}
	}
	// Registered before the worker can start the job: tracking it after
	// Submit returns races a job that has already finished, and the
	// finalize hook would find nothing to finalize.
	if _, err := s.queue.SubmitWith(job, func(queueID string) {
		s.track(queueID, "analysis", projectID, "", pending)
	}); err != nil {
		s.untrackPending(projectID, "analysis", pending.ID())
		_ = pending.Discard()
		return store.AnalysisInfo{}, err
	}

	return store.AnalysisInfo{ID: pending.ID(), ProjectID: projectID, State: store.Queued, CreatedAt: createdAt}, nil
}

// seedPending writes the queued status.json and an empty log.txt into a
// pending analysis directory.
func (s *Service) seedPending(pending *store.Pending, createdAt time.Time, project store.Project) error {
	status := statusFile{State: store.Queued, CreatedAt: createdAt, Target: project.Target}
	if project.Ecosystem == store.Pip {
		target := project.PipTarget
		status.Target, status.PipTarget = store.Target{}, &target
	}
	if err := s.store.WriteJSON(filepath.Join(pending.Path(), "status.json"), status); err != nil {
		return fmt.Errorf("jobs: write queued status.json: %w", err)
	}
	if err := s.store.WriteFile(filepath.Join(pending.Path(), "log.txt"), nil); err != nil {
		return fmt.Errorf("jobs: create log.txt: %w", err)
	}
	return nil
}

// QueueExport reserves a directory for a new export of analysisID and
// submits it to the queue, returning its queued state at once. analysisID
// must name a done analysis with a readable ranking.json: the export never
// resolves anything itself, so it has nothing to fall back to otherwise.
// The selection and its reasons are validated against that analysis' own
// result and the review policy before anything is reserved, so a bad
// selection never reaches the queue only to fail deep inside the job once
// the HTTP response is gone.
// The project's ecosystem picks Export or PipExport. Unlike Analysis, an
// export leaves a successful run's directory for Service's finalizer to
// commit.
func (s *Service) QueueExport(projectID, analysisID string, req ExportRequest) (store.ExportInfo, error) {
	project, err := s.store.Project(projectID)
	if err != nil {
		return store.ExportInfo{}, err
	}
	if project.Ecosystem == store.Pip {
		return s.queuePipExport(project, analysisID, req)
	}
	analysisInfo, err := s.store.AnalysisInfo(projectID, analysisID)
	if err != nil {
		return store.ExportInfo{}, err
	}
	if analysisInfo.State != store.Done {
		return store.ExportInfo{}, fmt.Errorf("%w: analysis %s is %s", ErrAnalysisNotDone, analysisID, analysisInfo.State)
	}
	var result Result
	if err := json.Unmarshal(analysisInfo.Result, &result); err != nil {
		return store.ExportInfo{}, fmt.Errorf("jobs: analysis %s has no usable ranking result: %w", analysisID, err)
	}
	if bad := ValidateSelection(result, req.Selection); len(bad) > 0 {
		return store.ExportInfo{}, &ErrInvalidSelection{Bad: bad}
	}
	if !req.IncludeProject && !selectsAnyVersion(req.Selection) {
		return store.ExportInfo{}, ErrNothingToExport
	}
	if req.IncludeProject {
		findings, err := projectFindings(filepath.Join(project.Dir, "analyses", analysisID))
		if err != nil {
			return store.ExportInfo{}, err
		}
		req.ProjectFindings = findings
		if keys := lockKeysToPlace(result, req.ProjectFindings); len(keys) > 0 {
			holders, err := projectHolders(filepath.Join(project.Dir, "analyses", analysisID), keys)
			if err != nil {
				return store.ExportInfo{}, err
			}
			req.ProjectHolders = holders
		}
	}
	if problems := CheckReasons(result, req, s.Review); len(problems) > 0 {
		return store.ExportInfo{}, &ErrInvalidReasons{Problems: problems}
	}

	settings := s.store.Settings()

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
		Review:   s.Review,
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	return s.submitExport(job, projectID, analysisID, pending)
}

// queuePipExport is QueueExport for a pip project: the export carries the
// analysis's whole set, so it takes no selection, and every package needs
// the wheel the analysis chose. A refusal reserves nothing.
func (s *Service) queuePipExport(project store.Project, analysisID string, req ExportRequest) (store.ExportInfo, error) {
	if len(req.Selection) > 0 {
		return store.ExportInfo{}, ErrPipSelection
	}
	if len(req.Reasons) > 0 {
		// Pip writes no review yet: a reason sent here would be lost.
		return store.ExportInfo{}, &pipRefusal{text: "jobs: a pip export takes no reasons: its set carries no review yet", class: ErrPipSelection}
	}
	analysisInfo, err := s.store.AnalysisInfo(project.ID, analysisID)
	if err != nil {
		return store.ExportInfo{}, err
	}
	if analysisInfo.State != store.Done {
		return store.ExportInfo{}, fmt.Errorf("%w: analysis %s is %s", ErrAnalysisNotDone, analysisID, analysisInfo.State)
	}
	var result PipResult
	if err := json.Unmarshal(analysisInfo.PipResult, &result); err != nil {
		return store.ExportInfo{}, fmt.Errorf("%w: analysis %s has no readable result", ErrPipNotExportable, analysisID)
	}
	if len(result.Packages) == 0 {
		return store.ExportInfo{}, fmt.Errorf("%w: analysis %s lists no package", ErrPipNotExportable, analysisID)
	}
	missing := 0
	for _, p := range result.Packages {
		if p.Wheel == nil {
			missing++
		}
	}
	if missing > 0 {
		return store.ExportInfo{}, fmt.Errorf("%w: %d of %d packages %s no wheel", ErrPipNotExportable, missing, len(result.Packages), plural(missing, "has", "have"))
	}
	if err := pipNoFixRefusal(result, s.Review); err != nil {
		return store.ExportInfo{}, err
	}
	s.mu.Lock()
	index := s.index
	s.mu.Unlock()
	if index == nil {
		return store.ExportInfo{}, errors.New("jobs: this server is not set up to export pip projects")
	}

	pending, err := s.store.NewDir("exports", project.ID)
	if err != nil {
		return store.ExportInfo{}, err
	}
	job := &PipExport{
		Store:    s.store,
		Index:    index,
		Trivy:    s.trivy,
		Project:  project,
		Settings: s.store.Settings(),
		Analysis: PipAnalysisRef{ID: analysisID, Dir: filepath.Join(project.Dir, "analyses", analysisID), Result: result},
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
	return s.submitExport(job, project.ID, analysisID, pending)
}

// submitExport queues an export job whose directory pending holds, and
// returns its queued state. A job the queue refuses gives its directory
// back.
func (s *Service) submitExport(job Job, projectID, analysisID string, pending *store.Pending) (store.ExportInfo, error) {
	// Registered before the worker can start the job: tracking it after
	// Submit returns races a job that has already finished, and the
	// finalize hook would find nothing to finalize.
	if _, err := s.queue.SubmitWith(job, func(queueID string) {
		s.track(queueID, "export", projectID, analysisID, pending)
	}); err != nil {
		s.untrackPending(projectID, "export", pending.ID())
		_ = pending.Discard()
		return store.ExportInfo{}, err
	}

	createdAt, _ := store.JobCreatedAt(pending.ID())
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
// kind just because the two share a directory id. analysisID is set only
// for kind "export".
func (s *Service) Cancel(projectID, kind, id string) (analysisID string, err error) {
	s.mu.Lock()
	tj, ok := s.byJobKey[jobKey{projectID: projectID, kind: kind, storeID: id}]
	s.mu.Unlock()
	if !ok {
		return "", store.ErrNotFound
	}
	if err := s.queue.Cancel(tj.queueID); err != nil {
		return "", err
	}
	return tj.analysisID, nil
}

// LiveState reports the state of the analysis or export named id under
// project projectID and kind ("analysis" or "export"): running while the
// queue's current job is it, queued otherwise. ok is false once the job
// has ended, at which point the store holds whatever became of its
// directory, and equally when id is tracked but under a different
// project or kind. analysisID is set only for kind "export".
func (s *Service) LiveState(projectID, kind, id string) (state store.State, analysisID string, ok bool) {
	s.mu.Lock()
	tj, tracked := s.byJobKey[jobKey{projectID: projectID, kind: kind, storeID: id}]
	s.mu.Unlock()
	if !tracked {
		return "", "", false
	}
	if curID, _, curOK := s.queue.Current(); curOK && curID == tj.queueID {
		return store.Running, tj.analysisID, true
	}
	return store.Queued, tj.analysisID, true
}

// LiveForProject reports the one analysis or export Service is still
// tracking for projectID, if any: its id, whether it is an "analysis" or
// an "export", its live state, and, for an export, the analysis it was
// exported from. A project can in principle have more than one job
// queued behind each other; this reports only the most recently queued
// one, which is enough for a project page to show that something is
// happening without a second index keyed by project and time.
func (s *Service) LiveForProject(projectID string) (id, kind string, state store.State, analysisID string, ok bool) {
	s.mu.Lock()
	tj, tracked := s.byProjectID[projectID]
	s.mu.Unlock()
	if !tracked {
		return "", "", "", "", false
	}
	state, analysisID, ok = s.LiveState(tj.projectID, tj.kind, tj.storeID)
	if !ok {
		return "", "", "", "", false
	}
	return tj.storeID, tj.kind, state, analysisID, true
}

// Subscribe wraps the queue's event stream, filling in each event's store
// id: the queue only knows the queue id it assigned at submission, while
// Service is what maps that to the directory id the store and the client
// both use. A per-job cache covers the "end" event, since finalize (which
// untracks the job) runs before the queue publishes it, so the direct
// lookup would otherwise miss on exactly the event a caller most needs
// the store id on.
func (s *Service) Subscribe() (<-chan Event, func()) {
	events, unsubscribe := s.queue.Subscribe()
	out := make(chan Event, replayLimit+2)
	stop := make(chan struct{})
	go func() {
		defer close(out)
		known := make(map[string]string)
		for {
			select {
			case e, ok := <-events:
				if !ok {
					return
				}
				// The queue stamps the id for jobs that carry one; the lookup
				// only covers a job that does not.
				if e.StoreID == "" {
					s.mu.Lock()
					tj, tracked := s.byQueueID[e.Job]
					s.mu.Unlock()
					if tracked {
						known[e.Job] = tj.storeID
					}
					e.StoreID = known[e.Job]
				}
				select {
				case out <- e:
				case <-stop:
					return
				}
			case <-stop:
				return
			}
		}
	}()
	return out, func() {
		unsubscribe()
		close(stop)
	}
}

// track records a just-submitted job under every index the rest of
// Service needs it by. analysisID is set only for kind "export".
func (s *Service) track(queueID, kind, projectID, analysisID string, pending *store.Pending) {
	tj := &trackedJob{queueID: queueID, kind: kind, storeID: pending.ID(), projectID: projectID, analysisID: analysisID, pending: pending}
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
// untrackPending removes a job that never reached the queue, so a failed
// submission leaves no entry behind.
func (s *Service) untrackPending(projectID, kind, storeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := jobKey{projectID: projectID, kind: kind, storeID: storeID}
	tj, ok := s.byJobKey[key]
	if !ok {
		return
	}
	delete(s.byJobKey, key)
	delete(s.byQueueID, tj.queueID)
	if s.byProjectID[projectID] == tj {
		delete(s.byProjectID, projectID)
	}
}

func (s *Service) finalize(info FinalizeInfo) error {
	s.mu.Lock()
	tj, ok := s.byQueueID[info.ID]
	s.mu.Unlock()
	if !ok {
		return nil
	}

	if tj.kind == "export" && info.State == store.Cancelled {
		s.recordQueuedExportCancel(tj)
	}
	err := s.finalizeDir(tj, info.State, info.Err)

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

// recordQueuedExportCancel writes the cancelled status.json of an export
// the queue dropped before it ran, so finalizePending commits it instead of
// discarding an empty directory. A directory that already holds files was
// written by a run, which left its own status.json. A failed write keeps
// today's discard.
func (s *Service) recordQueuedExportCancel(tj *trackedJob) {
	entries, err := os.ReadDir(tj.pending.Path())
	if err != nil || len(entries) > 0 {
		return
	}
	status := exportStatusFile{State: store.Cancelled, AnalysisID: tj.analysisID, Steps: []stepRecord{}}
	if err := s.store.WriteJSON(filepath.Join(tj.pending.Path(), "status.json"), status); err != nil {
		slog.Warn("jobs: write cancelled export status.json", "error", err)
	}
}

// finalizeDir publishes the job's directory with its final state. A
// directory still pending (the queue dropped the job before it ran, an
// analysis whose own commit failed, or an export that left its files for
// this hook) gets its status.json rewritten before the rename, so the
// record is published in one step and a crash or a failed write cannot
// leave it published with a stale state. An analysis that ran has already
// committed itself, so its published status.json is rewritten in place.
//
// Only an analysis that never started is discarded when its state cannot
// be rewritten: its directory holds a queued record and an empty log, and
// published as "queued" it would stay there, since nothing runs it. Any
// other directory holds a run's log and results, so it is published even
// when the rewrite fails, and the startup sweep settles its state.
//
// An analysis that failed without starting wrote no step of its own, so
// its record gets one, prepare, carrying runErr: without it the screen
// would show a failure with no cause.
func (s *Service) finalizeDir(tj *trackedJob, state store.State, runErr error) error {
	reconcile := tj.kind == "analysis" || tj.kind == "export"
	if _, err := os.Stat(tj.pending.Path()); err != nil {
		if !reconcile {
			return nil
		}
		return reconcileStatus(s.store, tj.pending.Final(), state)
	}
	if reconcile {
		// Judged before the rewrite, which replaces the state it reads.
		neverStarted := tj.kind == "analysis" && s.neverStarted(tj.pending.Path())
		fields := map[string]any{"state": state}
		if neverStarted && state == store.Failed && runErr != nil {
			fields["steps"] = []stepRecord{{Name: "prepare", State: string(store.Failed), Error: cause(s.store.Root(), runErr)}}
		}
		if err := rewriteStatus(s.store, tj.pending.Path(), fields); err != nil {
			if neverStarted {
				return errors.Join(err, tj.pending.Discard())
			}
			return errors.Join(err, finalizePending(tj.pending))
		}
	}
	return finalizePending(tj.pending)
}

// neverStarted reports whether the analysis directory dir still holds the
// queued status.json QueueAnalysis seeded. A running job replaces it with
// its own on its first write, so any other state, or a status.json that
// cannot be read, means the job started and dir may hold its run.
func (s *Service) neverStarted(dir string) bool {
	var status struct {
		State store.State `json:"state"`
	}
	if err := s.store.ReadJSON(filepath.Join(dir, "status.json"), &status); err != nil {
		return false
	}
	return status.State == store.Queued
}

// reconcileStatus overwrites the status.json in dir with the queue's own
// authoritative outcome in its "state" field, leaving every other field
// untouched. It does nothing when dir holds no status.json (a done export
// writes none). A job that never started still has the status.json its
// queueing seeded, so its outcome is rewritten here too.
func reconcileStatus(st *store.Store, dir string, state store.State) error {
	return rewriteStatus(st, dir, map[string]any{"state": state})
}

// rewriteStatus sets each of set's fields in the status.json in dir and
// leaves the others as they are. It does nothing when dir holds no
// status.json.
func rewriteStatus(st *store.Store, dir string, set map[string]any) error {
	path := filepath.Join(dir, "status.json")
	var fields map[string]json.RawMessage
	if err := st.ReadJSON(path, &fields); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for name, value := range set {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		fields[name] = encoded
	}
	return st.WriteJSON(path, fields)
}

// finalizePending decides what a job leaves behind once it has ended,
// returning any error committing or discarding it hit so the caller can
// log it: a failed commit here loses a finished export outright, so it
// must not disappear silently. A directory with any file in it is
// committed, an empty one discarded. Analysis commits itself whatever the
// outcome, so this finds one of its directories only when the job never
// started (the queue dropped it while still queued) or its own commit
// failed; both hold files, so both are committed. Export leaves its
// directory non-empty on every outcome (a done run's files, or a failed or
// cancelled run's status.json, see Export.Run), so this commits it; only a
// job that never started leaves an export directory empty.
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

func selectsAnyVersion(sel map[string][]string) bool {
	for _, versions := range sel {
		if len(versions) > 0 {
			return true
		}
	}
	return false
}

// projectFindings reads the analysis's scan of the project's lockfile. A
// missing or unreadable one is ErrNoProjectScan with its cause.
func projectFindings(analysisDir string) ([]rank.Finding, error) {
	f, err := openRegularFile(filepath.Join(analysisDir, "project.trivy.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoProjectScan, err)
	}
	defer f.Close()
	findings, err := rank.ReadTrivyJSON(f)
	if err != nil {
		return nil, fmt.Errorf("%w: project.trivy.json: %w", ErrNoProjectScan, err)
	}
	return findings, nil
}

// projectHolders reads the analysis's project lockfile into the direct
// dependencies that hold each of keys. An unreadable lockfile places
// nothing, so a CVE without a fix only it would place refuses the export.
// A lockfile too large to walk fails the export with its cause.
func projectHolders(analysisDir string, keys []string) (map[string][]string, error) {
	f, err := openRegularFile(filepath.Join(analysisDir, "project", "pnpm-lock.yaml"))
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	holders, err := npm.LockHolders(f, keys)
	if errors.Is(err, npm.ErrLockTooLarge) {
		return nil, fmt.Errorf("jobs: project lockfile of analysis %s: %w", filepath.Base(analysisDir), err)
	}
	if err != nil {
		slog.Warn("jobs: unreadable project lockfile", "dir", analysisDir, "error", err)
		return nil, nil
	}
	return holders, nil
}
