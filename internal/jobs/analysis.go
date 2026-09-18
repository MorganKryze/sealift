package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
)

// Analysis resolves a project's dependencies, scans them for known
// vulnerabilities, and ranks newer versions of each direct dependency
// against it (spec section 4). It implements Job.
type Analysis struct {
	Store    *store.Store
	Tools    *tools.Manager
	Pnpm     runner.Pnpm
	Trivy    runner.Trivy
	Registry *npm.Client
	Project  store.Project
	Settings store.Settings
	Dir      string // the pending analyses/<id> directory
	ID       string
}

// Result is what an analysis writes to candidates.json and ranking.json, and
// what the API returns. Field names match the contract's schemas.
type Result struct {
	Target       store.Target       `json:"target"`
	Before       Vector             `json:"before"`
	After        *Vector            `json:"after"` // nil when step 9 (check-combined) never measured it
	Dependencies []DependencyResult `json:"dependencies"`
	Warnings     []string           `json:"warnings"`
}

// DependencyResult is one direct dependency: its current vulnerability
// vector and every newer version considered for it.
type DependencyResult struct {
	Name       string      `json:"name"`
	Current    string      `json:"current"`
	Best       string      `json:"best,omitempty"` // empty when no candidate improves on current
	Vector     Vector      `json:"vector"`         // the current version's vector
	Candidates []Candidate `json:"candidates"`     // ascending by version
}

// Candidate is one newer version of a dependency, with its vulnerability
// vector and the signals it carries.
type Candidate struct {
	Version   string   `json:"version"`
	Vector    Vector   `json:"vector"`
	Signals   []Signal `json:"signals"`
	Key       bool     `json:"key"`
	Resolved  bool     `json:"resolved"`
	Published string   `json:"published,omitempty"` // RFC 3339, empty when the registry has none
}

// Signal is one fact about a candidate version worth the user's attention.
type Signal struct {
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
	Blocking bool   `json:"blocking"`
}

// Vector is rank.Vector in its JSON form: five counts, critical to unknown.
type Vector [5]int

// Kind identifies this job to the queue and names the id it assigns
// ("analysis-1", "analysis-2", ...).
func (a *Analysis) Kind() string { return "analysis" }

// statusFile is the on-disk shape of status.json: state, step timings, tool
// versions, the vulnerability database's date and the target. The queue,
// not this job, has the last word on the final state of a job (it tells
// "cancelled" apart from "failed"), so State here is this job's own
// best-effort account for a reader of the committed directory alone.
//
// Named statusFile, not analysisStatus: the export job (internal/jobs,
// area 2) already declares its own analysisStatus, a narrower read-only
// view of this same file, in export.go.
type statusFile struct {
	State        store.State  `json:"state"`
	CreatedAt    time.Time    `json:"createdAt"`
	Steps        []stepRecord `json:"steps"`
	PnpmVersion  string       `json:"pnpmVersion"`
	TrivyVersion string       `json:"trivyVersion"`
	TrivyDBDate  time.Time    `json:"trivyDbDate"`
	Target       store.Target `json:"target"`
}

// stepRecord is one entry of status.json's step timings.
type stepRecord struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	DurationMs int64  `json:"durationMs"`
}

// stepData is the payload of a "step" event.
type stepData struct {
	Name       string      `json:"name"`
	State      store.State `json:"state"`
	DurationMs int64       `json:"durationMs"`
}

// progressData is the payload of a "progress" event.
type progressData struct {
	Done  int `json:"done"`
	Total int `json:"total"`
}

// candidateData is the payload of a "candidate" event.
type candidateData struct {
	Dependency string   `json:"dependency"`
	Version    string   `json:"version"`
	Vector     Vector   `json:"vector"`
	Signals    []string `json:"signals"`
}

// logData is the payload of a "log" event.
type logData struct {
	Line string `json:"line"`
}

// mustJSON marshals v, which is always one of this file's payload types and
// therefore always encodable; a marshal failure here would be a programming
// error, not a runtime condition callers can act on.
func mustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("jobs: marshal event payload: %v", err))
	}
	return data
}

// run holds the state one Run call thread through its steps: the emitter,
// the log file, the accumulating result and the step timings that go into
// status.json.
type run struct {
	a       *Analysis
	ctx     context.Context
	emit    func(Event)
	logFile *os.File
	result  *Result
	steps   []stepRecord
}

// runStep runs fn, emits exactly one "step" event for name and records its
// timing in status.json, regardless of whether fn succeeds.
func (r *run) runStep(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	state := store.Done
	switch {
	case r.ctx.Err() != nil:
		state = store.Cancelled
	case err != nil:
		state = store.Failed
	}
	duration := time.Since(start).Milliseconds()
	r.steps = append(r.steps, stepRecord{Name: name, State: string(state), DurationMs: duration})
	r.emit(Event{Kind: "step", Data: mustJSON(stepData{Name: name, State: state, DurationMs: duration})})
	return err
}

// log writes line to log.txt and emits a matching "log" event.
func (r *run) log(line string) {
	fmt.Fprintln(r.logFile, line)
	r.emit(Event{Kind: "log", Data: mustJSON(logData{Line: line})})
}

// progress emits a "progress" event.
func (r *run) progress(done, total int) {
	r.emit(Event{Kind: "progress", Data: mustJSON(progressData{Done: done, Total: total})})
}

// commit writes status.json and renames the pending .tmp directory into
// place. Analyses keep their directory whatever the outcome, unlike
// exports, so this rename is unconditional.
func (a *Analysis) commit(status statusFile) error {
	if err := a.Store.WriteJSON(filepath.Join(a.Dir, "status.json"), status); err != nil {
		return fmt.Errorf("jobs: write status.json: %w", err)
	}
	final := strings.TrimSuffix(a.Dir, ".tmp")
	if err := os.Rename(a.Dir, final); err != nil {
		return fmt.Errorf("jobs: commit analysis directory: %w", err)
	}
	return nil
}

// Run executes the nine steps of spec section 4 in order, stopping at the
// first step whose failure the table marks as fatal. It always commits the
// pending directory, even on failure or cancellation, so a failed, cancelled
// or interrupted analysis keeps its directory and log.
func (a *Analysis) Run(ctx context.Context, emit func(Event)) (err error) {
	logFile, ferr := os.OpenFile(filepath.Join(a.Dir, "log.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o664)
	if ferr != nil {
		return fmt.Errorf("jobs: open log.txt: %w", ferr)
	}
	defer logFile.Close()

	createdAt := time.Now().UTC()
	// Written before the first step, so a crash leaves this file behind
	// with state running for the startup sweep (store.MarkRunningInterrupted)
	// to find: commit only ever writes the terminal outcome, which without
	// this early write means nothing on disk ever holds the running state
	// the sweep looks for.
	if werr := a.Store.WriteJSON(filepath.Join(a.Dir, "status.json"), statusFile{
		State:     store.Running,
		CreatedAt: createdAt,
		Target:    a.Project.Target,
	}); werr != nil {
		return fmt.Errorf("jobs: write initial status.json: %w", werr)
	}

	r := &run{
		a:       a,
		ctx:     ctx,
		emit:    emit,
		logFile: logFile,
		result:  &Result{Target: a.Project.Target},
	}

	trivyVersion, trivyDBDate := "", time.Time{}
	defer func() {
		state := store.Done
		switch {
		case ctx.Err() != nil:
			state = store.Cancelled
		case err != nil:
			state = store.Failed
		}
		commitErr := a.commit(statusFile{
			State:        state,
			CreatedAt:    createdAt,
			Steps:        r.steps,
			PnpmVersion:  a.Project.Target.PnpmVer,
			TrivyVersion: trivyVersion,
			TrivyDBDate:  trivyDBDate,
			Target:       a.Project.Target,
		})
		if commitErr != nil {
			err = errors.Join(err, commitErr)
		}
	}()

	manifest, err := r.stepValidate()
	if err != nil {
		return err
	}

	trivyVersion, trivyDBDate, err = r.stepPrepareTools()
	if err != nil {
		return err
	}

	projectPkgs, err := r.stepResolveProject(manifest)
	if err != nil {
		return err
	}

	beforeIndex, err := r.stepScanProject(projectPkgs)
	if err != nil {
		return err
	}

	deps := r.stepListCandidates(manifest)

	outcomes, err := r.stepResolveCandidates(deps, manifest, beforeIndex)
	if err != nil {
		return err
	}

	combinedIndex, err := r.stepScanCandidates(outcomes)
	if err != nil {
		return err
	}

	if err := r.stepRank(deps, outcomes, combinedIndex); err != nil {
		return err
	}

	r.stepCheckCombined(manifest)

	if werr := a.Store.WriteJSON(filepath.Join(a.Dir, "ranking.json"), r.result); werr != nil {
		return fmt.Errorf("jobs: write ranking.json: %w", werr)
	}
	return nil
}
