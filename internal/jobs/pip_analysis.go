package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/pip"
)

// PipAnalysis resolves a pip project's requirements files together with
// uv. It implements Job.
type PipAnalysis struct {
	Store    *store.Store
	Tools    *tools.Manager
	Uv       runner.Uv
	Trivy    runner.Trivy
	Index    *pip.Client
	Project  store.Project
	Settings store.Settings
	Dir, ID  string // the pending analyses/<id> directory and its id
}

// Kind identifies this job to the queue, as an npm analysis does.
func (a *PipAnalysis) Kind() string { return "analysis" }

// StoreID names the job by its store directory id, which the client uses.
func (a *PipAnalysis) StoreID() string { return a.ID }

// shownProblems bounds the requirements problems a validate failure names;
// the log lists every one.
const shownProblems = 3

// pipRun holds the state one PipAnalysis.Run call threads through its
// steps.
type pipRun struct {
	stepLog
	a     *PipAnalysis
	start time.Time
	set   pip.Set
	uvBin string
}

// Run validates the project's files, installs the target's uv, and
// resolves the files together. Like the npm analysis, it always commits the
// pending directory, so a failed or cancelled run keeps its log.
func (a *PipAnalysis) Run(ctx context.Context, emit func(Event)) (err error) {
	logFile, ferr := os.OpenFile(filepath.Join(a.Dir, "log.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o664)
	if ferr != nil {
		return fmt.Errorf("jobs: open log.txt: %w", ferr)
	}
	defer logFile.Close()

	target := a.Project.PipTarget
	createdAt := time.Now().UTC()
	// Written first, so the startup sweep finds a crashed run in state
	// running, as for the npm analysis.
	if werr := a.Store.WriteJSON(filepath.Join(a.Dir, "status.json"), statusFile{
		State: store.Running, CreatedAt: createdAt, PipTarget: &target,
	}); werr != nil {
		return fmt.Errorf("jobs: write initial status.json: %w", werr)
	}

	r := &pipRun{stepLog: stepLog{ctx: ctx, emit: emit, logFile: logFile}, a: a, start: createdAt.Truncate(time.Second)}
	uvVersion, trivyVersion, trivyDBDate := "", "", time.Time{}
	defer func() {
		state := store.Done
		switch {
		case ctx.Err() != nil:
			state = store.Cancelled
		case err != nil:
			state = store.Failed
		}
		status := statusFile{
			State:        state,
			CreatedAt:    createdAt,
			Steps:        r.steps,
			UvVersion:    uvVersion,
			TrivyVersion: trivyVersion,
			TrivyDBDate:  trivyDBDate,
			PipTarget:    &target,
		}
		if commitErr := commitAnalysis(a.Store, a.Dir, status); commitErr != nil {
			err = errors.Join(err, commitErr)
		}
	}()

	if err := r.stepValidate(); err != nil {
		return err
	}
	if trivyVersion, trivyDBDate, err = r.stepPrepareTools(); err != nil {
		return err
	}
	uvVersion = target.UvVer
	return r.stepResolve()
}

// stepValidate parses the stored files and copies them under
// requirements/. A problem stops the job before anything is fetched.
func (r *pipRun) stepValidate() error {
	return r.runStep("validate", func() error {
		stored, err := r.a.Store.ProjectRequirements(r.a.Project.ID)
		if err != nil {
			return fmt.Errorf("read the requirements files: %w", err)
		}
		files := make([]pip.File, len(stored))
		for i, f := range stored {
			files[i] = pip.File{Name: f.Name, Data: f.Data}
		}
		set, problems := pip.ParseFiles(files)
		if len(problems) > 0 {
			shown := make([]string, 0, shownProblems)
			for i, p := range problems {
				line := formatPipProblem(p)
				r.log(line)
				if i < shownProblems {
					shown = append(shown, line)
				}
			}
			msg := fmt.Sprintf("%d %s in the requirements files: %s", len(problems), plural(len(problems), "problem", "problems"), strings.Join(shown, "; "))
			if len(problems) > shownProblems {
				msg += "; the log lists the rest"
			}
			return errors.New(msg)
		}
		dir := filepath.Join(r.a.Dir, "requirements")
		if err := os.MkdirAll(dir, 0o770); err != nil {
			return err
		}
		for _, f := range stored {
			// The store checked each name before handing it out.
			if err := os.WriteFile(filepath.Join(dir, f.Name), f.Data, 0o664); err != nil {
				return fmt.Errorf("copy %s: %w", f.Name, err)
			}
		}
		r.set = set
		return nil
	})
}

func formatPipProblem(p pip.Problem) string {
	place := p.File
	if p.Line > 0 {
		place = fmt.Sprintf("%s line %d", p.File, p.Line)
	}
	if p.Text == "" {
		return place + ": " + p.Reason
	}
	return fmt.Sprintf("%s: %s: %s", place, p.Text, p.Reason)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// stepPrepareTools installs the target's uv, held to the release age, then
// refreshes the Trivy database. A failed database update on a stale
// database only goes to the log.
func (r *pipRun) stepPrepareTools() (trivyVersion string, dbDate time.Time, err error) {
	err = r.runStep("prepare-tools", func() error {
		version := r.a.Project.PipTarget.UvVer
		bin, uerr := r.a.Tools.EnsureUv(r.ctx, version, false)
		if uerr != nil {
			return fmt.Errorf("install uv %s: %w", version, uerr)
		}
		r.uvBin = bin
		if state, serr := r.a.Tools.TrivyState(r.ctx); serr == nil {
			trivyVersion, dbDate = state.Active, state.DBDate
		}
		if _, derr := r.a.Trivy.UpdateDB(r.ctx); derr != nil {
			r.log(fmt.Sprintf("trivy database update failed: %v; using the database from %s", derr, dbDateLabel(dbDate)))
			return nil
		}
		if state, serr := r.a.Tools.TrivyState(r.ctx); serr == nil {
			trivyVersion, dbDate = state.Active, state.DBDate
		}
		return nil
	})
	return trivyVersion, dbDate, err
}

// stepResolve resolves every file together with uv and writes
// project/requirements.lock. Every package is held to the minimum release
// age, except those the target's pins fix.
func (r *pipRun) stepResolve() error {
	return r.runStep("resolve", func() error {
		dir, err := r.a.Store.NewResolveDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)

		pins := r.targetPins()
		exempt := make([]string, 0, len(pins))
		for _, p := range pins {
			exempt = append(exempt, p.Key)
		}
		slices.Sort(exempt)
		age := time.Duration(r.a.Settings.MinReleaseAgeDays) * 24 * time.Hour
		res, err := r.a.Uv.Compile(r.ctx, runner.CompileInput{
			Bin:          r.uvBin,
			Dir:          dir,
			Requirements: r.set.RequirementsIn(),
			Constraints:  r.set.ConstraintsTxt(),
			Target:       r.a.Project.PipTarget,
			Index:        r.a.Index.Index,
			ExcludeNewer: r.start.Add(-age),
			Exempt:       slices.Compact(exempt),
			ExemptUntil:  r.start,
		})
		for _, line := range strings.Split(strings.TrimRight(res.Output, "\n"), "\n") {
			if line != "" {
				r.log("uv: " + line)
			}
		}
		if err != nil {
			if named := r.pinsNamedIn(err.Error()); named != "" {
				return fmt.Errorf("%w; pinned by %s", err, named)
			}
			return err
		}
		if err := r.checkPins(res.Set, pins); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(r.a.Dir, "project"), 0o770); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(r.a.Dir, "project", "requirements.lock"), res.Lock, 0o664)
	})
}

// pinsNamedIn lists each pin a failure message names, with the files that
// pin it, such as "mypy (requirements-dev.txt)". uv sees one merged file,
// so it cannot name the files itself.
func (r *pipRun) pinsNamedIn(msg string) string {
	var named []string
	for _, p := range slices.Concat(r.set.Requirements, r.set.Constraints) {
		if mentions(msg, p.Key) {
			named = append(named, fmt.Sprintf("%s (%s)", p.Key, strings.Join(r.set.FilesOf(p.Key), ", ")))
		}
	}
	return strings.Join(named, ", ")
}

// mentions reports whether msg holds name as a whole package name, so
// "mypy" does not match inside "mypy-extensions".
func mentions(msg, name string) bool {
	for from := 0; ; {
		i := strings.Index(msg[from:], name)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(name)
		if (i == 0 || !isNameByte(msg[i-1])) && (end == len(msg) || !isNameByte(msg[end])) {
			return true
		}
		from = i + 1
	}
}

func isNameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.'
}

// targetPins returns the pins that fix a version on the target: those with
// no marker or a marker true there. A pin whose marker is false fixes
// nothing, though another pin may still need its package, at a version the
// resolver chooses under the release age. A marker sealift cannot decide
// keeps its pin, since uv may hold it.
func (r *pipRun) targetPins() []pip.Pin {
	t := r.a.Project.PipTarget
	platform := pip.Platform{Python: t.Python, OS: t.OS, CPU: t.CPU, Glibc: t.Glibc}
	var pins []pip.Pin
	for _, p := range slices.Concat(r.set.Requirements, r.set.Constraints) {
		if p.Marker != "" {
			holds, err := pip.MarkerHolds(p.Marker, platform)
			if err != nil {
				r.log(fmt.Sprintf("%s==%s (%s): %v; the pin stays exempt from the release age", p.Key, p.Version, p.File, err))
			} else if !holds {
				continue
			}
		}
		pins = append(pins, p)
	}
	return pins
}

// checkPins refuses a resolution that gave one of pins another version, or
// left out a requirement whose line has no marker. A constraint only limits
// a package something else needs, so it may be absent.
func (r *pipRun) checkPins(set []runner.Resolved, pins []pip.Pin) error {
	resolved := make(map[string]string, len(set))
	for _, p := range set {
		resolved[p.Name] = p.Version
	}
	for _, p := range pins {
		if version, ok := resolved[p.Key]; ok && !pip.SameVersion(version, p.Version) {
			return fmt.Errorf("the pin %s==%s (%s) came back as %s", p.Key, p.Version, p.File, version)
		}
	}
	for _, p := range r.set.Requirements {
		if _, ok := resolved[p.Key]; !ok && p.Marker == "" {
			return fmt.Errorf("the pin %s==%s (%s) is missing from the resolution", p.Key, p.Version, p.File)
		}
	}
	return nil
}
