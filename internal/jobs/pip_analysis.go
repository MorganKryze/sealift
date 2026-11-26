package jobs

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/pip"
	"github.com/MorganKryze/sealift/rank"
	"github.com/MorganKryze/sealift/sbom"
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

// ProjectID is the id of the project the job runs for.
func (a *PipAnalysis) ProjectID() string { return a.Project.ID }

// PipResult is what a pip analysis writes to pip-result.json, and what the
// API returns as pipResult. Field names match the contract's schemas.
type PipResult struct {
	Target     store.PipTarget      `json:"target"`
	Files      []string             `json:"files"`    // every requirements file the set was resolved from
	Packages   []PipPackage         `json:"packages"` // sorted by normalized name
	Blocking   []PipBlocking        `json:"blocking"`
	Warnings   []string             `json:"warnings"`
	Advisories map[string]Advisory  `json:"advisories,omitempty"` // by CVE id; a result without the key predates advisories
	Previous   *PipPreviousCrossing `json:"previous,omitempty"`   // absent when none reads, and before crossings were compared
	Removed    []PipRemoved         `json:"removed,omitempty"`    // the previous crossing's packages the set no longer holds
}

// PipPackage is one package of the resolved set. A done analysis may hold
// a package without a wheel, which blocking names and no export takes.
type PipPackage struct {
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	Files    []string     `json:"files"`              // project files that pin it, empty for a transitive package
	PinnedAt []PipPlace   `json:"pinnedAt,omitempty"` // the set's pins; absent for a transitive package and before places were recorded
	Wheel    *PipWheel    `json:"wheel,omitempty"`    // absent until chosen, and for a blocked package
	CVEs     []PipFinding `json:"cves"`               // sorted by severity, then id
	Yanked   *PipYanked   `json:"yanked,omitempty"`   // absent when the index keeps the release
	Previous *PipPrevious `json:"previous,omitempty"` // absent for a new package and with no previous crossing
}

// PipPrevious is a package as the previous crossing held it.
type PipPrevious struct {
	Version   string       `json:"version"`
	CVEs      []PipFinding `json:"cves"` // at that version, from this analysis's scan
	MajorJump bool         `json:"majorJump"`
}

// PipPreviousCrossing names the export a pip analysis compares its set
// with.
type PipPreviousCrossing struct {
	ProjectID   string    `json:"projectId"`
	ProjectName string    `json:"projectName"`
	ExportID    string    `json:"exportId"`
	AnalysisID  string    `json:"analysisId"`
	SealedAt    time.Time `json:"sealedAt"`
}

// PipRemoved is a package of the previous crossing the set no longer
// holds.
type PipRemoved struct {
	Name    string       `json:"name"`
	Version string       `json:"version"`
	CVEs    []PipFinding `json:"cves"` // at that version, from this analysis's scan
}

// PipPlace is a line of a requirements file that pins a package.
type PipPlace struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// PipYanked marks a package whose chosen file the index has yanked.
type PipYanked struct {
	Reason string `json:"reason"` // empty when the index gives none
}

// PipWheel is the wheel chosen for a package, as the index lists it.
type PipWheel struct {
	File       string     `json:"file"`
	URL        string     `json:"url"`
	Sha256     string     `json:"sha256"`
	Size       int64      `json:"size"`
	UploadedAt *time.Time `json:"uploadedAt,omitempty"` // in UTC; absent when the index gives none
}

// PipFinding is one known vulnerability of a package.
type PipFinding struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	FixedVersions []string `json:"fixedVersions"`
	Title         string   `json:"title,omitempty"`
}

// PipBlocking is a package the target cannot install from a wheel.
type PipBlocking struct {
	Name     string     `json:"name"`
	Version  string     `json:"version"`
	Kind     string     `json:"kind"` // source-only, other-platforms, no-files, hash-mismatch
	Detail   string     `json:"detail"`
	PinnedAt []PipPlace `json:"pinnedAt,omitempty"` // absent for a transitive package
}

// shownProblems bounds the items a failure or a warning names: requirements
// problems, or packages outside the resolved set. The log lists every one.
const shownProblems = 3

// pipRun holds the state one PipAnalysis.Run call threads through its
// steps.
type pipRun struct {
	stepLog
	a          *PipAnalysis
	createdAt  time.Time // when the run started
	start      time.Time // createdAt to the second
	set        pip.Set
	files      []string  // the project's file names, in upload order
	pins       []pip.Pin // the pins the target installs
	uvBin      string
	resolved   []runner.Resolved          // with each blocked pin at its version
	indexFiles map[string][]pip.IndexFile // by name@version, each page read once
	wheels     map[string]PipWheel        // by normalized name
	yanked     map[string]PipYanked       // by normalized name
	blocking   []PipBlocking              // every package with no wheel the target can install
	warnings   []string
}

func (r *pipRun) resultPath() string { return filepath.Join(r.a.Dir, "pip-result.json") }

// releaseCut is the upload time a package no pin fixes is held to: uv
// resolves it, and choose-wheels picks its wheel, among the files uploaded
// before it.
func (r *pipRun) releaseCut() time.Time {
	return r.start.Add(-time.Duration(r.a.Settings.MinReleaseAgeDays) * 24 * time.Hour)
}

// Run validates the project's files, installs the target's uv, records
// each pin with no wheel, resolves the other lines together, records one
// wheel per package, or blocking where there is none, and scans the whole
// set. Like the npm analysis, it always commits the pending directory, so
// a failed or cancelled run keeps its log. A run that fails after a
// package was found with no wheel still writes pip-result.json, listing
// every such package and no other, so the failure never hides one.
func (a *PipAnalysis) Run(ctx context.Context, emit func(Event)) (err error) {
	logFile, ferr := openLog(filepath.Join(a.Dir, "log.txt"))
	if ferr != nil {
		return fmt.Errorf("jobs: open log.txt: %w", withoutPath(ferr))
	}
	defer logFile.Close()

	target := a.Project.PipTarget
	createdAt := time.Now().UTC()
	// Written first, so the startup sweep finds a crashed run in state
	// running, as for the npm analysis.
	if werr := a.Store.WriteJSON(filepath.Join(a.Dir, "status.json"), statusFile{
		State: store.Running, CreatedAt: createdAt, PipTarget: &target,
	}); werr != nil {
		return fmt.Errorf("jobs: write initial status.json: %w", withoutPath(werr))
	}

	r := &pipRun{stepLog: stepLog{ctx: ctx, root: a.Store.Root(), emit: emit, logFile: logFile}, a: a, createdAt: createdAt, start: createdAt.Truncate(time.Second)}
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
	if err := r.stepCheckPins(); err != nil {
		return err
	}
	if err := r.resolveAndScan(); err != nil {
		if len(r.blocking) > 0 && ctx.Err() == nil {
			if werr := r.writeFailedResult(r.blocking); werr != nil {
				err = errors.Join(err, werr)
			}
		}
		return err
	}
	return nil
}

// resolveAndScan runs the steps after check-pins.
func (r *pipRun) resolveAndScan() error {
	if err := r.stepResolve(); err != nil {
		return err
	}
	if err := r.stepChooseWheels(r.resolved); err != nil {
		return err
	}
	return r.stepScan()
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
		names := make([]string, len(stored))
		for i, f := range stored {
			files[i] = pip.File{Name: f.Name, Data: f.Data}
			names[i] = f.Name
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
			if err := writeNew(filepath.Join(dir, f.Name), f.Data); err != nil {
				return fmt.Errorf("copy %s: %w", f.Name, err)
			}
		}
		r.set, r.files = set, names
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
// refreshes the Trivy database. A failed database update only warns: the
// scan runs on the database already there.
func (r *pipRun) stepPrepareTools() (trivyVersion string, dbDate time.Time, err error) {
	err = r.runStep("prepare-tools", func() error {
		version := r.a.Project.PipTarget.UvVer
		bin, uerr := r.a.Tools.EnsureUv(r.ctx, version)
		if uerr != nil {
			return fmt.Errorf("install uv %s: %w", version, uerr)
		}
		r.uvBin = bin
		if state, serr := r.a.Tools.TrivyState(r.ctx); serr == nil {
			trivyVersion, dbDate = state.Active, state.DBDate
		}
		if _, derr := r.a.Trivy.UpdateDB(r.ctx); derr != nil {
			r.warnings = append(r.warnings, causeText(r.root, fmt.Sprintf(
				"could not refresh the vulnerability database: %v; using the database from %s", derr, dbDateLabel(dbDate))))
			r.log(fmt.Sprintf("trivy database update failed: %v", derr))
			return nil
		}
		if state, serr := r.a.Tools.TrivyState(r.ctx); serr == nil {
			trivyVersion, dbDate = state.Active, state.DBDate
		}
		return nil
	})
	return trivyVersion, dbDate, err
}

// stepResolve resolves every file together with uv, holding the pins
// check-pins blocked as constraints, and writes project/requirements.lock.
// Every package is held to the minimum release age, except those the
// target's pins fix. Each blocked pin then joins the set at its version,
// without a wheel. When uv itself names a package with no wheel the target
// can install, it gives no set: the step fails, and the package joins
// blocking.
func (r *pipRun) stepResolve() error {
	return r.runStep("resolve", func() error {
		dir, err := r.a.Store.NewResolveDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)

		// A blocked pin's line becomes a constraint: nothing requires it,
		// but should another package need it, uv keeps its version and
		// stops on it rather than resolving a version the pin rules out.
		input := r.set
		input.Requirements = nil
		input.Constraints = slices.Clone(r.set.Constraints)
		for _, p := range r.set.Requirements {
			if r.blocked(p.Key) {
				input.Constraints = append(input.Constraints, p)
			} else {
				input.Requirements = append(input.Requirements, p)
			}
		}
		slices.SortStableFunc(input.Constraints, func(a, b pip.Pin) int { return strings.Compare(a.Key, b.Key) })
		exempt := make([]string, 0, len(r.pins))
		for _, p := range r.pins {
			exempt = append(exempt, p.Key)
		}
		slices.Sort(exempt)
		res, err := r.a.Uv.Compile(r.ctx, runner.CompileInput{
			Bin:          r.uvBin,
			Dir:          dir,
			Requirements: input.RequirementsIn(),
			Constraints:  input.ConstraintsTxt(),
			Target:       r.a.Project.PipTarget,
			Index:        r.a.Index.Index,
			ExcludeNewer: r.releaseCut(),
			Exempt:       slices.Compact(exempt),
			ExemptUntil:  r.start,
		})
		for _, line := range strings.Split(strings.TrimRight(res.Output, "\n"), "\n") {
			if line != "" {
				r.log("uv: " + line)
			}
		}
		if err != nil {
			if b, ok := blockingFromUv(res.Output); ok && !r.blocked(b.Name) {
				r.block(b)
			}
			if named := r.pinsNamedIn(err.Error()); named != "" {
				return fmt.Errorf("%w; pinned by %s", err, named)
			}
			return err
		}
		set := slices.Clone(res.Set)
		for _, b := range r.blocking {
			if !slices.ContainsFunc(set, func(p runner.Resolved) bool { return p.Name == b.Name }) {
				set = append(set, runner.Resolved{Name: b.Name, Version: b.Version})
			}
		}
		slices.SortStableFunc(set, func(a, b runner.Resolved) int { return strings.Compare(a.Name, b.Name) })
		if err := r.checkPins(set, r.pins); err != nil {
			return err
		}
		r.resolved = set
		if err := os.MkdirAll(filepath.Join(r.a.Dir, "project"), 0o770); err != nil {
			return err
		}
		return writeNew(filepath.Join(r.a.Dir, "project", "requirements.lock"), res.Lock)
	})
}

// stepScan scans the resolved set with Trivy, together with each version
// the previous crossing held, keeping the report as project.trivy.json,
// and writes pip-result.json. A scan failure stops the job, so a done
// analysis never stands for a scan that did not run.
func (r *pipRun) stepScan() error {
	return r.runStep("scan", func() error {
		previous, earlier := r.previousCrossing()
		components := make([]sbom.Component, 0, len(r.resolved)+len(earlier))
		scanned := map[string]bool{}
		for _, p := range slices.Concat(r.resolved, earlier) {
			if key := p.Name + "@" + p.Version; !scanned[key] {
				scanned[key] = true
				components = append(components, sbom.PyPIComponents(p.Name, p.Version)...)
			}
		}
		findings, err := scanComponents(r.ctx, r.a.Trivy, components, filepath.Join(r.a.Dir, "project.trivy.json"))
		if err != nil {
			return fmt.Errorf("scan the resolved set: %w", err)
		}
		// Trivy may name a package as its metadata or the SBOM spells it,
		// such as Jinja2 or plone.namedfile, while the set holds normalized
		// names. Both spellings of a project fold into one key, where
		// rank.Index.Set counts each vulnerability once.
		for i := range findings {
			findings[i].Package = pip.Normalize(findings[i].Package)
		}
		index := rank.NewIndex(findings)

		result := PipResult{
			Target:   r.a.Project.PipTarget,
			Files:    nonNil(r.files),
			Packages: make([]PipPackage, 0, len(r.resolved)),
			Blocking: sortedBlocking(r.blocking),
			Warnings: nonNil(r.warnings),
			Previous: previous,
		}
		advisories := map[string]Advisory{}
		findingsOf := func(name, version string) []PipFinding {
			return pipFindingsOf(r.root, index.Set([]string{name + "@" + version}), advisories, r.logDropped)
		}
		earlierVersion := make(map[string]string, len(earlier))
		matched := map[string]bool{}
		for _, p := range earlier {
			earlierVersion[p.Name] = p.Version
			matched[p.Name+"@"+p.Version] = true
		}
		current := make(map[string]bool, len(r.resolved))
		for _, p := range r.resolved {
			key := p.Name + "@" + p.Version
			matched[key] = true
			pkg := PipPackage{
				Name:     p.Name,
				Version:  p.Version,
				Files:    nonNil(r.set.FilesOf(p.Name)),
				PinnedAt: r.placesOf(p.Name),
				CVEs:     findingsOf(p.Name, p.Version),
			}
			if w, ok := r.wheels[p.Name]; ok {
				pkg.Wheel = &w
			}
			if y, ok := r.yanked[p.Name]; ok {
				pkg.Yanked = &y
			}
			if v, ok := earlierVersion[p.Name]; ok {
				pkg.Previous = &PipPrevious{Version: v, CVEs: findingsOf(p.Name, v), MajorJump: pipMajorJump(v, p.Version)}
			}
			current[p.Name] = true
			result.Packages = append(result.Packages, pkg)
		}
		for _, p := range earlier {
			if !current[p.Name] {
				result.Removed = append(result.Removed, PipRemoved{Name: p.Name, Version: p.Version, CVEs: findingsOf(p.Name, p.Version)})
			}
		}
		if len(advisories) > 0 {
			result.Advisories = advisories
		}
		var outside []string
		outsideFindings := 0
		for _, key := range slices.Sorted(maps.Keys(index)) {
			if matched[key] {
				continue
			}
			n := len(index.Set([]string{key}))
			name := cleanName(key)
			r.log(fmt.Sprintf("trivy reported %d %s for %s, which is not in the set", n, plural(n, "finding", "findings"), name))
			outside = append(outside, name)
			outsideFindings += n
		}
		if len(outside) > 0 {
			result.Warnings = append(result.Warnings, causeText(r.root, outsideWarning(outsideFindings, outside)))
		}
		return r.a.Store.WriteJSON(r.resultPath(), result)
	})
}

// previousCrossing finds the set this analysis compares with, sorted by
// name, and logs what it found. One that does not read adds a warning and
// counts as none.
func (r *pipRun) previousCrossing() (*PipPreviousCrossing, []runner.Resolved) {
	previous, earlier, err := previousCrossing(r.a.Store, r.a.Project, r.createdAt)
	switch {
	case err != nil:
		r.log(causeText(r.root, err.Error()))
		r.warnings = append(r.warnings, causeText(r.root, fmt.Sprintf(
			"The previous crossing %s could not be read, so nothing is compared", cleanName(strings.TrimSpace(r.a.Project.Name)))))
		return nil, nil
	case previous == nil:
		r.log("no previous crossing: no pip project of this name has a done export from before this analysis")
		return nil, nil
	}
	r.log(fmt.Sprintf("previous crossing: export %s of project %s, %d %s", previous.ExportID, previous.ProjectID,
		len(earlier), plural(len(earlier), "package", "packages")))
	slices.SortStableFunc(earlier, func(a, b runner.Resolved) int { return strings.Compare(a.Name, b.Name) })
	return previous, earlier
}

// outsideWarning tells how many findings matched no package of the set,
// and names the first shownProblems of the packages they name, as
// name@version.
func outsideWarning(findings int, names []string) string {
	shown := names[:min(len(names), shownProblems)]
	msg := fmt.Sprintf("%d Trivy %s matched no package of the resolved set: %s",
		findings, plural(findings, "finding", "findings"), strings.Join(shown, ", "))
	if more := len(names) - len(shown); more > 0 {
		msg += fmt.Sprintf(", and %d more in the log", more)
	}
	return msg
}

// shownNameLimit bounds, in runes, a package name from Trivy's report that
// the log or a warning quotes.
const shownNameLimit = 100

// cleanName drops control and format characters from a name Trivy
// reported, turns each whitespace control into a space, and cuts it to
// shownNameLimit runes.
func cleanName(s string) string { return cleanText(s, shownNameLimit) }

// cleanText drops control and format characters from s, which comes from
// outside, turns each whitespace control into a space, and cuts it to
// limit runes.
func cleanText(s string, limit int) string {
	runes := []rune(dropControl(s))
	if len(runes) <= limit {
		return string(runes)
	}
	return string(runes[:limit]) + "..."
}

// scanComponents writes components as a CycloneDX SBOM beside outPath,
// scans it with Trivy into outPath, and returns the findings the report
// lists.
func scanComponents(ctx context.Context, trivy runner.Trivy, components []sbom.Component, outPath string) ([]rank.Finding, error) {
	sbomPath := outPath + ".cdx.json"
	defer os.Remove(sbomPath)

	f, err := createNew(sbomPath)
	if err != nil {
		return nil, err
	}
	werr := sbom.WriteCycloneDX(f, components)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, fmt.Errorf("write sbom: %w", werr)
	}
	if _, err := trivy.ScanSBOM(ctx, sbomPath, outPath); err != nil {
		return nil, fmt.Errorf("trivy scan: %w", err)
	}
	return readTrivyReport(outPath, trivyReportLimit)
}

// trivyReportLimit bounds the Trivy report an npm or pip scan reads. A finding
// takes about 4 KiB of it, so this holds some 16,000 findings.
const trivyReportLimit = 64 << 20

// readTrivyReport reads the findings of the report at path, under
// readRegularFile's rule.
func readTrivyReport(path string, limit int64) ([]rank.Finding, error) {
	data, err := readRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	return rank.ReadTrivyJSON(bytes.NewReader(data))
}

// pipFindingsOf converts a vulnerability set, as rank.Index.Set returns
// it, into findings sorted by severity, critical first, then id, with
// titles cleaned as advisoryTitle cleans them. It adds each finding's
// advisory to advisories in that order, unless the table already holds
// one for its id, and passes logDropped each finding it adds.
func pipFindingsOf(root string, set map[string]rank.Finding, advisories map[string]Advisory, logDropped func(rank.Finding)) []PipFinding {
	sorted := slices.SortedFunc(maps.Values(set), func(a, b rank.Finding) int {
		return cmp.Or(cmp.Compare(a.Severity, b.Severity), strings.Compare(a.ID, b.ID))
	})
	findings := make([]PipFinding, len(sorted))
	for i, f := range sorted {
		findings[i] = PipFinding{ID: f.ID, Severity: severityText(f.Severity), FixedVersions: fixedVersions(f.FixedVersion), Title: advisoryTitle(root, f.Title)}
		if _, ok := advisories[f.ID]; !ok {
			logDropped(f)
		}
		addAdvisory(advisories, root, f)
	}
	return findings
}

// fixedVersions splits Trivy's FixedVersion, such as "3.1.3, 3.0.4", into
// its versions. An empty value gives an empty list.
func fixedVersions(s string) []string {
	versions := []string{}
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			versions = append(versions, v)
		}
	}
	return versions
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
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
	platform := platformOfPip(r.a.Project.PipTarget)
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
// a package something else needs, so it may be absent. A blocked pin that
// came back at another version is a package another one needs, and the
// refusal names it with why it has no wheel.
func (r *pipRun) checkPins(set []runner.Resolved, pins []pip.Pin) error {
	resolved := make(map[string]string, len(set))
	for _, p := range set {
		resolved[p.Name] = p.Version
	}
	var needed []PipBlocking
	for _, b := range r.blocking {
		if version, ok := resolved[b.Name]; ok && !pip.SameVersion(version, b.Version) {
			needed = append(needed, b)
		}
	}
	if len(needed) > 0 {
		return r.neededBlocking(needed)
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

// neededBlocking fails a resolution on blocked packages another package
// needs, naming the first shownProblems with the files that pin them and
// why. The result lists every one.
func (r *pipRun) neededBlocking(blocking []PipBlocking) error {
	shown := make([]string, 0, shownProblems)
	for _, b := range blocking[:min(len(blocking), shownProblems)] {
		shown = append(shown, r.describeBlocking(b))
	}
	msg := fmt.Sprintf("%d %s no wheel the target can install and %s: %s", len(blocking),
		plural(len(blocking), "package has", "packages have"),
		plural(len(blocking), "another package needs it", "other packages need them"), strings.Join(shown, "; "))
	if len(blocking) > shownProblems {
		msg += "; the result lists every one"
	}
	return errors.New(msg)
}
