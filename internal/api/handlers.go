package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/pip"
)

// manifestSizeLimit bounds an uploaded package.json: real ones run a few
// kilobytes at most, so this only guards against a client sending far more
// than a manifest ever needs to be.
const manifestSizeLimit = 1 << 20

// Handlers implements StrictServerInterface. It holds no state of its own:
// every operation reads or writes through Store, Service or Tools.
type Handlers struct {
	*EventsHandler
	// ListenAddr is the address the server listens on; its host may send a
	// regenerate of the signing key.
	ListenAddr string
	Store      *store.Store
	Service    *jobs.Service
	Tools      *tools.Manager
	Trivy      runner.Trivy
	// Ready answers /healthz. NewHandlers sets it to the tools manager's
	// own check; the server sets the start's preparation.
	Ready Readiness
	// Ephemeral is the idle delay of ephemeral mode, zero when the mode is
	// off. In that mode, deleting a project also empties the shared caches.
	Ephemeral time.Duration
	// Policy is the deployment's policy: the default targets, the limits
	// and the brand.
	Policy policy.Policy
}

// problemBody is the shape every operation's default response carries.
// oapi-codegen generates one distinctly named type per operation even
// though they are all identical, so problem and its callers convert into
// whichever one an operation needs with a plain type conversion.
type problemBody struct {
	Body       Problem
	StatusCode int
}

// problem builds a problemBody from err, mapping store.ErrNotFound and
// jobs.ErrNotFound to 404 and everything else to 500. title names the
// operation that failed; detail is left to err's own message.
func problem(status int, title string, err error) problemBody {
	return problemBody{Body: NewProblem(status, title, err.Error()), StatusCode: status}
}

// statusFor picks the HTTP status a plain error (not a validation failure,
// which callers build their own Problem for) maps to: a sentinel the
// caller could have avoided by asking first (an analysis not done yet, a
// release too young) gets its own status rather than the 500 an
// unexpected failure gets.
func statusFor(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, jobs.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, jobs.ErrNothingToExport), errors.Is(err, jobs.ErrPipSelection), errors.Is(err, store.ErrInvalidTarget), errors.Is(err, store.ErrInvalidRequirements), errors.Is(err, store.ErrInvalidLimits), errors.Is(err, tools.ErrInvalidTrivyVersion), errors.Is(err, tools.ErrInvalidUvVersion):
		return http.StatusBadRequest
	case errors.Is(err, jobs.ErrAnalysisNotDone), errors.Is(err, jobs.ErrPipNotExportable), errors.Is(err, tools.ErrReleaseTooRecent), errors.Is(err, store.ErrBusy):
		return http.StatusConflict
	case errors.Is(err, tools.ErrReleaseSourceUnavailable):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// autoProblem builds a problemBody for err, picking its status with
// statusFor. Most handlers have nothing more specific to say about a
// failure than this.
func autoProblem(title string, err error) problemBody {
	return problem(statusFor(err), title, err)
}

// manifestProblem builds the 400 response for an invalid package.json,
// listing every offending entry npm.Manifest.Validate found.
func manifestProblem(problems []manifestValidationEntry) problemBody {
	p := NewProblem(http.StatusBadRequest, "invalid package.json", "the manifest has entries sealift cannot analyze")
	details := make([]ProblemDetail, len(problems))
	for i, entry := range problems {
		details[i] = ProblemDetail{Field: entry.Field, Reason: entry.Reason}
		if entry.Name != "" {
			details[i].Name = ptr(entry.Name)
		}
		if entry.Value != "" {
			details[i].Value = ptr(entry.Value)
		}
	}
	p.Errors = &details
	return problemBody{Body: p, StatusCode: http.StatusBadRequest}
}

// requirementsProblem builds the 400 response for refused requirements
// files, one entry per problem with its file, line, text and reason.
func requirementsProblem(problems []pip.Problem) problemBody {
	detail := "the requirements files have lines sealift cannot analyze"
	if len(problems) > maxRequirementsProblems {
		detail = fmt.Sprintf("%s: %d refusals, the first %d are listed", detail, len(problems), maxRequirementsProblems)
		problems = problems[:maxRequirementsProblems]
	}
	p := NewProblem(http.StatusBadRequest, "invalid requirements files", detail)
	details := make([]ProblemDetail, len(problems))
	for i, pr := range problems {
		details[i] = ProblemDetail{Field: pr.File, Reason: pr.Reason}
		if pr.Line > 0 {
			details[i].Line = ptr(pr.Line)
		}
		if pr.Text != "" {
			details[i].Value = ptr(pr.Text)
		}
	}
	p.Errors = &details
	return problemBody{Body: p, StatusCode: http.StatusBadRequest}
}

// toolsMissingProblem builds the 409 response for an operation that
// needs trivy and its database before it can queue
// anything: the same list tools.Manager.Ready reports on GET /tools, so
// the web and the API agree on what "ready" means.
func toolsMissingProblem(missing []string) problemBody {
	p := NewProblem(http.StatusConflict, "tools not ready", "trivy or its database is not installed yet")
	p.Type = ptr("tools-missing")
	m := missing
	p.Missing = &m
	return problemBody{Body: p, StatusCode: http.StatusConflict}
}

// invalidSelectionProblem builds the 400 response for an export request
// whose selection names one or more versions the analysis did not
// resolve, listing every offending "name@version" entry.
func invalidSelectionProblem(bad []string) problemBody {
	p := NewProblem(http.StatusBadRequest, "invalid export selection", "the selection names versions the analysis did not resolve")
	details := make([]ProblemDetail, len(bad))
	for i, entry := range bad {
		details[i] = ProblemDetail{Field: "selection", Name: ptr(entry), Reason: "not a version the analysis resolved"}
	}
	p.Errors = &details
	return problemBody{Body: p, StatusCode: http.StatusBadRequest}
}

// manifestValidationEntry mirrors npm.Problem's fields, so this file does
// not need to import npm just to shape a Problem Details response; the
// caller (handlers_projects.go) converts from npm.Problem to this.
type manifestValidationEntry struct {
	Field, Name, Value, Reason string
}

// decodeAnalysisResult unmarshals raw (an analysis' ranking.json, or nil
// before one exists) into the contract's AnalysisResult shape. Field names
// match internal/jobs.Result's JSON tags exactly, so this never needs that
// package's own Go type.
func decodeAnalysisResult(raw json.RawMessage) (AnalysisResult, bool) {
	if len(raw) == 0 {
		return AnalysisResult{}, false
	}
	var result AnalysisResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return AnalysisResult{}, false
	}
	// An analysis written by an older release lacks fields added since, such
	// as cves, and the contract marks these arrays required: a client must
	// never meet null where it expects a list.
	result.Dependencies = orEmpty(result.Dependencies)
	result.Warnings = orEmpty(result.Warnings)
	for i := range result.Dependencies {
		d := &result.Dependencies[i]
		d.Cves = orEmpty(d.Cves)
		d.Candidates = orEmpty(d.Candidates)
		for j := range d.Candidates {
			d.Candidates[j].Cves = orEmpty(d.Candidates[j].Cves)
			d.Candidates[j].Signals = orEmpty(d.Candidates[j].Signals)
		}
	}
	return result, true
}

// decodePipResult unmarshals raw (a pip analysis' pip-result.json, or nil
// before one exists) into the contract's PipAnalysisResult. Field names
// match internal/jobs.PipResult's JSON tags.
func decodePipResult(raw json.RawMessage) (PipAnalysisResult, bool) {
	if len(raw) == 0 {
		return PipAnalysisResult{}, false
	}
	var result PipAnalysisResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return PipAnalysisResult{}, false
	}
	// The contract marks these lists required, so a client never meets null
	// where it expects a list.
	result.Files = orEmpty(result.Files)
	result.Packages = orEmpty(result.Packages)
	result.Blocking = orEmpty(result.Blocking)
	result.Warnings = orEmpty(result.Warnings)
	for i := range result.Packages {
		p := &result.Packages[i]
		p.Files = orEmpty(p.Files)
		p.Cves = orEmpty(p.Cves)
		for j := range p.Cves {
			p.Cves[j].FixedVersions = orEmpty(p.Cves[j].FixedVersions)
		}
	}
	return result, true
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func targetToAPI(t store.Target) Target {
	return Target{Os: t.OS, Cpu: t.CPU, Libc: t.Libc, Node: t.Node, PnpmVer: t.PnpmVer}
}

func pipTargetToAPI(t store.PipTarget) PipTarget {
	return PipTarget{Python: t.Python, Os: t.OS, Cpu: t.CPU, Glibc: t.Glibc, UvVer: t.UvVer}
}

func pipTargetFromAPI(t PipTarget) store.PipTarget {
	return store.PipTarget{Python: t.Python, OS: t.Os, CPU: t.Cpu, Glibc: t.Glibc, UvVer: t.UvVer}
}

// projectTargets returns the target a project's ecosystem uses and nil for
// the other, so a response never carries an empty target of the wrong kind.
func projectTargets(p store.Project) (*Target, *PipTarget) {
	if p.Ecosystem == store.Pip {
		t := pipTargetToAPI(p.PipTarget)
		return nil, &t
	}
	t := targetToAPI(p.Target)
	return &t, nil
}

func targetFromAPI(t Target) store.Target {
	return store.Target{OS: t.Os, CPU: t.Cpu, Libc: t.Libc, Node: t.Node, PnpmVer: t.PnpmVer}
}

// settingsToAPI converts settings for a response.
func settingsToAPI(s store.Settings) Settings {
	return Settings{
		Target:              targetToAPI(s.Target),
		MinReleaseAgeDays:   s.MinReleaseAgeDays,
		ResolveParallelism:  s.ResolveParallelism,
		DownloadParallelism: s.DownloadParallelism,
	}
}

// analysisToAPI converts a store.AnalysisInfo for a response. A result
// that fails to decode is dropped rather than failing the whole response:
// the state and identity are still worth returning.
func analysisToAPI(info store.AnalysisInfo) Analysis {
	a := Analysis{Id: info.ID, ProjectId: info.ProjectID, State: State(info.State), CreatedAt: info.CreatedAt}
	if result, ok := decodeAnalysisResult(info.Result); ok {
		a.Result = &result
	}
	if result, ok := decodePipResult(info.PipResult); ok {
		a.PipResult = &result
	}
	if info.TrivyVersion != "" {
		a.TrivyVersion = &info.TrivyVersion
	}
	if !info.TrivyDBDate.IsZero() {
		a.TrivyDbDate = &info.TrivyDBDate
	}
	if info.PnpmVersion != "" {
		a.PnpmVersion = &info.PnpmVersion
	}
	if info.UvVersion != "" {
		a.UvVersion = &info.UvVersion
	}
	if info.Failure != nil {
		a.Failure = &Failure{Step: info.Failure.Step, Message: info.Failure.Message}
	}
	return a
}

func exportToAPI(info store.ExportInfo) Export {
	e := Export{
		Id: info.ID, ProjectId: info.ProjectID, AnalysisId: info.AnalysisID,
		State: State(info.State), CreatedAt: info.CreatedAt,
	}
	if info.Files != nil {
		files := info.Files
		e.Files = &files
	}
	if info.Failure != nil {
		e.Failure = &Failure{Step: info.Failure.Step, Message: info.Failure.Message}
	}
	return e
}

func projectToAPI(p store.Project, analyses []store.AnalysisInfo, exports []store.ExportInfo) Project {
	out := Project{Id: p.ID, Name: p.Name, Ecosystem: Ecosystem(p.Ecosystem)}
	out.Target, out.PipTarget = projectTargets(p)
	if p.ManifestSha256 != "" {
		out.ManifestSha256 = &p.ManifestSha256
	}
	if len(analyses) > 0 {
		list := make([]Analysis, len(analyses))
		for i, a := range analyses {
			list[i] = analysisToAPI(a)
		}
		out.Analyses = &list
	}
	if len(exports) > 0 {
		list := make([]Export, len(exports))
		for i, e := range exports {
			list[i] = exportToAPI(e)
		}
		out.Exports = &list
	}
	return out
}
