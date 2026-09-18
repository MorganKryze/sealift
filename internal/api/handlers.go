package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
)

// maskedSignatureKey is what GetSettings returns for a non-empty
// signatureKey, and what UpdateSettings reads as "keep the current value":
// the setting is never echoed back in the clear once it has been set.
const maskedSignatureKey = "********"

// manifestSizeLimit bounds an uploaded package.json: real ones run a few
// kilobytes at most, so this only guards against a client sending far more
// than a manifest ever needs to be.
const manifestSizeLimit = 1 << 20

// Handlers implements StrictServerInterface. It holds no state of its own:
// every operation reads or writes through Store, Service or Tools.
type Handlers struct {
	*EventsHandler
	Store   *store.Store
	Service *jobs.Service
	Tools   *tools.Manager
	Trivy   runner.Trivy
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
// which callers build their own Problem for) maps to.
func statusFor(err error) int {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, jobs.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
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
// match internal/jobs.Result's JSON tags exactly (CONTRACTS.md's shared
// types), so this never needs that package's own Go type.
func decodeAnalysisResult(raw json.RawMessage) (AnalysisResult, bool) {
	if len(raw) == 0 {
		return AnalysisResult{}, false
	}
	var result AnalysisResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return AnalysisResult{}, false
	}
	return result, true
}

func targetToAPI(t store.Target) Target {
	return Target{Os: t.OS, Cpu: t.CPU, Libc: t.Libc, Node: t.Node, PnpmVer: t.PnpmVer}
}

func targetFromAPI(t Target) store.Target {
	return store.Target{OS: t.Os, CPU: t.Cpu, Libc: t.Libc, Node: t.Node, PnpmVer: t.PnpmVer}
}

// settingsToAPI converts settings for a response, masking signatureKey.
func settingsToAPI(s store.Settings) Settings {
	key := ""
	if s.SignatureKey != "" {
		key = maskedSignatureKey
	}
	return Settings{
		Target:              targetToAPI(s.Target),
		SignatureKey:        key,
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
	return e
}

func projectToAPI(p store.Project, analyses []store.AnalysisInfo, exports []store.ExportInfo) Project {
	out := Project{Id: p.ID, Name: p.Name, Target: targetToAPI(p.Target)}
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
