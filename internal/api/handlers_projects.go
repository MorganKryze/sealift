package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/pip"
)

// liveAnalysisOrExport builds a synthetic Analysis or Export from
// Service's live tracking of projectID, if any. A queued or running job
// has no committed directory yet, so neither ListProjects nor GetProject
// can see it by reading the store alone.
func (h *Handlers) liveAnalysisOrExport(projectID string) (analysis *Analysis, export *Export) {
	id, kind, state, analysisID, ok := h.Service.LiveForProject(projectID)
	if !ok {
		return nil, nil
	}
	createdAt, _ := store.JobCreatedAt(id)
	switch kind {
	case "analysis":
		a := Analysis{Id: id, ProjectId: projectID, State: State(state), CreatedAt: createdAt}
		return &a, nil
	case "export":
		e := Export{Id: id, ProjectId: projectID, AnalysisId: analysisID, State: State(state), CreatedAt: createdAt}
		return nil, &e
	default:
		return nil, nil
	}
}

// ListProjects lists every project with its last analysis and export, or,
// with manifestSha256 set, only the projects created from that exact
// manifest, newest first. A live job in progress takes precedence over the
// store's own last entry, which cannot see it yet. A store error reading
// one project's history is logged and skipped rather than failing the
// whole listing: a transient I/O error on one project must not look
// identical to "never analyzed".
func (h *Handlers) ListProjects(_ context.Context, req ListProjectsRequestObject) (ListProjectsResponseObject, error) {
	var projects []store.Project
	var err error
	if req.Params.ManifestSha256 != nil && *req.Params.ManifestSha256 != "" {
		projects, err = h.Store.ProjectsByManifestSha256(*req.Params.ManifestSha256)
	} else {
		projects, err = h.Store.Projects()
	}
	if err != nil {
		return ListProjectsdefaultApplicationProblemPlusJSONResponse(autoProblem("list projects", err)), nil
	}

	out := make([]ProjectSummary, len(projects))
	for i, p := range projects {
		summary := ProjectSummary{Id: p.ID, Name: p.Name, Ecosystem: Ecosystem(p.Ecosystem)}
		summary.Target, summary.PipTarget = projectTargets(p)
		liveAnalysis, liveExport := h.liveAnalysisOrExport(p.ID)

		switch {
		case liveAnalysis != nil:
			summary.LastAnalysis = liveAnalysis
		default:
			analyses, err := h.Store.Analyses(p.ID)
			if err != nil {
				slog.Warn("api: list projects: reading analyses", "project", p.ID, "error", err)
			} else if len(analyses) > 0 {
				last := analysisToAPI(analyses[0])
				summary.LastAnalysis = &last
			}
		}

		switch {
		case liveExport != nil:
			summary.LastExport = liveExport
		default:
			exports, err := h.Store.Exports(p.ID)
			if err != nil {
				slog.Warn("api: list projects: reading exports", "project", p.ID, "error", err)
			} else if len(exports) > 0 {
				last := exportToAPI(exports[0])
				summary.LastExport = &last
			}
		}

		out[i] = summary
	}
	return ListProjects200JSONResponse(out), nil
}

// Bounds on a project creation request.
const (
	maxCreateParts = 40
	// maxRequirementsProblems bounds the refusal list of one answer.
	maxRequirementsProblems = 100
	pipTargetLimit          = 4 << 10
	requirementsField       = "requirements"
)

// createParts is what a project creation request holds.
type createParts struct {
	name      string
	ecosystem Ecosystem
	manifest  []byte
	files     []store.RequirementsFile
	pipTarget *store.PipTarget
}

// CreateProject reads the uploaded package.json or requirements files from
// the multipart body and creates the project. An npm project queues its
// first analysis, and an invalid manifest gets a 400 listing every
// offending entry instead of stopping at the first one. A pip project
// queues its first analysis too.
func (h *Handlers) CreateProject(_ context.Context, req CreateProjectRequestObject) (CreateProjectResponseObject, error) {
	parts, err := readCreateProjectParts(req.Body)
	if err != nil {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "create project", err)), nil
	}
	if parts.ecosystem == Pip {
		return h.createPipProject(parts), nil
	}
	name, manifest := parts.name, parts.manifest
	if len(manifest) == 0 {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "create project", errors.New("the manifest field is required"))), nil
	}

	parsed, err := npm.ParseManifest(bytes.NewReader(manifest))
	if err != nil {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "create project", err)), nil
	}
	if problems := parsed.Validate(); len(problems) > 0 {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(manifestProblem(toValidationEntries(problems))), nil
	}
	if name == "" {
		name = parsed.Name
	}

	if ready, missing := h.Tools.Ready(); !ready {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(toolsMissingProblem(missing)), nil
	}

	project, err := h.Store.CreateProject(name, manifest)
	if err != nil {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(autoProblem("create project", err)), nil
	}
	analysisInfo, err := h.Service.QueueAnalysis(project.ID)
	if err != nil {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(autoProblem("queue analysis", err)), nil
	}
	return CreateProject201JSONResponse(projectToAPI(project, []store.AnalysisInfo{analysisInfo}, nil)), nil
}

// createPipProject checks a pip request's name, files and target, then
// stores the project and queues its first analysis.
func (h *Handlers) createPipProject(parts createParts) CreateProjectResponseObject {
	refuse := func(pb problemBody) CreateProjectResponseObject {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(pb)
	}
	if parts.name == "" {
		return refuse(problem(http.StatusBadRequest, "create project", errors.New("the name field is required for a pip project")))
	}
	if len(parts.files) == 0 {
		return refuse(problem(http.StatusBadRequest, "create project", errors.New("at least one requirements file is required")))
	}
	files := make([]pip.File, len(parts.files))
	for i, f := range parts.files {
		files[i] = pip.File{Name: f.Name, Data: f.Data}
	}
	if _, problems := pip.ParseFiles(files); len(problems) > 0 {
		return refuse(requirementsProblem(problems))
	}
	target := store.DefaultPipTarget
	if parts.pipTarget != nil {
		target = *parts.pipTarget
	}
	if err := store.ValidatePipTarget(target); err != nil {
		return refuse(autoProblem("create project", err))
	}
	if ready, missing := h.Tools.Ready(); !ready {
		return refuse(toolsMissingProblem(missing))
	}
	project, err := h.Store.CreatePipProject(parts.name, parts.files, target)
	if err != nil {
		return refuse(autoProblem("create project", err))
	}
	analysisInfo, err := h.Service.QueueAnalysis(project.ID)
	if err != nil {
		return refuse(autoProblem("queue analysis", err))
	}
	return CreateProject201JSONResponse(projectToAPI(project, []store.AnalysisInfo{analysisInfo}, nil))
}

// readCreateProjectParts reads the fields of a multipart creation body. The
// name and manifest keep the manifest size cap. A requirements part above
// pip.MaxFileBytes is refused, never cut: a cut file would drop pins
// without a word.
func readCreateProjectParts(body *multipart.Reader) (createParts, error) {
	out := createParts{ecosystem: Npm}
	for count := 1; ; count++ {
		part, perr := body.NextPart()
		if errors.Is(perr, io.EOF) {
			return out, nil
		}
		if perr != nil {
			return createParts{}, perr
		}
		if count > maxCreateParts {
			_ = part.Close()
			return createParts{}, fmt.Errorf("a request takes at most %d parts", maxCreateParts)
		}
		err := readCreatePart(part, &out)
		_ = part.Close()
		if err != nil {
			return createParts{}, err
		}
	}
}

func readCreatePart(part *multipart.Part, out *createParts) error {
	switch part.FormName() {
	case requirementsField:
		if len(out.files) >= pip.MaxFiles {
			return fmt.Errorf("a project takes at most %d files", pip.MaxFiles)
		}
		if err := store.ValidRequirementsName(part.FileName()); err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(part, pip.MaxFileBytes+1))
		if err != nil {
			return err
		}
		if len(data) > pip.MaxFileBytes {
			return fmt.Errorf("requirements file %q is above the 1 MiB limit", part.FileName())
		}
		out.files = append(out.files, store.RequirementsFile{Name: part.FileName(), Data: data})
	case "pipTarget":
		data, err := io.ReadAll(io.LimitReader(part, pipTargetLimit+1))
		if err != nil {
			return err
		}
		if len(data) > pipTargetLimit {
			return errors.New("the pipTarget field is above the 4 KiB limit")
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var t PipTarget
		if err := dec.Decode(&t); err != nil {
			return fmt.Errorf("the pipTarget field is not a valid target: %w", err)
		}
		target := pipTargetFromAPI(t)
		out.pipTarget = &target
	default:
		data, err := io.ReadAll(io.LimitReader(part, manifestSizeLimit))
		if err != nil {
			return err
		}
		switch part.FormName() {
		case "name":
			out.name = strings.TrimSpace(string(data))
		case "manifest":
			out.manifest = data
		case "ecosystem":
			switch e := Ecosystem(strings.TrimSpace(string(data))); e {
			case "", Npm:
				out.ecosystem = Npm
			case Pip:
				out.ecosystem = Pip
			default:
				return fmt.Errorf("the ecosystem field must be npm or pip, not %q", e)
			}
		}
	}
	return nil
}

// toValidationEntries converts npm.Manifest.Validate's Problem list to the
// shape manifestProblem builds a response from, without this package
// importing npm just for that one type.
func toValidationEntries(problems []npm.Problem) []manifestValidationEntry {
	entries := make([]manifestValidationEntry, len(problems))
	for i, p := range problems {
		entries[i] = manifestValidationEntry{Field: p.Field, Name: p.Name, Value: p.Value, Reason: p.Reason}
	}
	return entries
}

// GetProject returns a project, its target and its full analysis and
// export history. A live job in progress is prepended to the relevant
// history array: it has no committed directory yet, so it is otherwise
// invisible until it ends.
func (h *Handlers) GetProject(_ context.Context, req GetProjectRequestObject) (GetProjectResponseObject, error) {
	project, err := h.Store.Project(req.ProjectId)
	if err != nil {
		return GetProjectdefaultApplicationProblemPlusJSONResponse(autoProblem("get project", err)), nil
	}
	analyses, err := h.Store.Analyses(req.ProjectId)
	if err != nil {
		return GetProjectdefaultApplicationProblemPlusJSONResponse(autoProblem("get project", err)), nil
	}
	exports, err := h.Store.Exports(req.ProjectId)
	if err != nil {
		return GetProjectdefaultApplicationProblemPlusJSONResponse(autoProblem("get project", err)), nil
	}

	resp := projectToAPI(project, analyses, exports)
	liveAnalysis, liveExport := h.liveAnalysisOrExport(req.ProjectId)
	if liveAnalysis != nil {
		list := []Analysis{*liveAnalysis}
		if resp.Analyses != nil {
			list = append(list, *resp.Analyses...)
		}
		resp.Analyses = &list
	}
	if liveExport != nil {
		list := []Export{*liveExport}
		if resp.Exports != nil {
			list = append(list, *resp.Exports...)
		}
		resp.Exports = &list
	}
	return GetProject200JSONResponse(resp), nil
}

// DeleteProject removes a project directory and everything under it.
func (h *Handlers) DeleteProject(_ context.Context, req DeleteProjectRequestObject) (DeleteProjectResponseObject, error) {
	if err := h.Store.DeleteProject(req.ProjectId); err != nil {
		return DeleteProjectdefaultApplicationProblemPlusJSONResponse(autoProblem("delete project", err)), nil
	}
	if h.Ephemeral > 0 {
		// With a job of another project in flight, the store puts the purge
		// off and the next sweep that finds the instance idle runs it.
		if _, err := h.Store.PurgeIfIdle(); err != nil {
			return DeleteProjectdefaultApplicationProblemPlusJSONResponse(problem(http.StatusInternalServerError, "delete project", fmt.Errorf("the project is deleted, the shared caches are not: %w", err))), nil
		}
	}
	return DeleteProject204Response{}, nil
}

// SetProjectTarget changes a project's target platform and toolchain.
func (h *Handlers) SetProjectTarget(_ context.Context, req SetProjectTargetRequestObject) (SetProjectTargetResponseObject, error) {
	if req.Body == nil {
		return SetProjectTargetdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "set target", errors.New("a target body is required"))), nil
	}
	if err := h.Store.SetProjectTarget(req.ProjectId, targetFromAPI(*req.Body)); err != nil {
		return SetProjectTargetdefaultApplicationProblemPlusJSONResponse(autoProblem("set target", err)), nil
	}
	project, err := h.Store.Project(req.ProjectId)
	if err != nil {
		return SetProjectTargetdefaultApplicationProblemPlusJSONResponse(autoProblem("set target", err)), nil
	}
	return SetProjectTarget200JSONResponse(projectToAPI(project, nil, nil)), nil
}

type projectManifestResponse struct {
	body io.ReadCloser
}

func (r projectManifestResponse) VisitGetProjectManifestResponse(w http.ResponseWriter) error {
	defer r.body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := io.Copy(w, r.body)
	return err
}

// GetProjectManifest returns the package.json a project was created from,
// byte for byte, so a session can show what was uploaded even when its
// analysis never produced a result.
func (h *Handlers) GetProjectManifest(_ context.Context, req GetProjectManifestRequestObject) (GetProjectManifestResponseObject, error) {
	f, err := h.Store.ProjectManifest(req.ProjectId)
	if err != nil {
		return GetProjectManifestdefaultApplicationProblemPlusJSONResponse(autoProblem("get project manifest", err)), nil
	}
	return projectManifestResponse{body: f}, nil
}
