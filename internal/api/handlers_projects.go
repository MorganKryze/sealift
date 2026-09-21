package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
)

// liveAnalysisOrExport builds a synthetic Analysis or Export from
// Service's live tracking of projectID, if any. A queued or running job
// has no committed directory yet, so neither ListProjects nor GetProject
// can see it by reading the store alone.
func (h *Handlers) liveAnalysisOrExport(projectID string) (analysis *Analysis, export *Export) {
	id, kind, state, ok := h.Service.LiveForProject(projectID)
	if !ok {
		return nil, nil
	}
	createdAt, _ := time.Parse(idLayout, id)
	switch kind {
	case "analysis":
		a := Analysis{Id: id, ProjectId: projectID, State: State(state), CreatedAt: createdAt}
		return &a, nil
	case "export":
		e := Export{Id: id, ProjectId: projectID, State: State(state), CreatedAt: createdAt}
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
		summary := ProjectSummary{Id: p.ID, Name: p.Name, Target: targetToAPI(p.Target)}
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

// CreateProject reads the uploaded package.json from the multipart body,
// validates it, creates the project directory and queues its first
// analysis. An invalid manifest gets a 400 listing every offending entry
// instead of stopping at the first one.
func (h *Handlers) CreateProject(_ context.Context, req CreateProjectRequestObject) (CreateProjectResponseObject, error) {
	name, manifest, err := readCreateProjectParts(req.Body)
	if err != nil {
		return CreateProjectdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "create project", err)), nil
	}
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

// readCreateProjectParts reads the "name" and "manifest" fields of a
// multipart body, capping each at manifestSizeLimit.
func readCreateProjectParts(body *multipart.Reader) (name string, manifest []byte, err error) {
	for {
		part, perr := body.NextPart()
		if errors.Is(perr, io.EOF) {
			return name, manifest, nil
		}
		if perr != nil {
			return "", nil, perr
		}
		data, rerr := io.ReadAll(io.LimitReader(part, manifestSizeLimit))
		_ = part.Close()
		if rerr != nil {
			return "", nil, rerr
		}
		switch part.FormName() {
		case "name":
			name = strings.TrimSpace(string(data))
		case "manifest":
			manifest = data
		}
	}
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
