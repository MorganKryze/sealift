package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/MorganKryze/sealift/internal/tools"
)

// toolsStateToAPI converts a tools.TrivyState, the installed pnpm versions
// and the current readiness for a response.
func toolsStateToAPI(s tools.TrivyState, pnpmInstalled []string, ready bool, missing []string) ToolsState {
	if pnpmInstalled == nil {
		pnpmInstalled = []string{}
	}
	trivyInstalled := s.Installed
	if trivyInstalled == nil {
		trivyInstalled = []string{}
	}
	if missing == nil {
		missing = []string{}
	}
	state := ToolsState{
		PnpmInstalled:   pnpmInstalled,
		TrivyActive:     s.Active,
		TrivyInstalled:  trivyInstalled,
		TrivyLatest:     s.Latest,
		TrivyLatestAge:  s.LatestAge.String(),
		TrivyDbDate:     s.DBDate,
		LatestSizeBytes: int(s.LatestSizeBytes),
		Ready:           ready,
		Missing:         missing,
	}
	if s.Recommended != "" {
		state.TrivyRecommended = &s.Recommended
	}
	return state
}

// currentToolsState reads the installed and available pnpm and Trivy
// versions, and the current readiness, shared by every tools operation's
// response.
func (h *Handlers) currentToolsState(ctx context.Context) (ToolsState, error) {
	trivyState, err := h.Tools.TrivyState(ctx)
	if err != nil {
		return ToolsState{}, err
	}
	pnpmInstalled, err := h.Tools.InstalledPnpm()
	if err != nil {
		return ToolsState{}, err
	}
	ready, missing := h.Tools.Ready()
	return toolsStateToAPI(trivyState, pnpmInstalled, ready, missing), nil
}

// GetTools returns installed and available tool versions and the
// vulnerability database's date.
func (h *Handlers) GetTools(ctx context.Context, _ GetToolsRequestObject) (GetToolsResponseObject, error) {
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return GetToolsdefaultApplicationProblemPlusJSONResponse(autoProblem("get tools", err)), nil
	}
	return GetTools200JSONResponse(state), nil
}

// ActivateTrivy switches the active Trivy version to an installed one.
func (h *Handlers) ActivateTrivy(ctx context.Context, req ActivateTrivyRequestObject) (ActivateTrivyResponseObject, error) {
	if req.Body == nil {
		return ActivateTrivydefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "activate trivy", errors.New("a version body is required"))), nil
	}
	if err := h.Tools.ActivateTrivy(req.Body.Version); err != nil {
		return ActivateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("activate trivy", err)), nil
	}
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return ActivateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("activate trivy", err)), nil
	}
	return ActivateTrivy200JSONResponse(state), nil
}

// UpdateTrivy installs a new Trivy release, refusing one younger than the
// minimum release age unless the request forces it.
func (h *Handlers) UpdateTrivy(ctx context.Context, req UpdateTrivyRequestObject) (UpdateTrivyResponseObject, error) {
	var version string
	force := false
	if req.Body != nil {
		force = req.Body.Force
		if req.Body.Version != nil {
			version = *req.Body.Version
		}
	}
	if _, err := h.Tools.UpdateTrivy(ctx, version, force); err != nil {
		return UpdateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy", err)), nil
	}
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return UpdateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy", err)), nil
	}
	return UpdateTrivy200JSONResponse(state), nil
}

// UpdateTrivyDB forces a vulnerability database download.
func (h *Handlers) UpdateTrivyDB(ctx context.Context, _ UpdateTrivyDBRequestObject) (UpdateTrivyDBResponseObject, error) {
	if _, err := h.Trivy.UpdateDB(ctx); err != nil {
		return UpdateTrivyDBdefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy db", err)), nil
	}
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return UpdateTrivyDBdefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy db", err)), nil
	}
	return UpdateTrivyDB200JSONResponse(state), nil
}
