package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/MorganKryze/sealift/internal/tools"
)

// toolsStateToAPI converts a tools.TrivyState, the installed pnpm and uv
// versions and the current readiness for a response.
func toolsStateToAPI(s tools.TrivyState, pnpmInstalled, uvInstalled []string, ready bool, missing []string) ToolsState {
	if pnpmInstalled == nil {
		pnpmInstalled = []string{}
	}
	if uvInstalled == nil {
		uvInstalled = []string{}
	}
	trivyInstalled := s.Installed
	if trivyInstalled == nil {
		trivyInstalled = []string{}
	}
	if missing == nil {
		missing = []string{}
	}
	// TrivyLatest carries the pin: nothing asks GitHub for a newer release,
	// so no size, age or recommendation goes with it.
	return ToolsState{
		PnpmInstalled:  pnpmInstalled,
		UvInstalled:    &uvInstalled,
		TrivyActive:    s.Active,
		TrivyInstalled: trivyInstalled,
		TrivyLatest:    s.Pinned,
		TrivyDbDate:    s.DBDate,
		Ready:          ready,
		Missing:        missing,
	}
}

// currentToolsState reads the installed pnpm, uv and Trivy versions, the
// pinned Trivy and the current readiness, shared by every tools
// operation's response. It asks nothing of GitHub or the package index.
func (h *Handlers) currentToolsState(ctx context.Context) (ToolsState, error) {
	trivyState, err := h.Tools.TrivyState(ctx)
	if err != nil {
		return ToolsState{}, err
	}
	pnpmInstalled, err := h.Tools.InstalledPnpm()
	if err != nil {
		return ToolsState{}, err
	}
	uvInstalled, err := h.Tools.InstalledUv()
	if err != nil {
		return ToolsState{}, err
	}
	ready, missing := h.Tools.Ready()
	return toolsStateToAPI(trivyState, pnpmInstalled, uvInstalled, ready, missing), nil
}

// GetTools returns the installed and pinned tool versions and the
// vulnerability database's date, from the data volume alone.
func (h *Handlers) GetTools(ctx context.Context, _ GetToolsRequestObject) (GetToolsResponseObject, error) {
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return GetToolsdefaultApplicationProblemPlusJSONResponse(autoProblem("get tools", err)), nil
	}
	return GetTools200JSONResponse(state), nil
}

// pinnedOnly is the refusal of a request for another Trivy than the pin.
func (h *Handlers) pinnedOnly(ctx context.Context, title string) problemBody {
	state, err := h.Tools.TrivyState(ctx)
	if err != nil {
		return autoProblem(title, err)
	}
	return problem(http.StatusConflict, title, fmt.Errorf("sealift runs only Trivy %s, the release pinned in this build", state.Pinned))
}

// ActivateTrivy refuses every switch: the pinned Trivy is the only one
// sealift activates.
func (h *Handlers) ActivateTrivy(ctx context.Context, _ ActivateTrivyRequestObject) (ActivateTrivyResponseObject, error) {
	return ActivateTrivydefaultApplicationProblemPlusJSONResponse(h.pinnedOnly(ctx, "activate trivy")), nil
}

// UpdateTrivy installs and activates the pinned Trivy release, and refuses
// a request that names another version.
func (h *Handlers) UpdateTrivy(ctx context.Context, req UpdateTrivyRequestObject) (UpdateTrivyResponseObject, error) {
	if req.Body != nil && req.Body.Version != nil {
		state, err := h.Tools.TrivyState(ctx)
		if err != nil {
			return UpdateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy", err)), nil
		}
		if strings.TrimPrefix(*req.Body.Version, "v") != state.Pinned {
			return UpdateTrivydefaultApplicationProblemPlusJSONResponse(h.pinnedOnly(ctx, "update trivy")), nil
		}
	}
	if _, err := h.Tools.EnsureTrivy(ctx); err != nil {
		return UpdateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy", err)), nil
	}
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return UpdateTrivydefaultApplicationProblemPlusJSONResponse(autoProblem("update trivy", err)), nil
	}
	return UpdateTrivy200JSONResponse(state), nil
}

// InstallUv installs a uv release from the package index, refusing one
// younger than the minimum release age unless the request forces it.
func (h *Handlers) InstallUv(ctx context.Context, req InstallUvRequestObject) (InstallUvResponseObject, error) {
	if req.Body == nil {
		return InstallUvdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "install uv", errors.New("a version body is required"))), nil
	}
	force := req.Body.Force != nil && *req.Body.Force
	if _, err := h.Tools.EnsureUv(ctx, req.Body.Version, force); err != nil {
		return InstallUvdefaultApplicationProblemPlusJSONResponse(autoProblem("install uv", err)), nil
	}
	state, err := h.currentToolsState(ctx)
	if err != nil {
		return InstallUvdefaultApplicationProblemPlusJSONResponse(autoProblem("install uv", err)), nil
	}
	return InstallUv200JSONResponse(state), nil
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
