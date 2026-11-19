package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/MorganKryze/sealift/internal/store"
)

// GetSettings returns settings.
func (h *Handlers) GetSettings(_ context.Context, _ GetSettingsRequestObject) (GetSettingsResponseObject, error) {
	return GetSettings200JSONResponse(settingsToAPI(h.Store.Settings())), nil
}

// UpdateSettings replaces the settings.
func (h *Handlers) UpdateSettings(_ context.Context, req UpdateSettingsRequestObject) (UpdateSettingsResponseObject, error) {
	if req.Body == nil {
		return UpdateSettingsdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "update settings", errors.New("a settings body is required"))), nil
	}
	body := req.Body
	next := store.Settings{
		Target:              targetFromAPI(body.Target),
		MinReleaseAgeDays:   body.MinReleaseAgeDays,
		ResolveParallelism:  body.ResolveParallelism,
		DownloadParallelism: body.DownloadParallelism,
	}
	if err := h.Store.SaveSettings(next); err != nil {
		return UpdateSettingsdefaultApplicationProblemPlusJSONResponse(autoProblem("update settings", err)), nil
	}
	return UpdateSettings200JSONResponse(settingsToAPI(next)), nil
}
