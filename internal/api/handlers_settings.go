package api

import (
	"context"
	"net/http"
)

// GetSettings returns settings.
func (h *Handlers) GetSettings(_ context.Context, _ GetSettingsRequestObject) (GetSettingsResponseObject, error) {
	return GetSettings200JSONResponse(settingsToAPI(h.Store.Settings())), nil
}

// UpdateSettings refuses every change: the deployment's policy file sets
// the settings at start.
func (h *Handlers) UpdateSettings(_ context.Context, _ UpdateSettingsRequestObject) (UpdateSettingsResponseObject, error) {
	refused := NewProblem(http.StatusConflict, "update settings", "Settings are set at deploy, in the policy file")
	return UpdateSettingsdefaultApplicationProblemPlusJSONResponse(problemBody{Body: refused, StatusCode: http.StatusConflict}), nil
}
