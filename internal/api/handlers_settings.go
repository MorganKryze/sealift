package api

import "context"

// GetSettings returns settings.
func (h *Handlers) GetSettings(_ context.Context, _ GetSettingsRequestObject) (GetSettingsResponseObject, error) {
	return GetSettings200JSONResponse(settingsToAPI(h.Store.Settings())), nil
}
