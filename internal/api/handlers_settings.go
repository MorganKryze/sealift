package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/MorganKryze/sealift/internal/store"
)

// GetSettings returns settings, with signatureKey masked.
func (h *Handlers) GetSettings(_ context.Context, _ GetSettingsRequestObject) (GetSettingsResponseObject, error) {
	return GetSettings200JSONResponse(settingsToAPI(h.Store.Settings())), nil
}

// UpdateSettings updates settings. A signatureKey equal to the mask
// GetSettings returns is read as "keep the current value", so a client
// that only changed another field never has to know the real key to send
// a valid update.
func (h *Handlers) UpdateSettings(_ context.Context, req UpdateSettingsRequestObject) (UpdateSettingsResponseObject, error) {
	if req.Body == nil {
		return UpdateSettingsdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "update settings", errors.New("a settings body is required"))), nil
	}
	body := req.Body
	current := h.Store.Settings()

	key := body.SignatureKey
	if key == maskedSignatureKey {
		key = current.SignatureKey
	}
	next := store.Settings{
		Target:              targetFromAPI(body.Target),
		SignatureKey:        key,
		MinReleaseAgeDays:   body.MinReleaseAgeDays,
		ResolveParallelism:  body.ResolveParallelism,
		DownloadParallelism: body.DownloadParallelism,
	}
	if err := h.Store.SaveSettings(next); err != nil {
		return UpdateSettingsdefaultApplicationProblemPlusJSONResponse(autoProblem("update settings", err)), nil
	}
	return UpdateSettings200JSONResponse(settingsToAPI(next)), nil
}
