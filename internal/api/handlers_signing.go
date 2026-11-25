package api

import (
	"context"
	"net/http"

	"github.com/MorganKryze/sealift/internal/store"
)

// GetSigningKey returns the public half of the signing key. A key file that
// does not read answers 500 with the store's cause, which names the file and
// never the key.
func (h *Handlers) GetSigningKey(_ context.Context, _ GetSigningKeyRequestObject) (GetSigningKeyResponseObject, error) {
	key := h.Store.SigningKey()
	if err := key.Err(); err != nil {
		return GetSigningKeydefaultApplicationProblemPlusJSONResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       NewProblem(http.StatusInternalServerError, "read the signing key", err.Error()),
		}, nil
	}
	return GetSigningKey200JSONResponse(signingKeyToAPI(key)), nil
}

func signingKeyToAPI(key store.SigningKey) SigningKey {
	return SigningKey{PublicKeyPem: key.PublicPEM, PublicKeySha256: key.PublicKeySHA256}
}
