package service

import "context"

// GetMe names the user the checked token stands for.
func (h *Handlers) GetMe(ctx context.Context, _ GetMeRequestObject) (GetMeResponseObject, error) {
	return GetMe200JSONResponse{User: userFrom(ctx), MinioConfigured: h.objects != nil}, nil
}
