package service

import "context"

// GetMe names the user the checked token stands for.
func (h *Handlers) GetMe(ctx context.Context, _ GetMeRequestObject) (GetMeResponseObject, error) {
	user := userFrom(ctx)
	return GetMe200JSONResponse{User: user, MinioConfigured: h.objects != nil, Bucket: bucketOf(user), Folder: Folder}, nil
}
