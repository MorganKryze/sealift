package service

import "context"

// GetMe names the user the checked token stands for.
func (h *Handlers) GetMe(ctx context.Context, _ GetMeRequestObject) (GetMeResponseObject, error) {
	user := userFrom(ctx)
	return GetMe200JSONResponse{User: user, MinioConfigured: h.objects != nil, Bucket: bucketOf(user), Folder: FolderNPM, PublicKeySha256: h.settings.PublicKeySHA256}, nil
}
