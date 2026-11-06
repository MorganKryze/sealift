package service

import (
	"context"
	"errors"

	"github.com/MorganKryze/sealift/internal/importer/s3"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

// remove deletes the archive and then its manifest from the user's bucket. It
// runs only after an attempt that put every package in Nexus. Both objects are
// headed first and each must still carry the ETag the import recorded; if
// either differs or cannot be read, nothing is deleted and the reason says
// which. The archive goes first: a manifest left alone does no harm, an
// archive left without its manifest would be listed as not importable.
//
// The check and the delete are two requests. An object replaced in the few
// milliseconds between them is deleted anyway; MinIO's conditional delete
// would close the gap and is not used until proven on the deployed version.
func (h *Handlers) remove(ctx context.Context, bucket string, imp imports.Import) *imports.Removal {
	ctx, cancel := context.WithTimeout(ctx, minioCallTimeout)
	defer cancel()
	kept := func(reason string) *imports.Removal { return &imports.Removal{Reason: cleanText(reason)} }

	for _, o := range []struct {
		what string
		obj  imports.Object
	}{{"the archive", imp.Archive}, {"the manifest", imp.Manifest}} {
		got, err := h.objects.Head(ctx, bucket, o.obj.Key)
		switch {
		case errors.Is(err, s3.ErrNotFound):
			return kept(o.what + " is no longer in MinIO; nothing was removed")
		case err != nil:
			h.log.Warn("could not check an object before removing it", "id", imp.ID, "error", cleanText(err.Error()))
			return kept("could not check " + o.what + " before removing it; nothing was removed: " + err.Error())
		case got.ETag != o.obj.ETag:
			return kept(o.what + " changed in MinIO after the import read it; nothing was removed")
		}
	}
	if err := h.objects.Delete(ctx, bucket, imp.Archive.Key); err != nil {
		h.log.Warn("could not remove an archive", "id", imp.ID, "error", cleanText(err.Error()))
		return kept("could not remove the archive: " + err.Error())
	}
	if err := h.objects.Delete(ctx, bucket, imp.Manifest.Key); err != nil {
		h.log.Warn("could not remove a manifest", "id", imp.ID, "error", cleanText(err.Error()))
		return &imports.Removal{Removed: true, Reason: cleanText("the archive was removed, but the manifest could not be and stays in the folder: " + err.Error())}
	}
	return &imports.Removal{Removed: true}
}
