package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/s3"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

// maxETagBytes caps an ETag MinIO sends before it is stored: 200 bytes.
const maxETagBytes = 200

var hexSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// validETag reports whether MinIO's ETag is a short run of printable ASCII.
func validETag(etag string) bool {
	if etag == "" || len(etag) > maxETagBytes {
		return false
	}
	for i := 0; i < len(etag); i++ {
		if etag[i] < 0x20 || etag[i] > 0x7e {
			return false
		}
	}
	return true
}

func newProblem(status int, title, detail string) Problem {
	return Problem{Type: ptr("about:blank"), Title: title, Status: status, Detail: ptr(detail)}
}

// problem carries an answer until a handler turns it into its own response type.
type problem struct {
	status int
	body   Problem
}

func notFound() problem {
	return problem{status: 404, body: newProblem(404, "Not found", "no such archive in your folder")}
}

func conflict(detail string, id *string) StartImport409ApplicationProblemPlusJSONResponse {
	return StartImport409ApplicationProblemPlusJSONResponse(ImportConflict{
		Type: ptr("about:blank"), Title: "Cannot start this import", Status: 409, Detail: &detail, ImportId: id,
	})
}

// minioProblem is the 502 answer for a MinIO failure; MinIO's text is cleaned and cut.
func (h *Handlers) minioProblem(what string, err error) problem {
	h.log.Warn("MinIO failed", "while", what, "error", cleanText(err.Error()))
	return problem{status: 502, body: newProblem(502, "MinIO failed", cleanText("MinIO could not "+what+": "+err.Error()))}
}

// StartImport queues an import of one archive in the user's own folder.
func (h *Handlers) StartImport(ctx context.Context, req StartImportRequestObject) (StartImportResponseObject, error) {
	user := userFrom(ctx)
	fail := func(p problem) (StartImportResponseObject, error) {
		return StartImportdefaultApplicationProblemPlusJSONResponse{StatusCode: p.status, Body: p.body}, nil
	}
	if req.Body == nil {
		return fail(problem{status: 400, body: newProblem(400, "Bad request", "the request needs an archive key")})
	}
	key := req.Body.Archive
	// The key is checked before any MinIO request: anything outside the user's
	// folder answers 404 as if the archive did not exist.
	if err := ArchiveKey(key); err != nil {
		h.log.Info("refused a start", "user", user, "check", "key")
		return fail(notFound())
	}
	expected := ""
	if s := req.Body.ExpectedSha256; s != nil && *s != "" {
		if !hexSHA256.MatchString(*s) {
			return fail(problem{status: 400, body: newProblem(400, "Bad request", "expectedSha256 must be 64 hex digits")})
		}
		expected = strings.ToLower(*s)
	}
	if h.objects == nil {
		return conflict("MinIO is not configured: the settings file has no minio section", nil), nil
	}

	bucket := bucketOf(user)
	archive, manifest, refusal := h.checkArchive(ctx, bucket, key)
	if refusal != nil {
		if refusal.status == 409 {
			return conflict(*refusal.body.Detail, nil), nil
		}
		return fail(*refusal)
	}

	h.startMu.Lock()
	defer h.startMu.Unlock()
	existing, err := h.store.List(user)
	if err != nil {
		return nil, err
	}
	for _, imp := range existing { // newest first
		// A replaced manifest makes another import: a refusal for it must not block the objects now in MinIO.
		if imp.Archive.Key == archive.Key && imp.Archive.ETag == archive.ETag && imp.Manifest.ETag == manifest.ETag {
			if imp.Outcome() != importer.OutcomeComplete {
				return conflict("this archive already has an import that has not completed; read it or retry it", &imp.ID), nil
			}
			break
		}
	}
	imp, err := h.store.Create(user, archive, manifest, expected)
	if err != nil {
		return nil, err
	}
	h.submit(user, imp.ID)
	out, err := toImport(imp)
	if err != nil {
		return nil, err
	}
	return StartImport202JSONResponse(out), nil
}

// checkArchive confirms that the key is an importable archive in the user's
// folder and returns it and its manifest as MinIO describes them now.
func (h *Handlers) checkArchive(ctx context.Context, bucket, key string) (archive, manifest imports.Object, refusal *problem) {
	fail := func(p problem) (imports.Object, imports.Object, *problem) {
		return imports.Object{}, imports.Object{}, &p
	}
	ctx, cancel := context.WithTimeout(ctx, minioCallTimeout)
	defer cancel()
	folder := path.Dir(key) + "/"
	listing, err := h.objects.List(ctx, bucket, folder, MaxListed)
	switch {
	case s3.IsNoBucket(err):
		return fail(notFound())
	case err != nil:
		return fail(h.minioProblem("list the archives", err))
	}
	var found *Archive
	for _, a := range pair(listing.Objects) {
		if a.Key == key {
			found = &a
			break
		}
	}
	switch {
	case found == nil:
		return fail(notFound())
	case !found.Importable:
		return fail(problem{status: 409, body: newProblem(409, "Cannot start this import", *found.Reason)})
	}
	manifestKey := folder + manifestName
	var objs [2]imports.Object
	for i, k := range []string{key, manifestKey} {
		o, err := h.objects.Head(ctx, bucket, k)
		switch {
		case errors.Is(err, s3.ErrNotFound):
			return fail(notFound())
		case err != nil:
			return fail(h.minioProblem("read the archive's description", err))
		case !validETag(o.ETag):
			return fail(h.minioProblem("describe the archive", errors.New("it sent an ETag the service cannot use")))
		}
		objs[i] = imports.Object{Key: k, ETag: o.ETag, Size: o.Size}
	}
	return objs[0], objs[1], nil
}

// ListImports lists the user's imports, newest first.
func (h *Handlers) ListImports(ctx context.Context, _ ListImportsRequestObject) (ListImportsResponseObject, error) {
	imps, err := h.store.List(userFrom(ctx))
	if err != nil {
		return nil, err
	}
	out := ImportList{Imports: make([]Import, 0, len(imps))}
	for _, imp := range imps {
		api, err := toImport(imp)
		if err != nil {
			return nil, err
		}
		out.Imports = append(out.Imports, api)
	}
	return ListImports200JSONResponse(out), nil
}

// GetImport reads one of the user's imports. Another user's id is a missing one.
func (h *Handlers) GetImport(ctx context.Context, req GetImportRequestObject) (GetImportResponseObject, error) {
	// The store checks the id's shape before it joins any path.
	imp, err := h.store.Get(userFrom(ctx), req.ImportId)
	if errors.Is(err, imports.ErrNotFound) {
		return GetImportdefaultApplicationProblemPlusJSONResponse{StatusCode: 404, Body: newProblem(404, "Not found", "no such import")}, nil
	}
	if err != nil {
		return nil, err
	}
	out, err := toImport(imp)
	if err != nil {
		return nil, err
	}
	return GetImport200JSONResponse(out), nil
}

// toImport turns a stored import into the contract's shape. The record and
// the contract share their field names, so the record's JSON is the contract's.
func toImport(imp imports.Import) (Import, error) {
	b, err := json.Marshal(imp)
	if err != nil {
		return Import{}, err
	}
	var out Import
	if err := json.Unmarshal(b, &out); err != nil {
		return Import{}, err
	}
	out.Outcome, out.ArchiveRemoved = imp.Outcome(), imp.ArchiveRemoved()
	return out, nil
}

// RunAttempt runs one attempt of imp: it reads both objects from the user's
// bucket and imports them as `sealift import` does. It keeps its files in a
// directory of its own below dir and removes it. It removes nothing from MinIO yet.
func (h *Handlers) RunAttempt(ctx context.Context, imp imports.Import, dir string, p importer.Progress) (importer.Report, *imports.Removal) {
	work, err := os.MkdirTemp(dir, "run-")
	if err != nil {
		h.log.Error("could not make a working directory", "id", imp.ID, "error", cleanText(err.Error()))
		return importer.Report{
			Outcome: importer.OutcomeRefused, Reason: "could not check the archive: no working directory",
			Unencrypted: len(h.links) > 0, ImportVersion: h.importVersion,
			Archive:  importer.ArchiveInfo{File: cleanText(path.Base(imp.Archive.Key))},
			Nexus:    importer.NexusInfo{URL: h.settings.NexusURL.String(), Repository: h.settings.Repository},
			Packages: []importer.Result{},
		}, nil
	}
	defer os.RemoveAll(work)
	rep := importer.RunAttempt(ctx, importer.Attempt{
		Settings:       h.settings,
		Source:         minioSource(h.objects, bucketOf(imp.User), imp),
		ExpectedSHA256: imp.ExpectedSHA256,
		ImportVersion:  h.importVersion,
		Dir:            work,
		Unencrypted:    len(h.links) > 0,
		Progress:       p,
	}, h.newPublisher)
	return rep, nil
}
