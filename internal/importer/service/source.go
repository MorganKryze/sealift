package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/s3"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

// changed is why an attempt refuses an object whose ETag moved since the import
// was created. what names the object: "the archive" or "the manifest".
func changed(what string) error {
	return &archive.Refusal{Reason: what + " changed in MinIO; start a new import"}
}

// minioCallTimeout is how long a list or a head may take: 30 seconds.
const minioCallTimeout = 30 * time.Second

// idleReadTimeout is how long a read of an object may wait for its next bytes: 60 seconds.
// One global queue runs one import at a time, so a stalled MinIO would hold every user.
var idleReadTimeout = 60 * time.Second

// minioSource reads an import's manifest and archive from the user's bucket,
// each once and each on condition that its ETag is still the recorded one. A
// failure of the read marks importer.ErrSource, so the attempt ends
// incomplete; an object that changed is a refusal that says it changed in
// MinIO and asks for a new import.
func minioSource(o Objects, bucket string, imp imports.Import) importer.Source {
	return importer.Source{
		Name: cleanText(path.Base(imp.Archive.Key)),
		Manifest: func(ctx context.Context) (io.ReadCloser, error) {
			return openObject(ctx, o, bucket, imp.Manifest, "the manifest")
		},
		Archive: func(ctx context.Context) (io.ReadCloser, error) {
			return openObject(ctx, o, bucket, imp.Archive, "the archive")
		},
	}
}

// sourceError marks a failure of MinIO. The cause stays in the chain so an
// interrupt is still recognised as one.
func sourceError(what string, err error) error {
	switch {
	case errors.Is(err, s3.ErrChanged):
		return changed(what)
	case errors.Is(err, s3.ErrNotFound):
		return fmt.Errorf("%w: %s is no longer in MinIO", importer.ErrSource, what)
	}
	return fmt.Errorf("%w: %w", importer.ErrSource, err)
}

func openObject(ctx context.Context, o Objects, bucket string, want imports.Object, what string) (io.ReadCloser, error) {
	readCtx, cancel := context.WithCancel(ctx)
	body, got, err := o.Get(readCtx, bucket, want.Key, want.ETag)
	if err != nil {
		cancel()
		return nil, sourceError(what, err)
	}
	// A 200 for another version than the one asked for is a changed object.
	if got.ETag != want.ETag {
		_ = body.Close()
		cancel()
		return nil, changed(what)
	}
	b := &objectBody{ctx: ctx, cancel: cancel, rc: body, size: got.Size, what: what}
	b.timer = time.AfterFunc(idleReadTimeout, cancel)
	b.timer.Stop()
	return b, nil
}

// objectBody reads an object under an idle deadline and checks that it ends
// where MinIO said it would.
type objectBody struct {
	ctx    context.Context // the attempt's; its end is an interrupt, not a MinIO failure
	cancel context.CancelFunc
	timer  *time.Timer
	rc     io.ReadCloser
	size   int64
	read   int64
	what   string
}

func (b *objectBody) Read(p []byte) (int, error) {
	// The wait counts only while MinIO is being waited for, never the time the caller spends on the bytes.
	b.timer.Reset(idleReadTimeout)
	n, err := b.rc.Read(p)
	b.timer.Stop()
	b.read += int64(n)
	switch {
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF):
		if b.read != b.size {
			return n, fmt.Errorf("%w: %s was cut short after %d of %d bytes", importer.ErrSource, b.what, b.read, b.size)
		}
		return n, io.EOF
	case b.ctx.Err() != nil:
		return n, fmt.Errorf("%w: %w", importer.ErrSource, b.ctx.Err())
	case errors.Is(err, context.Canceled):
		return n, fmt.Errorf("%w: no data from MinIO for %s while reading %s", importer.ErrSource, idleReadTimeout, b.what)
	}
	return n, fmt.Errorf("%w: reading %s: %w", importer.ErrSource, b.what, err)
}

func (b *objectBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel()
	return err
}
