package importer

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"os"

	"github.com/MorganKryze/sealift/pip"
)

// PublishWheels handles each wheel once, in order, as PublishEach does for
// tarballs: a mismatch, then read before, upload, read back. It takes
// PublishEach's arguments, but a Nexus copy is hashed as it arrives and never
// written, so the directory goes unused. ended may be nil.
func PublishWheels(ctx context.Context, p Publisher, wheels []Package, _ string, ended func(int, Result)) []Result {
	return publishEach(ctx, p, wheels, ended, func(w Package) Result { return publishWheel(ctx, p, w) })
}

func publishWheel(ctx context.Context, p Publisher, w Package) Result {
	f, err := os.Open(w.Path)
	if err != nil {
		return failed(w, KindLocal, "cannot open the checked file: "+err.Error())
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return failed(w, KindLocal, "cannot read the checked file: "+err.Error())
	}
	limit := 2*info.Size() + maxCopySlack

	if reason := wheelMismatch(f, info.Size(), w); reason != "" {
		return failed(w, KindMismatch, reason)
	}

	project := pip.Normalize(w.Name)
	remote, found, err := fileDigest(ctx, p, project, w.File, limit)
	if err != nil {
		return failedOr(ctx, w, KindNexus, err.Error())
	}
	if found {
		if bytes.Equal(remote, w.SHA512) {
			return Result{Name: w.Name, Version: w.Version, File: w.File, State: Present}
		}
		return failed(w, KindConflict, "nexus holds this file with other bytes: "+digests(w.SHA512, remote))
	}

	// The file is hashed again here: nothing reaches Nexus that the checks
	// did not hash, even if the file changed since.
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return failed(w, KindLocal, "cannot read the checked file: "+err.Error())
	}
	if now := h.Sum(nil); !bytes.Equal(now, w.SHA512) {
		return failed(w, KindLocal, "the file changed after the checks: "+digests(w.SHA512, now))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failed(w, KindLocal, "cannot read the checked file: "+err.Error())
	}
	if err := p.Upload(ctx, w.File, f); err != nil {
		return failedOr(ctx, w, KindNexus, "upload failed: "+err.Error())
	}

	remote, found, err = fileDigest(ctx, p, project, w.File, limit)
	if err != nil {
		return failedOr(ctx, w, KindNexus, "read back failed: "+err.Error())
	}
	if !found {
		return failed(w, KindNexus, "nexus accepted the upload but does not list the file")
	}
	if !bytes.Equal(remote, w.SHA512) {
		return failed(w, KindNexus, "nexus serves other bytes after the upload: "+digests(w.SHA512, remote))
	}
	return Result{Name: w.Name, Version: w.Version, File: w.File, State: Published}
}

// fileDigest returns the sha512 of the file Nexus lists for project, and
// found false when it lists none.
func fileDigest(ctx context.Context, p Publisher, project, file string, limit int64) ([]byte, bool, error) {
	h := sha512.New()
	found, err := p.FetchFile(ctx, project, file, h, limit)
	if err != nil || !found {
		return nil, false, err
	}
	return h.Sum(nil), true, nil
}

// wheelMismatch returns why the wheel in f cannot be the package of its
// manifest entry, or "" when it can: its METADATA and its file name must
// both name the entry's project and version.
func wheelMismatch(f io.ReaderAt, size int64, w Package) string {
	info, err := pip.InspectWheel(f, size, pip.WheelLimits{})
	if err != nil {
		return clean("the wheel is not a valid package: " + err.Error())
	}
	if pip.Normalize(info.Name) != pip.Normalize(w.Name) || !pip.SameVersion(info.Version, w.Version) {
		return fmt.Sprintf("the wheel's METADATA says %s %s, the manifest says %s %s", shown(info.Name), shown(info.Version), w.Name, w.Version)
	}
	name, err := pip.ParseWheelName(w.File)
	if err != nil {
		return clean("the wheel's file name is not a wheel name: " + err.Error())
	}
	if pip.Normalize(name.Name) != pip.Normalize(w.Name) || !pip.SameVersion(name.Version, w.Version) {
		return fmt.Sprintf("the wheel's file name says %s %s, the manifest says %s %s", shown(name.Name), shown(name.Version), w.Name, w.Version)
	}
	return ""
}
