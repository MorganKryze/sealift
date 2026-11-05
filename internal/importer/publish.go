// Package importer publishes the packages of a verified archive to Nexus.
package importer

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxCopySlack is added to twice the shipped size to bound the Nexus copy.
const maxCopySlack = 1 << 20

// State is the outcome of one package.
type State string

// The three states a package ends in.
const (
	Published State = "published"
	Present   State = "present"
	Failed    State = "failed"
)

// Package is one verified tarball waiting to be published.
type Package struct {
	Name, Version, File, Path string
	SHA512                    []byte
	PublishConfigStripped     bool
}

// Result is what happened to one package.
type Result struct {
	Name, Version, File string
	State               State
	Reason, Note        string
}

// Publisher is the part of the Nexus client the run uses.
type Publisher interface {
	CheckRepository(context.Context) error
	Fetch(context.Context, string, string, io.Writer, int64) (bool, error)
	Upload(context.Context, string, io.Reader) error
}

// Publish handles each package once, in order. Nexus copies are written to
// files in dir, which the caller removes.
func Publish(ctx context.Context, p Publisher, pkgs []Package, dir string) []Result {
	results := make([]Result, len(pkgs))
	if err := p.CheckRepository(ctx); err != nil {
		reason := "repository check failed: " + err.Error()
		for i, pkg := range pkgs {
			results[i] = failed(pkg, reason)
		}
		return results
	}
	for i, pkg := range pkgs {
		results[i] = publishOne(ctx, p, pkg, dir)
	}
	return results
}

func publishOne(ctx context.Context, p Publisher, pkg Package, dir string) Result {
	f, err := os.Open(pkg.Path)
	if err != nil {
		return failed(pkg, "cannot open the checked file: "+err.Error())
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return failed(pkg, "cannot read the checked file: "+err.Error())
	}
	limit := 2*info.Size() + maxCopySlack

	remote, found, err := fetchDigest(ctx, p, pkg, dir, limit)
	if err != nil {
		return failed(pkg, err.Error())
	}
	if found {
		if bytes.Equal(remote, pkg.SHA512) {
			return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Present}
		}
		return failed(pkg, "nexus holds this version with other bytes: "+digests(pkg.SHA512, remote))
	}

	// The file is hashed again here: nothing reaches Nexus that the checks
	// did not hash, even if the file changed since.
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return failed(pkg, "cannot read the checked file: "+err.Error())
	}
	if now := h.Sum(nil); !bytes.Equal(now, pkg.SHA512) {
		return failed(pkg, "the file changed after the checks: "+digests(pkg.SHA512, now))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failed(pkg, "cannot read the checked file: "+err.Error())
	}
	if err := p.Upload(ctx, pkg.File, f); err != nil {
		return failed(pkg, "upload failed: "+err.Error())
	}

	remote, found, err = fetchDigest(ctx, p, pkg, dir, limit)
	if err != nil {
		return failed(pkg, "read back failed: "+err.Error())
	}
	if !found {
		return failed(pkg, "nexus accepted the upload but does not serve the version")
	}
	if !bytes.Equal(remote, pkg.SHA512) {
		return failed(pkg, "nexus serves other bytes after the upload: "+digests(pkg.SHA512, remote))
	}
	return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Published}
}

// fetchDigest copies the Nexus version to a file in dir and returns its
// sha512. The file is removed before return.
func fetchDigest(ctx context.Context, p Publisher, pkg Package, dir string, limit int64) ([]byte, bool, error) {
	tmp, err := os.CreateTemp(dir, "nexus-*.tgz")
	if err != nil {
		return nil, false, fmt.Errorf("cannot keep the nexus copy: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	h := sha512.New()
	found, err := p.Fetch(ctx, pkg.Name, pkg.Version, io.MultiWriter(tmp, h), limit)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	if err := tmp.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return nil, false, fmt.Errorf("cannot keep the nexus copy: %w", err)
	}
	return h.Sum(nil), true, nil
}

func digests(shipped, nexus []byte) string {
	return "shipped sha512 " + hex.EncodeToString(shipped) + ", nexus sha512 " + hex.EncodeToString(nexus)
}

func failed(pkg Package, reason string) Result {
	return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Failed, Reason: reason}
}
