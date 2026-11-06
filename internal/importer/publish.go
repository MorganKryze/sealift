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
	"strings"
	"unicode"

	"github.com/MorganKryze/sealift/npm"
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

// Pending marks a listed package that has not ended. Only the stored progress
// of a running attempt carries it; a report never does.
const Pending State = "pending"

// Package is one verified tarball waiting to be published.
type Package struct {
	Name, Version, File, Path string
	SHA512                    []byte
	PublishConfigStripped     bool
}

// Kind says why a package failed, so a reader can tell what to do next
// without reading the reason.
type Kind string

// The kinds of failure. A package that did not fail has none.
const (
	KindConflict    Kind = "conflict"    // Nexus holds this version with other bytes
	KindNexus       Kind = "nexus"       // Nexus refused, did not answer or served something else after the upload
	KindSource      Kind = "source"      // the archive could not be read from where it is kept
	KindInterrupted Kind = "interrupted" // the service stopped before the package ended
	KindMismatch    Kind = "mismatch"    // the tarball is not the package the manifest names
	KindLocal       Kind = "local"       // a file or a client on the import's own side failed
)

// Result is what happened to one package. Kind is set on a failed package only.
type Result struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	File    string `json:"file"`
	State   State  `json:"state"`
	Reason  string `json:"reason"`
	Note    string `json:"note"`
	Kind    Kind   `json:"kind,omitempty"`
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
	return PublishEach(ctx, p, pkgs, dir, nil)
}

// PublishEach is Publish that calls ended with each package's result as soon
// as it is known, before the next package starts. ended may be nil.
func PublishEach(ctx context.Context, p Publisher, pkgs []Package, dir string, ended func(int, Result)) []Result {
	results := make([]Result, len(pkgs))
	done := func(i int, r Result) {
		results[i] = r
		if ended != nil {
			ended(i, r)
		}
	}
	if err := p.CheckRepository(ctx); err != nil {
		for i, pkg := range pkgs {
			done(i, failedOr(ctx, pkg, KindNexus, "repository check failed: "+err.Error()))
		}
		return results
	}
	for i, pkg := range pkgs {
		// A package that has not started never starts after an interrupt.
		if ctx.Err() != nil {
			done(i, failed(pkg, KindInterrupted, reasonInterrupted))
			continue
		}
		done(i, publishOne(ctx, p, pkg, dir))
	}
	return results
}

// reasonInterrupted is the reason of a package an interrupt kept from finishing.
const reasonInterrupted = "interrupted"

// failedOr fails pkg as interrupted when ctx is done, since a cancelled
// request reports an error that says nothing about Nexus, and as kind with
// reason otherwise.
func failedOr(ctx context.Context, pkg Package, kind Kind, reason string) Result {
	if ctx.Err() != nil {
		return failed(pkg, KindInterrupted, reasonInterrupted)
	}
	return failed(pkg, kind, reason)
}

// localError marks a failure on the import's own side inside a helper that
// also reports Nexus failures.
type localError struct{ error }

func (e localError) Unwrap() error { return e.error }

// kindOf is KindLocal for a localError and KindNexus for any other error of a call to Nexus.
func kindOf(err error) Kind {
	if errors.As(err, new(localError)) {
		return KindLocal
	}
	return KindNexus
}

func publishOne(ctx context.Context, p Publisher, pkg Package, dir string) Result {
	f, err := os.Open(pkg.Path)
	if err != nil {
		return failed(pkg, KindLocal, "cannot open the checked file: "+err.Error())
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return failed(pkg, KindLocal, "cannot read the checked file: "+err.Error())
	}
	limit := 2*info.Size() + maxCopySlack

	if reason := mismatch(f, pkg); reason != "" {
		return failed(pkg, KindMismatch, reason)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failed(pkg, KindLocal, "cannot read the checked file: "+err.Error())
	}

	remote, found, same, err := fetchDigest(ctx, p, pkg, dir, limit, f, info.Size())
	if err != nil {
		return failedOr(ctx, pkg, kindOf(err), err.Error())
	}
	if found {
		if bytes.Equal(remote, pkg.SHA512) {
			return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Present}
		}
		if same {
			return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Present, Note: noteSameContent}
		}
		return failed(pkg, KindConflict, "nexus holds this version with other bytes: "+digests(pkg.SHA512, remote))
	}

	// The file is hashed again here: nothing reaches Nexus that the checks
	// did not hash, even if the file changed since.
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return failed(pkg, KindLocal, "cannot read the checked file: "+err.Error())
	}
	if now := h.Sum(nil); !bytes.Equal(now, pkg.SHA512) {
		return failed(pkg, KindLocal, "the file changed after the checks: "+digests(pkg.SHA512, now))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failed(pkg, KindLocal, "cannot read the checked file: "+err.Error())
	}
	if err := p.Upload(ctx, pkg.File, f); err != nil {
		return failedOr(ctx, pkg, KindNexus, "upload failed: "+err.Error())
	}

	remote, found, _, err = fetchDigest(ctx, p, pkg, dir, limit, nil, 0)
	if err != nil {
		return failedOr(ctx, pkg, kindOf(err), "read back failed: "+err.Error())
	}
	if !found {
		return failed(pkg, KindNexus, "nexus accepted the upload but does not serve the version")
	}
	if !bytes.Equal(remote, pkg.SHA512) {
		return failed(pkg, KindNexus, "nexus serves other bytes after the upload: "+digests(pkg.SHA512, remote))
	}
	return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Published}
}

// noteSameContent is the note of a stripped package that Nexus holds repacked.
const noteSameContent = "same content, packed differently"

// maxShownName cuts a name or version read from a tarball before it enters a reason.
const maxShownName = 100

// mismatch returns why the tarball in f cannot be the package of its manifest
// entry, or "" when it can.
func mismatch(f io.Reader, pkg Package) string {
	info, err := npm.InspectTarball(f)
	if err != nil {
		return clean("the tarball is not a valid package: " + err.Error())
	}
	if info.Name != pkg.Name || info.Version != pkg.Version {
		return fmt.Sprintf("the tarball is %s@%s, the manifest says %s@%s", shown(info.Name), shown(info.Version), pkg.Name, pkg.Version)
	}
	return ""
}

// maxReasonChars is the longest text read from a tarball that reaches a reason.
const maxReasonChars = 300

// clean removes control characters from text read from a tarball, then cuts it.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > maxReasonChars {
		s = string(r[:maxReasonChars])
	}
	return s
}

// shown quotes text from a tarball and cuts it to maxShownName characters.
func shown(s string) string {
	if r := []rune(s); len(r) > maxShownName {
		s = string(r[:maxShownName]) + "..."
	}
	return fmt.Sprintf("%q", s)
}

// fetchDigest copies the Nexus version to a file in dir and returns its
// sha512. The file is removed before return. When shipped is not nil, a copy
// with other bytes of a stripped package is compared with the shipped
// tarball, and same reports equal content.
func fetchDigest(ctx context.Context, p Publisher, pkg Package, dir string, limit int64, shipped io.ReaderAt, size int64) (digest []byte, found, same bool, err error) {
	tmp, err := os.CreateTemp(dir, "nexus-*.tgz")
	if err != nil {
		return nil, false, false, localError{fmt.Errorf("cannot keep the nexus copy: %w", err)}
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	h := sha512.New()
	found, err = p.Fetch(ctx, pkg.Name, pkg.Version, io.MultiWriter(tmp, h), limit)
	if err != nil {
		return nil, false, false, err
	}
	if !found {
		return nil, false, false, nil
	}
	if err := tmp.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return nil, false, false, localError{fmt.Errorf("cannot keep the nexus copy: %w", err)}
	}
	digest = h.Sum(nil)
	if shipped == nil || !pkg.PublishConfigStripped || bytes.Equal(digest, pkg.SHA512) {
		return digest, true, false, nil
	}
	same, err = sameContent(tmp, shipped, size, pkg.SHA512)
	if err != nil {
		return nil, false, false, err
	}
	return digest, true, same, nil
}

// sameContent compares the Nexus copy with the shipped tarball. The shipped
// bytes are hashed while they are read, so a file that changed since the
// checks never reads as the same content.
func sameContent(nexusCopy *os.File, shipped io.ReaderAt, size int64, want []byte) (bool, error) {
	if _, err := nexusCopy.Seek(0, io.SeekStart); err != nil {
		return false, localError{fmt.Errorf("cannot read the nexus copy: %w", err)}
	}
	h := sha512.New()
	tee := io.TeeReader(io.NewSectionReader(shipped, 0, size), h)
	same, err := npm.SameContent(tee, nexusCopy)
	if err != nil {
		return false, errors.New(clean("cannot compare the nexus copy: " + err.Error()))
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return false, localError{fmt.Errorf("cannot read the checked file: %w", err)}
	}
	return same && bytes.Equal(h.Sum(nil), want), nil
}

func digests(shipped, nexus []byte) string {
	return "shipped sha512 " + hex.EncodeToString(shipped) + ", nexus sha512 " + hex.EncodeToString(nexus)
}

func failed(pkg Package, kind Kind, reason string) Result {
	return Result{Name: pkg.Name, Version: pkg.Version, File: pkg.File, State: Failed, Reason: reason, Kind: kind}
}
