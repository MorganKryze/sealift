package importer

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

type publishFunc func(context.Context, Publisher, []Package, string) []Result

// Options tell Run what to import and where to.
type Options struct {
	Settings       Settings
	Archive        string // packages_npm.tar.gz
	Manifest       string // manifest.json
	Signature      string // manifest.json.sig; empty reads Manifest + ".sig"
	ExpectedSHA256 string // hex sha256 received through a separate channel; empty skips the check
	ImportVersion  string
}

// Run checks the manifest's signature, then the archive against the manifest, then
// publishes its packages. It writes only to one private temporary directory,
// removed before it returns, and never to the archive or the manifest.
func Run(ctx context.Context, opts Options, newPublisher func(Settings) (Publisher, error)) Report {
	return runFiles(ctx, opts, newPublisher, PublishEach)
}

// run takes the publishing step as a parameter so a test can fix its results.
func run(ctx context.Context, opts Options, newPublisher func(Settings) (Publisher, error), publishAll publishFunc) Report {
	return runFiles(ctx, opts, newPublisher, func(ctx context.Context, p Publisher, pkgs []Package, dir string, _ func(int, Result)) []Result {
		return publishAll(ctx, p, pkgs, dir)
	})
}

// runFiles runs one attempt that reads the two files of opts. A local read
// failure is not marked ErrSource, so it stays a refusal.
func runFiles(ctx context.Context, opts Options, newPublisher func(Settings) (Publisher, error), publishAll publishEachFunc) Report {
	open := func(path string) func(context.Context) (io.ReadCloser, error) {
		return func(context.Context) (io.ReadCloser, error) { return os.Open(path) }
	}
	sigPath := opts.Signature
	if sigPath == "" {
		sigPath = opts.Manifest + ".sig"
	}
	openSignature := func(context.Context) (io.ReadCloser, error) {
		f, err := os.Open(sigPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrUnsigned
		}
		return f, err
	}
	a := Attempt{
		Settings: opts.Settings,
		Source: Source{
			Name: filepath.Base(opts.Archive), SignatureName: filepath.Base(sigPath),
			Manifest: open(opts.Manifest), Signature: openSignature, Archive: open(opts.Archive),
		},
		ExpectedSHA256: opts.ExpectedSHA256,
		ImportVersion:  opts.ImportVersion,
	}
	dir, err := os.MkdirTemp("", "sealift-import-")
	if err == nil {
		// MkdirTemp gives a relative path when TMPDIR is relative.
		dir, err = filepath.Abs(dir)
	}
	if err != nil {
		return Report{
			Outcome:         OutcomeRefused,
			Reason:          cut("could not check the archive: " + err.Error()),
			Unencrypted:     opts.Settings.NexusURL.Scheme == "http",
			ImportVersion:   opts.ImportVersion,
			PublicKeySHA256: opts.Settings.PublicKeySHA256,
			Archive:         ArchiveInfo{File: a.Source.Name},
			Nexus:           NexusInfo{URL: opts.Settings.NexusURL.String(), Repository: opts.Settings.Repository},
			Packages:        []Result{},
			ArchiveChecked:  ptr(false),
		}
	}
	defer os.RemoveAll(dir)
	a.Dir = dir
	return runAttempt(ctx, a, newPublisher, publishAll)
}
