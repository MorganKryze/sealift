package importer

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/MorganKryze/sealift/archive"
)

// Options tell Run what to import and where to.
type Options struct {
	Settings       Settings
	Archive        string // packages_npm.tar.gz
	Manifest       string // manifest.json
	ExpectedSHA256 string // hex sha256 received through a separate channel; empty skips the check
	ImportVersion  string
}

// Run checks the archive against its manifest and the signature key, then
// publishes its packages. It writes only to one private temporary directory,
// removed before it returns, and never to the archive or the manifest.
func Run(ctx context.Context, opts Options, newPublisher func(Settings) (Publisher, error)) Report {
	rep := Report{
		Outcome:       OutcomeRefused,
		Unencrypted:   opts.Settings.NexusURL.Scheme == "http",
		ImportVersion: opts.ImportVersion,
		Archive:       ArchiveInfo{File: filepath.Base(opts.Archive)},
		Nexus:         NexusInfo{URL: opts.Settings.NexusURL.String(), Repository: opts.Settings.Repository},
		Packages:      []Result{},
	}
	refuse := func(err error) Report {
		var ref *archive.Refusal
		if errors.As(err, &ref) {
			rep.Reason = ref.Reason
		} else {
			rep.Reason = "could not check the archive: " + err.Error()
		}
		return rep
	}

	m, err := readManifest(opts.Manifest)
	if err != nil {
		return refuse(err)
	}
	rep.ToolVersion, rep.AnalysisID = m.ToolVersion, m.AnalysisID
	rep.Target = TargetInfo{OS: m.Target.OS, CPU: m.Target.CPU, Libc: m.Target.Libc, Node: m.Target.Node, PnpmVer: m.Target.PnpmVer}
	rep.Archive.SHA256, rep.Archive.Size = m.Archive.SHA256, m.Archive.Size

	dir, err := os.MkdirTemp("", "sealift-import-")
	if err != nil {
		return refuse(err)
	}
	defer os.RemoveAll(dir)

	checked, err := verify(opts, m, dir)
	if err != nil {
		return refuse(err)
	}
	pkgs := make([]Package, len(checked))
	for i, c := range checked {
		pkgs[i] = Package{
			Name: c.Package.Name, Version: c.Package.Version, File: c.Package.File,
			Path: c.Path, SHA512: c.SHA512, PublishConfigStripped: c.Package.PublishConfigStripped,
		}
	}

	rep.Packages = publish(ctx, opts, newPublisher, pkgs, dir)
	for _, r := range rep.Packages {
		switch r.State {
		case Published:
			rep.Counts.Published++
		case Present:
			rep.Counts.Present++
		default:
			rep.Counts.Failed++
		}
	}
	rep.Outcome = OutcomeComplete
	if rep.Counts.Failed > 0 {
		rep.Outcome = OutcomeIncomplete
	}
	return rep
}

func readManifest(path string) (archive.Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer f.Close()
	return archive.ParseManifest(f)
}

func verify(opts Options, m archive.Manifest, dir string) ([]archive.Checked, error) {
	f, err := os.Open(opts.Archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return archive.Verify(f, m, archive.VerifyOptions{
		ExpectedSHA256: opts.ExpectedSHA256,
		SignatureKey:   opts.Settings.SignatureKey,
		Dir:            dir,
	})
}

// publish uploads the checked packages. A failure to set up the client or the
// working directory fails every package with that reason.
func publish(ctx context.Context, opts Options, newPublisher func(Settings) (Publisher, error), pkgs []Package, dir string) []Result {
	fail := func(reason string) []Result {
		out := make([]Result, len(pkgs))
		for i, p := range pkgs {
			out[i] = failed(p, reason)
		}
		return out
	}
	pub, err := newPublisher(opts.Settings)
	if err != nil {
		return fail("could not set up the nexus client: " + err.Error())
	}
	// A package file never holds a directory name, so the Nexus copies cannot
	// collide with the checked tarballs.
	work := filepath.Join(dir, "nexus")
	if err := os.Mkdir(work, 0o700); err != nil {
		return fail("could not keep the nexus copies: " + err.Error())
	}
	results := Publish(ctx, pub, pkgs, work)
	for i, p := range pkgs {
		if p.PublishConfigStripped && results[i].State != Failed {
			results[i].Note = "sealift removed publishConfig at export"
		}
	}
	return results
}
