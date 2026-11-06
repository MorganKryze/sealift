package importer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MorganKryze/sealift/archive"
)

// ErrSource marks a failure of the place the archive is read from. RunAttempt
// reports it as an incomplete import, never as a refused archive.
var ErrSource = errors.New("the archive's source failed")

// maxStoredReason is the longest reason a report keeps: 1,000 characters.
const maxStoredReason = 1000

// Source is where an attempt reads the manifest and the archive. Each opener
// returns a fresh stream; an error it marks with ErrSource is a failure of the
// source, an *archive.Refusal is a refusal, and any other error is a local one.
type Source struct {
	Name     string // archive file name for the report
	Manifest func(ctx context.Context) (io.ReadCloser, error)
	Archive  func(ctx context.Context) (io.ReadCloser, error)
}

// Progress receives the attempt's package states as they change. Either field
// may be nil.
type Progress struct {
	Listed  func(rep Report)      // the manifest is read: the report so far, every package pending, no outcome
	Checked func()                // the archive passed its checks
	Ended   func(i int, r Result) // package i has ended
}

// Attempt is one try at importing an archive.
type Attempt struct {
	Settings       Settings
	Source         Source
	ExpectedSHA256 string
	ImportVersion  string
	Dir            string // absolute, existing, private; RunAttempt empties it before returning
	Unencrypted    bool   // MinIO or the key set is plain http
	Progress       Progress
}

type publishEachFunc func(context.Context, Publisher, []Package, string, func(int, Result)) []Result

// RunAttempt checks the archive against its manifest and the signature key,
// then publishes its packages. It writes only to a.Dir and empties it before
// it returns.
func RunAttempt(ctx context.Context, a Attempt, newPublisher func(Settings) (Publisher, error)) Report {
	return runAttempt(ctx, a, newPublisher, PublishEach)
}

// runAttempt takes the publishing step as a parameter so a test can fix its results.
func runAttempt(ctx context.Context, a Attempt, newPublisher func(Settings) (Publisher, error), publishAll publishEachFunc) Report {
	defer emptyDir(a.Dir)
	rep := Report{
		Outcome:        OutcomeRefused,
		Unencrypted:    a.Unencrypted || a.Settings.NexusURL.Scheme == "http",
		ImportVersion:  a.ImportVersion,
		Archive:        ArchiveInfo{File: a.Source.Name},
		Nexus:          NexusInfo{URL: a.Settings.NexusURL.String(), Repository: a.Settings.Repository},
		Packages:       []Result{},
		ArchiveChecked: ptr(false),
	}
	interrupted := func(err error) bool { return err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) }
	// stop ends the attempt on an error before any package is listed.
	stop := func(err error) Report {
		var ref *archive.Refusal
		switch {
		case interrupted(err):
			rep.Outcome, rep.Reason = OutcomeIncomplete, reasonInterrupted
		case errors.As(err, &ref):
			rep.Reason = cut(ref.Reason)
		case errors.Is(err, ErrSource):
			rep.Outcome, rep.Reason = OutcomeIncomplete, cut(clean(err.Error()))
		default:
			rep.Reason = cut("could not check the archive: " + err.Error())
		}
		return rep
	}

	m, err := readManifest(ctx, a.Source)
	if err != nil {
		return stop(err)
	}
	rep.ToolVersion, rep.AnalysisID = m.ToolVersion, m.AnalysisID
	rep.Target = TargetInfo{OS: m.Target.OS, CPU: m.Target.CPU, Libc: m.Target.Libc, Node: m.Target.Node, PnpmVer: m.Target.PnpmVer}
	rep.Archive.SHA256, rep.Archive.Size = m.Archive.SHA256, m.Archive.Size

	listed := make([]Result, len(m.Packages))
	for i, p := range m.Packages {
		listed[i] = Result{Name: p.Name, Version: p.Version, File: p.File, State: Pending}
	}
	if a.Progress.Listed != nil {
		snap := rep
		snap.Outcome, snap.Reason = "", ""
		snap.Packages = append([]Result(nil), listed...)
		snap.ArchiveChecked = ptr(false)
		a.Progress.Listed(snap)
	}
	// failAll ends every listed package with one reason.
	failAll := func(kind Kind, reason string) {
		rep.Outcome, rep.Reason = OutcomeIncomplete, ""
		rep.Packages = make([]Result, len(listed))
		for i, r := range listed {
			rep.Packages[i] = failed(Package{Name: r.Name, Version: r.Version, File: r.File}, kind, reason)
			if a.Progress.Ended != nil {
				a.Progress.Ended(i, rep.Packages[i])
			}
		}
		rep.Counts.Failed = len(rep.Packages)
	}

	checked, err := verify(ctx, a, m)
	var ref *archive.Refusal
	switch {
	case interrupted(err):
		// No package was handled: the checks did not finish.
		failAll(KindInterrupted, reasonInterrupted)
		return rep
	case errors.As(err, &ref):
		rep.Reason = cut(ref.Reason)
		return rep
	case errors.Is(err, ErrSource):
		failAll(KindSource, cut(clean(err.Error())))
		return rep
	case err != nil:
		rep.Reason = cut("could not check the archive: " + err.Error())
		return rep
	}
	*rep.ArchiveChecked = true
	if a.Progress.Checked != nil {
		a.Progress.Checked()
	}
	pkgs := make([]Package, len(checked))
	for i, c := range checked {
		pkgs[i] = Package{
			Name: c.Package.Name, Version: c.Package.Version, File: c.Package.File,
			Path: c.Path, SHA512: c.SHA512, PublishConfigStripped: c.Package.PublishConfigStripped,
		}
	}

	rep.Packages = publish(ctx, a, newPublisher, publishAll, pkgs)
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

// readManifest reads the whole manifest before parsing it, so a read cut
// short is a failure of the source and never a refusal of the manifest.
func readManifest(ctx context.Context, src Source) (archive.Manifest, error) {
	rc, err := src.Manifest(ctx)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, archive.MaxManifestSize+1))
	if err != nil {
		return archive.Manifest{}, err
	}
	return archive.ParseManifest(bytes.NewReader(data))
}

// ctxReader stops a read once ctx is done, so an interrupt does not wait for
// the whole archive.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func verify(ctx context.Context, a Attempt, m archive.Manifest) ([]archive.Checked, error) {
	rc, err := a.Source.Archive(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return archive.Verify(ctxReader{ctx, rc}, m, archive.VerifyOptions{
		ExpectedSHA256: a.ExpectedSHA256,
		SignatureKey:   a.Settings.SignatureKey,
		Dir:            a.Dir,
	})
}

// publish uploads the checked packages. A failure to set up the client or the
// working directory fails every package with that reason.
func publish(ctx context.Context, a Attempt, newPublisher func(Settings) (Publisher, error), publishAll publishEachFunc, pkgs []Package) []Result {
	// A note from the publisher is evidence of how the verdict was reached
	// and stays; the default only fills an empty one.
	finish := func(i int, r Result) Result {
		if pkgs[i].PublishConfigStripped && r.State != Failed && r.Note == "" {
			r.Note = "sealift removed publishConfig at export"
		}
		r.Reason = cut(r.Reason)
		return r
	}
	ended := func(i int, r Result) {
		if a.Progress.Ended != nil {
			a.Progress.Ended(i, finish(i, r))
		}
	}
	fail := func(reason string) []Result {
		out := make([]Result, len(pkgs))
		for i, p := range pkgs {
			out[i] = failed(p, KindLocal, reason)
			ended(i, out[i])
		}
		return out
	}
	pub, err := newPublisher(a.Settings)
	if err != nil {
		return fail("could not set up the nexus client: " + err.Error())
	}
	// A package file never holds a directory name, so the Nexus copies cannot
	// collide with the checked tarballs.
	work := filepath.Join(a.Dir, "nexus")
	if err := os.Mkdir(work, 0o700); err != nil {
		return fail("could not keep the nexus copies: " + err.Error())
	}
	results := publishAll(ctx, pub, pkgs, work, ended)
	for i := range results {
		results[i] = finish(i, results[i])
	}
	return results
}

// cut keeps the first maxStoredReason characters of a reason.
func cut(s string) string {
	s = strings.ToValidUTF8(s, "")
	if r := []rune(s); len(r) > maxStoredReason {
		s = string(r[:maxStoredReason])
	}
	return s
}

// emptyDir removes what an attempt left in dir and keeps dir itself.
func emptyDir(dir string) {
	// Verify refuses a relative directory, so nothing relative holds our files.
	if !filepath.IsAbs(dir) {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}

func ptr[T any](v T) *T { return &v }
