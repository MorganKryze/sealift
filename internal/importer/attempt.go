package importer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/nexus"
)

// ErrSource marks a failure of the place the archive is read from. RunAttempt
// reports it as an incomplete import, never as a refused archive.
var ErrSource = errors.New("the archive's source failed")

// ErrUnsigned marks a missing signature file. A Source opener returns it, and
// the attempt refuses the archive as unsigned.
var ErrUnsigned = errors.New("no signature file")

// maxStoredReason is the longest reason a report keeps: 1,000 characters.
const maxStoredReason = 1000

// ecosystemPip is Report.Ecosystem for a pip archive.
const ecosystemPip = string(archive.Pip)

// Source is where an attempt reads the manifest, its signature and the archive. Each opener
// returns a fresh stream; an error it marks with ErrSource is a failure of the
// source, an *archive.Refusal is a refusal, and any other error is a local one.
type Source struct {
	Name          string // archive file name for the report
	SignatureName string // signature file name for the unsigned refusal; empty means manifest.json.sig
	Manifest      func(ctx context.Context) (io.ReadCloser, error)
	Signature     func(ctx context.Context) (io.ReadCloser, error) // returns ErrUnsigned when there is none
	Archive       func(ctx context.Context) (io.ReadCloser, error)
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
	// Ecosystem is the archive's folder: a manifest of another ecosystem is
	// refused. Empty accepts either.
	Ecosystem archive.Ecosystem
}

type publishEachFunc func(context.Context, Publisher, []Package, string, func(int, Result)) []Result

// RunAttempt checks the manifest's signature, then the archive against the
// manifest, then publishes its packages. It writes only to a.Dir and empties it before
// it returns.
func RunAttempt(ctx context.Context, a Attempt, newPublisher func(Settings) (Publisher, error)) Report {
	return runAttempt(ctx, a, newPublisher, PublishEach)
}

// runAttempt takes the publishing step as a parameter so a test can fix its results.
func runAttempt(ctx context.Context, a Attempt, newPublisher func(Settings) (Publisher, error), publishAll publishEachFunc) Report {
	defer emptyDir(a.Dir)
	rep := Report{
		Outcome:         OutcomeRefused,
		Unencrypted:     a.Unencrypted || a.Settings.NexusURL.Scheme == "http",
		ImportVersion:   a.ImportVersion,
		Archive:         ArchiveInfo{File: a.Source.Name},
		Nexus:           NexusInfo{URL: a.Settings.NexusURL.String(), Repository: a.Settings.Repository},
		Packages:        []Result{},
		ArchiveChecked:  ptr(false),
		PublicKeySHA256: a.Settings.PublicKeySHA256,
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

	data, err := readSigned(ctx, a.Source, a.Settings.PublicKey)
	if err != nil {
		return stop(err)
	}
	eco, err := archive.ManifestEcosystem(data)
	if err != nil {
		return stop(err)
	}
	if a.Ecosystem != "" && eco != a.Ecosystem {
		return stop(wrongFolder(eco, a.Ecosystem))
	}
	if eco == archive.Pip {
		return runPip(ctx, a, newPublisher, data, &rep, stop)
	}
	m, err := archive.ParseManifest(data)
	if err != nil {
		return stop(err)
	}
	rep.ToolVersion, rep.AnalysisID = m.ToolVersion, m.AnalysisID
	rep.Target = TargetInfo{OS: m.Target.OS, CPU: m.Target.CPU, Libc: m.Target.Libc, Node: m.Target.Node, PnpmVer: m.Target.PnpmVer}
	rep.Archive.SHA256, rep.Archive.Size = m.Archive.SHA256, m.Archive.Size
	rep.Crossing = crossingOf(m.CreatedAt, len(m.Packages), m.Review)

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

// readSigned reads the manifest once, whole, then the signature file, and
// returns the manifest's bytes once the signature over them checks, so no
// untrusted JSON is parsed before it is authenticated and a read cut short is
// a failure of the source, never a refusal of the manifest.
func readSigned(ctx context.Context, src Source, trusted ed25519.PublicKey) ([]byte, error) {
	data, err := readAll(ctx, src.Manifest, archive.ReadManifest)
	if err != nil {
		return nil, err
	}
	sig, err := readSignature(ctx, src)
	if err != nil {
		return nil, err
	}
	if err := archive.CheckSignature(data, sig, trusted); err != nil {
		return nil, err
	}
	return data, nil
}

// crossingOf is the crossing a manifest whose signature verified describes.
// Its figures count as a reader of the review does: an update or a jumped
// package each counts once, and the CVEs carried with a reason count by
// dependency.
func crossingOf(sealedAt string, packages int, r *archive.Review) *Crossing {
	c := &Crossing{SealedAt: sealedAt, Packages: packages}
	if r == nil {
		return c
	}
	c.Project = r.Project
	jumped := 0
	for _, j := range r.Jumps {
		jumped += len(j.Packages)
	}
	carried := map[string]bool{}
	for _, l := range r.Left {
		if l.Reason != "" {
			carried[l.Dependency] = true
		}
	}
	c.Review = &CrossingReview{
		Updated: len(r.Updates) + jumped, CVEsBefore: r.CVEs.Before,
		Carried: len(carried), Jumps: jumped,
	}
	if r.CVEs.After != nil {
		after := *r.CVEs.After
		c.Review.CVEsAfter = &after
	}
	return c
}

// wrongFolder refuses a manifest of ecosystem got found in a folder that takes want.
func wrongFolder(got, want archive.Ecosystem) error {
	article := func(e archive.Ecosystem) string {
		if e == archive.NPM {
			return "an"
		}
		return "a"
	}
	return &archive.Refusal{Reason: fmt.Sprintf("the manifest describes %s %s archive, and this folder takes %s archives: move the three files to packages/%s/",
		article(got), got, want, got)}
}

func readSignature(ctx context.Context, src Source) ([]byte, error) {
	if src.Signature == nil {
		return nil, signatureMissing(src)
	}
	sig, err := readAll(ctx, src.Signature, func(r io.Reader) ([]byte, error) {
		return io.ReadAll(io.LimitReader(r, archive.MaxSignatureSize+1))
	})
	if errors.Is(err, ErrUnsigned) {
		return nil, signatureMissing(src)
	}
	return sig, err
}

func signatureMissing(src Source) error {
	name := src.SignatureName
	if name == "" {
		name = archive.SignatureFile
	}
	return archive.Unsigned(name)
}

func readAll(ctx context.Context, open func(context.Context) (io.ReadCloser, error), read func(io.Reader) ([]byte, error)) ([]byte, error) {
	rc, err := open(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return read(rc)
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
		Dir:            a.Dir,
	})
}

// runPip goes on with a pip manifest whose signature checked. rep is the
// attempt's report, the one stop fills. The settings and the repository are
// checked before the archive is read, so a deployment that cannot take wheels
// refuses the archive without reading it.
func runPip(ctx context.Context, a Attempt, newPublisher func(Settings) (Publisher, error), data []byte, rep *Report, stop func(error) Report) Report {
	rep.Ecosystem = ecosystemPip
	rep.Nexus.Repository = ""
	if a.Settings.Pip != nil {
		rep.Nexus.Repository = a.Settings.Pip.Repository
	}
	m, err := archive.ParsePipManifest(data)
	if err != nil {
		return stop(err)
	}
	rep.ToolVersion, rep.AnalysisID = m.ToolVersion, m.AnalysisID
	rep.Target = TargetInfo{OS: m.Target.OS, CPU: m.Target.CPU, Python: m.Target.Python, Glibc: m.Target.Glibc}
	rep.Archive.SHA256, rep.Archive.Size = m.Archive.SHA256, m.Archive.Size
	rep.Crossing = crossingOf(m.CreatedAt, len(m.Packages), m.Review)

	listed := make([]Result, len(m.Packages))
	for i, w := range m.Packages {
		listed[i] = Result{Name: w.Name, Version: w.Version, File: w.File, State: Pending}
	}
	if a.Progress.Listed != nil {
		snap := *rep
		snap.Outcome, snap.Reason = "", ""
		snap.Packages = append([]Result(nil), listed...)
		snap.ArchiveChecked = ptr(false)
		a.Progress.Listed(snap)
	}
	ended := func(i int, r Result) Result {
		r.Reason = cut(r.Reason)
		if a.Progress.Ended != nil {
			a.Progress.Ended(i, r)
		}
		return r
	}
	// failAll ends every listed wheel with one reason, or as interrupted
	// once ctx is done.
	failAll := func(kind Kind, reason string) Report {
		rep.Outcome, rep.Reason = OutcomeIncomplete, ""
		rep.Packages = make([]Result, len(listed))
		for i, r := range listed {
			rep.Packages[i] = ended(i, failedOr(ctx, Package{Name: r.Name, Version: r.Version, File: r.File}, kind, reason))
		}
		rep.Counts = Counts{Failed: len(listed)}
		return *rep
	}

	settings, err := a.Settings.ForPip()
	if err != nil {
		rep.Reason = err.Error()
		return *rep
	}
	pub, err := newPublisher(settings)
	if err != nil {
		return failAll(KindLocal, "could not set up the nexus client: "+err.Error())
	}
	// A repository Nexus does not list as pypi hosted is the settings'
	// fault and refuses the archive; an unreachable Nexus or refused
	// credentials leave the import to retry.
	if err := pub.CheckRepository(ctx); err != nil {
		if ctx.Err() == nil && errors.Is(err, nexus.ErrRepository) {
			rep.Reason = cut(err.Error())
			return *rep
		}
		return failAll(KindNexus, "repository check failed: "+err.Error())
	}

	checked, err := verifyPip(ctx, a, m)
	var ref *archive.Refusal
	switch {
	case err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()):
		return failAll(KindInterrupted, reasonInterrupted)
	case errors.As(err, &ref):
		rep.Reason = cut(ref.Reason)
		return *rep
	case errors.Is(err, ErrSource):
		return failAll(KindSource, clean(err.Error()))
	case err != nil:
		rep.Reason = cut("could not check the archive: " + err.Error())
		return *rep
	}
	*rep.ArchiveChecked = true
	if a.Progress.Checked != nil {
		a.Progress.Checked()
	}
	wheels := make([]Package, len(checked))
	for i, c := range checked {
		wheels[i] = Package{Name: c.Wheel.Name, Version: c.Wheel.Version, File: c.Wheel.File, Path: c.Path, SHA512: c.SHA512}
	}
	// PublishWheels hashes the Nexus copies as they arrive, so it needs no directory.
	rep.Packages = PublishWheels(ctx, pub, wheels, "", func(i int, r Result) { ended(i, r) })
	rep.Counts = Counts{}
	for i, r := range rep.Packages {
		rep.Packages[i].Reason = cut(r.Reason)
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
	return *rep
}

func verifyPip(ctx context.Context, a Attempt, m archive.PipManifest) ([]archive.CheckedWheel, error) {
	rc, err := a.Source.Archive(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return archive.VerifyPip(ctxReader{ctx, rc}, m, archive.VerifyOptions{
		ExpectedSHA256: a.ExpectedSHA256,
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
