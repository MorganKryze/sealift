package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importtest"
	"github.com/MorganKryze/sealift/internal/nexus"
	"github.com/MorganKryze/sealift/npm"
)

func fileSource(opts Options) Source {
	open := func(path string) func(context.Context) (io.ReadCloser, error) {
		return func(context.Context) (io.ReadCloser, error) { return os.Open(path) }
	}
	return Source{
		Name: "packages_npm.tar.gz", SignatureName: "manifest.json.sig",
		Manifest: open(opts.Manifest), Signature: open(opts.Manifest + ".sig"), Archive: open(opts.Archive),
	}
}

// attemptOf builds an attempt over the fixture's files with a fresh directory.
func (r *runFixture) attemptOf(t *testing.T) Attempt {
	t.Helper()
	return Attempt{
		Settings: r.opts.Settings, Source: fileSource(r.opts), ImportVersion: "0.3.0",
		Dir: filepath.Join(t.TempDir(), "data[1]", "work-1"),
	}
}

func (r *runFixture) runAttempt(t *testing.T, a Attempt) Report {
	t.Helper()
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return RunAttempt(context.Background(), a, func(Settings) (Publisher, error) {
		r.built++
		return r.f.client(t), nil
	})
}

// cutReader returns the first n bytes of b, then err.
func cutReader(b []byte, n int, err error) io.ReadCloser {
	return io.NopCloser(io.MultiReader(bytes.NewReader(b[:n]), &errReader{err}))
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

func TestRunAttemptSourceFailure(t *testing.T) {
	cutErr := fmt.Errorf("%w: connection reset by peer", ErrSource)
	for name, tc := range map[string]struct {
		change   func(a *Attempt, manifest, arch []byte)
		outcome  string
		reason   string
		packages int
	}{
		"manifest cut partway": {func(a *Attempt, manifest, _ []byte) {
			a.Source.Manifest = func(context.Context) (io.ReadCloser, error) {
				return cutReader(manifest, len(manifest)/2, cutErr), nil
			}
		}, OutcomeIncomplete, "connection reset by peer", 0},
		"manifest cannot be opened": {func(a *Attempt, _, _ []byte) {
			a.Source.Manifest = func(context.Context) (io.ReadCloser, error) { return nil, cutErr }
		}, OutcomeIncomplete, "connection reset by peer", 0},
		"archive cut partway": {func(a *Attempt, _, arch []byte) {
			a.Source.Archive = func(context.Context) (io.ReadCloser, error) {
				return cutReader(arch, len(arch)/2, cutErr), nil
			}
		}, OutcomeIncomplete, "connection reset by peer", 2},
		"archive cannot be opened": {func(a *Attempt, _, _ []byte) {
			a.Source.Archive = func(context.Context) (io.ReadCloser, error) { return nil, cutErr }
		}, OutcomeIncomplete, "connection reset by peer", 2},
		"refusal from the archive opener": {func(a *Attempt, _, _ []byte) {
			a.Source.Archive = func(context.Context) (io.ReadCloser, error) {
				return nil, &archive.Refusal{Reason: "the object changed since it was listed"}
			}
		}, OutcomeRefused, "the object changed since it was listed", 0},
		"failure that is not the source's": {func(a *Attempt, _, _ []byte) {
			a.Source.Archive = func(context.Context) (io.ReadCloser, error) { return nil, errors.New("disk on fire") }
		}, OutcomeRefused, "could not check the archive: disk on fire", 0},
		"a long reason is cut": {func(a *Attempt, _, _ []byte) {
			a.Source.Archive = func(context.Context) (io.ReadCloser, error) {
				return nil, fmt.Errorf("%w: %s", ErrSource, strings.Repeat("x", 5000))
			}
		}, OutcomeIncomplete, "xxx", 2},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			manifest, _ := os.ReadFile(r.opts.Manifest)
			arch, _ := os.ReadFile(r.opts.Archive)
			a := r.attemptOf(t)
			tc.change(&a, manifest, arch)
			var listed int
			var ended []Result
			a.Progress = Progress{
				Listed: func(Report) { listed++ },
				Ended:  func(_ int, res Result) { ended = append(ended, res) },
			}
			rep := r.runAttempt(t, a)

			if rep.Outcome != tc.outcome {
				t.Fatalf("outcome %q (%s), want %q", rep.Outcome, rep.Reason, tc.outcome)
			}
			if tc.outcome == OutcomeIncomplete {
				reason := rep.Reason
				if tc.packages > 0 {
					reason = rep.Packages[0].Reason
				}
				if !strings.Contains(reason, tc.reason) {
					t.Errorf("reason %q lacks %q", reason, tc.reason)
				}
			} else if !strings.Contains(rep.Reason, tc.reason) {
				t.Errorf("reason %q lacks %q", rep.Reason, tc.reason)
			}
			if len(rep.Packages) != tc.packages || rep.Counts.Failed != tc.packages {
				t.Errorf("%d packages, counts %+v, want %d failed", len(rep.Packages), rep.Counts, tc.packages)
			}
			for _, p := range rep.Packages {
				if p.State != Failed || len([]rune(p.Reason)) > 1000 {
					t.Errorf("%s: %q, reason of %d characters", p.Name, p.State, len([]rune(p.Reason)))
				}
			}
			if len([]rune(rep.Reason)) > 1000 {
				t.Errorf("report reason has %d characters", len([]rune(rep.Reason)))
			}
			if tc.packages > 0 && (listed != 1 || len(ended) != tc.packages) {
				t.Errorf("listed %d times, %d packages ended, want 1 and %d", listed, len(ended), tc.packages)
			}
			if r.built != 0 || len(r.f.requests) != 0 {
				t.Errorf("publisher built %d times, %d requests", r.built, len(r.f.requests))
			}
		})
	}
}

func TestRunAttemptRemovesWorkFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		setup   func(r *runFixture, a *Attempt)
		outcome string
	}{
		"complete":   {func(r *runFixture, _ *Attempt) { r.serveUploads() }, OutcomeComplete},
		"incomplete": {func(r *runFixture, _ *Attempt) { r.f.postStatus = 500 }, OutcomeIncomplete},
		"refused":    {func(_ *runFixture, a *Attempt) { a.ExpectedSHA256 = wrongSHA256 }, OutcomeRefused},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			a := r.attemptOf(t)
			tc.setup(r, &a)
			if err := os.MkdirAll(a.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(a.Dir, "stray"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			rep := r.runAttempt(t, a)
			if rep.Outcome != tc.outcome {
				t.Fatalf("outcome %q (%s), want %q", rep.Outcome, rep.Reason, tc.outcome)
			}
			assertEmpty(t, a.Dir)
		})
	}

	t.Run("cancelled during an upload", func(t *testing.T) {
		r, held := newInterruptFixture(t)
		a := r.attemptOf(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := os.MkdirAll(a.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		done := make(chan Report, 1)
		go func() {
			done <- RunAttempt(ctx, a, func(Settings) (Publisher, error) { return r.f.client(t), nil })
		}()
		<-held
		cancel()
		rep := <-done
		if rep.Outcome != OutcomeIncomplete {
			t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
		}
		assertEmpty(t, a.Dir)
	})
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	left, err := os.ReadDir(dir)
	if err != nil || len(left) != 0 {
		t.Fatalf("%s holds %v, %v", dir, left, err)
	}
}

func TestRunAttemptProgress(t *testing.T) {
	r := newRunFixture(t)
	r.serveUploads()
	a := r.attemptOf(t)
	var mu sync.Mutex
	var events []string
	var listed []Result
	a.Progress = Progress{
		Listed: func(rep Report) {
			mu.Lock()
			defer mu.Unlock()
			listed = slices.Clone(rep.Packages)
			events = append(events, "listed")
		},
		Ended: func(i int, res Result) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, fmt.Sprintf("ended %d %s %s", i, res.Name, res.State))
		},
	}
	rep := r.runAttempt(t, a)
	if rep.Outcome != OutcomeComplete {
		t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
	}
	want := []string{"listed", "ended 0 left-pad published", "ended 1 @scope/zeta published"}
	if !slices.Equal(events, want) {
		t.Fatalf("events %q, want %q", events, want)
	}
	if len(listed) != 2 {
		t.Fatalf("listed %+v", listed)
	}
	for _, p := range listed {
		if p.State != Pending || p.Name == "" || p.Version == "" || p.File == "" {
			t.Errorf("listed %+v, want a named pending package", p)
		}
	}
}

func TestRunAttemptReportsUnencrypted(t *testing.T) {
	r := newRunFixture(t)
	a := r.attemptOf(t)
	a.Unencrypted = true
	a.ExpectedSHA256 = wrongSHA256 // refused: no Nexus needed
	rep := r.runAttempt(t, a)
	if !rep.Unencrypted || rep.Archive.File != "packages_npm.tar.gz" {
		t.Fatalf("got %+v", rep)
	}
}

func TestRunAttemptCutsReasonsAtAThousandCharacters(t *testing.T) {
	long := strings.Repeat("é", 5000)

	t.Run("refusal", func(t *testing.T) {
		r := newRunFixture(t)
		a := r.attemptOf(t)
		a.Source.Archive = func(context.Context) (io.ReadCloser, error) {
			return nil, &archive.Refusal{Reason: long}
		}
		rep := r.runAttempt(t, a)
		if rep.Outcome != OutcomeRefused {
			t.Fatalf("outcome %q, want refused", rep.Outcome)
		}
		if got := len([]rune(rep.Reason)); got != 1000 {
			t.Errorf("refusal reason has %d characters, want 1000", got)
		}
	})

	t.Run("nexus failure", func(t *testing.T) {
		r := newRunFixture(t)
		a := r.attemptOf(t)
		if err := os.MkdirAll(a.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		rep := runAttempt(context.Background(), a, func(Settings) (Publisher, error) { return r.f.client(t), nil },
			func(_ context.Context, _ Publisher, pkgs []Package, _ string, _ func(int, Result)) []Result {
				out := make([]Result, len(pkgs))
				for i, p := range pkgs {
					out[i] = failed(p, KindNexus, long)
				}
				return out
			})
		if len(rep.Packages) == 0 {
			t.Fatal("no package in the report")
		}
		for _, p := range rep.Packages {
			if got := len([]rune(p.Reason)); got != 1000 {
				t.Errorf("%s: reason has %d characters, want 1000", p.Name, got)
			}
		}
	})
}

// counts holds how often an attempt opened each object. countOpens makes the
// manifest opener serve later on every call after the first, to show that a
// second read would see other bytes.
type counts struct{ manifest, signature, archive int }

func countOpens(a *Attempt, later []byte) *counts {
	n := &counts{}
	manifest, signature, arch := a.Source.Manifest, a.Source.Signature, a.Source.Archive
	a.Source.Manifest = func(ctx context.Context) (io.ReadCloser, error) {
		n.manifest++
		if n.manifest > 1 && later != nil {
			return io.NopCloser(bytes.NewReader(later)), nil
		}
		return manifest(ctx)
	}
	a.Source.Signature = func(ctx context.Context) (io.ReadCloser, error) { n.signature++; return signature(ctx) }
	a.Source.Archive = func(ctx context.Context) (io.ReadCloser, error) { n.archive++; return arch(ctx) }
	return n
}

func TestAttemptVerifiesBeforeParsing(t *testing.T) {
	other, _ := newTestKey()
	for name, tc := range map[string]struct {
		setup   func(t *testing.T, r *runFixture, a *Attempt)
		later   []byte // what a second read of the manifest would return
		outcome string
		reason  string
		want    counts
		checked bool
	}{
		"verifies, then a wrong sha256": {func(_ *testing.T, _ *runFixture, a *Attempt) { a.ExpectedSHA256 = wrongSHA256 },
			nil, OutcomeRefused, "differs from the expected sha256", counts{1, 1, 1}, false},
		"another key": {func(_ *testing.T, _ *runFixture, a *Attempt) {
			a.Settings.PublicKey, a.Settings.PublicKeySHA256 = other, archive.PublicKeySHA256(other)
		}, nil, OutcomeRefused, "the manifest is signed by another key, public key sha256 " + testPubSHA, counts{1, 1, 0}, false},
		"a broken manifest with a stale signature": {func(t *testing.T, r *runFixture, _ *Attempt) {
			if err := os.WriteFile(r.opts.Manifest, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, nil, OutcomeRefused, "the signature does not match the manifest", counts{1, 1, 0}, false},
		"a broken manifest, signed": {func(t *testing.T, r *runFixture, _ *Attempt) {
			if err := os.WriteFile(r.opts.Manifest, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			signManifest(t, r.opts.Manifest)
		}, nil, OutcomeRefused, "the manifest is not valid JSON", counts{1, 1, 0}, false},
		"the verified bytes are the parsed bytes": {func(_ *testing.T, r *runFixture, _ *Attempt) { r.serveUploads() },
			[]byte("{"), OutcomeComplete, "", counts{1, 1, 1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			a := r.attemptOf(t)
			tc.setup(t, r, &a)
			n := countOpens(&a, tc.later)
			rep := r.runAttempt(t, a)
			if rep.Outcome != tc.outcome || !strings.Contains(rep.Reason, tc.reason) {
				t.Fatalf("outcome %q reason %q, want %q containing %q", rep.Outcome, rep.Reason, tc.outcome, tc.reason)
			}
			if *n != tc.want {
				t.Errorf("opened manifest %d, signature %d, archive %d times; want %+v", n.manifest, n.signature, n.archive, tc.want)
			}
			if rep.ArchiveChecked == nil || *rep.ArchiveChecked != tc.checked {
				t.Errorf("archiveChecked %v, want %v", rep.ArchiveChecked, tc.checked)
			}
			if tc.outcome == OutcomeRefused && tc.want.archive == 0 && (rep.ToolVersion != "" || rep.AnalysisID != "" || rep.Archive.SHA256 != "") {
				t.Errorf("a refusal before the manifest is parsed reports manifest values: %+v", rep)
			}
		})
	}
}

// overrun serves spaces and fails once a reader asks for a byte past the
// first limit, so only a bounded read ends before the failure.
type overrun struct{ served, limit int }

func (o *overrun) Read(p []byte) (int, error) {
	if o.served >= o.limit {
		return 0, errors.New("read past the bound")
	}
	n := min(len(p), o.limit-o.served)
	for i := range n {
		p[i] = ' '
	}
	o.served += n
	return n, nil
}

func (o *overrun) Close() error { return nil }

func TestAttemptReadsAtMostOneByteOverTheSignatureBound(t *testing.T) {
	r := newRunFixture(t)
	a := r.attemptOf(t)
	body := &overrun{limit: archive.MaxSignatureSize + 1}
	a.Source.Signature = func(context.Context) (io.ReadCloser, error) { return body, nil }
	rep := r.runAttempt(t, a)
	if rep.Outcome != OutcomeRefused || !strings.Contains(rep.Reason, "it is larger than 4096 bytes") {
		t.Fatalf("outcome %q reason %q, want a refusal naming the 4096 bytes", rep.Outcome, rep.Reason)
	}
	if body.served > archive.MaxSignatureSize+1 {
		t.Errorf("read %d bytes of the signature, want at most %d", body.served, archive.MaxSignatureSize+1)
	}
}

func TestAttemptSignatureRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		signature func(context.Context) (io.ReadCloser, error)
		outcome   string
		reason    string
	}{
		"unsigned": {func(context.Context) (io.ReadCloser, error) { return nil, ErrUnsigned }, OutcomeRefused,
			"the archive is unsigned: manifest.json.sig is missing beside the manifest"},
		"unreadable": {func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("not json")), nil }, OutcomeRefused,
			"manifest.json.sig is not a signature this import reads: it is not a JSON object"},
		"over 4 KiB": {func(context.Context) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(strings.Repeat(" ", archive.MaxSignatureSize+1))), nil
		}, OutcomeRefused, "it is larger than 4096 bytes"},
		"the source failed": {func(context.Context) (io.ReadCloser, error) { return nil, fmt.Errorf("%w: gone", ErrSource) }, OutcomeIncomplete,
			"gone"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			a := r.attemptOf(t)
			a.Source.Signature = tc.signature
			rep := r.runAttempt(t, a)
			if rep.Outcome != tc.outcome || !strings.Contains(rep.Reason, tc.reason) {
				t.Fatalf("outcome %q reason %q, want %q containing %q", rep.Outcome, rep.Reason, tc.outcome, tc.reason)
			}
			if r.built != 0 || len(r.f.requests) != 0 {
				t.Errorf("publisher built %d times, %d requests", r.built, len(r.f.requests))
			}
		})
	}
}

// pipFixture is a signed pip archive of two wheels, a fake pypi Nexus and the
// settings that point at it.
type pipFixture struct {
	n        *importtest.PyPINexus
	files    importtest.PipFiles
	settings Settings
	wheels   []importtest.WheelFile
	// archiveErr, when set, is what opening the archive returns.
	archiveErr error
	// cancelOpen and cancelRead cancel the attempt as the archive is opened,
	// or as its first bytes are read.
	cancelOpen, cancelRead bool
	// wrap, when set, wraps the Nexus client the attempt builds.
	wrap func(Publisher) Publisher
}

// cancelOnRead cancels the attempt on each read and reads on, so only the
// attempt's own check of its context stops the archive's read.
type cancelOnRead struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnRead) Read(p []byte) (int, error) {
	c.cancel()
	return c.ReadCloser.Read(p)
}

func newPipFixture(t *testing.T) *pipFixture {
	t.Helper()
	n := importtest.NewPyPINexus(t, pipRepo)
	wheels := []importtest.WheelFile{
		importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any"),
		importtest.Wheel(t, "idna", "3.6", "py3-none-any"),
	}
	return &pipFixture{
		n: n, wheels: wheels,
		files: importtest.PipArchive(t, t.TempDir(), testPriv, wheels...),
		settings: Settings{
			NexusURL: n.URL, Repository: testRepo, User: "sealift-import", Password: Secret(testPassword),
			Pip:       &PipRepository{Repository: pipRepo, User: "sealift-import", Password: Secret(testPassword)},
			PublicKey: testPub, PublicKeySHA256: testPubSHA,
		},
	}
}

// clientFor builds the real Nexus client for s, as the commands do.
func clientFor(s Settings) (Publisher, error) {
	c, err := nexus.New(nexus.Config{URL: s.NexusURL, Repository: s.Repository, Format: nexus.Format(s.Format), User: s.User, Password: s.Password})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// attempt runs one attempt over p's files and counts the archive's opens.
func (p *pipFixture) attempt(t *testing.T, folder archive.Ecosystem, opts ...func(*Attempt)) (Report, int) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "work-1")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := Attempt{
		Settings: p.settings, Ecosystem: folder, ImportVersion: "0.7.0", Dir: dir,
		Source: fileSource(Options{Archive: p.files.Archive, Manifest: p.files.Manifest}),
	}
	a.Source.Name = archive.PipArchiveFile
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := 0
	open := a.Source.Archive
	a.Source.Archive = func(ctx context.Context) (io.ReadCloser, error) {
		opened++
		switch {
		case p.archiveErr != nil:
			return nil, p.archiveErr
		case p.cancelOpen:
			cancel()
			return nil, ctx.Err()
		}
		rc, err := open(ctx)
		if err != nil || !p.cancelRead {
			return rc, err
		}
		return cancelOnRead{rc, cancel}, nil
	}
	for _, o := range opts {
		o(&a)
	}
	newPublisher := clientFor
	if p.wrap != nil {
		newPublisher = func(s Settings) (Publisher, error) {
			c, err := clientFor(s)
			if err != nil {
				return nil, err
			}
			return p.wrap(c), nil
		}
	}
	return RunAttempt(ctx, a, newPublisher), opened
}

func TestPipAttemptRefusals(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	gone, err := url.Parse(closed.URL)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		setup   func(t *testing.T, p *pipFixture)
		folder  archive.Ecosystem
		outcome string
		reason  string // the report's reason, or every wheel's when incomplete
		kind    Kind
		read    bool // the archive was opened
	}{
		"no pip section": {
			setup:   func(_ *testing.T, p *pipFixture) { p.settings.Pip = nil },
			outcome: OutcomeRefused, reason: "the settings name no pip repository: set nexus.pip.repository",
		},
		"repository listed as npm hosted": {
			setup:   func(_ *testing.T, p *pipFixture) { p.n.SetRepository("npm", "hosted") },
			outcome: OutcomeRefused, reason: `nexus repository "pypi" is npm hosted, not pypi hosted`,
		},
		"repository absent": {
			setup:   func(_ *testing.T, p *pipFixture) { p.settings.Pip.Repository = "pypi-elsewhere" },
			outcome: OutcomeRefused, reason: `nexus repository "pypi-elsewhere" not found`,
		},
		"nexus unreachable": {
			setup:   func(_ *testing.T, p *pipFixture) { p.settings.NexusURL = gone },
			outcome: OutcomeIncomplete, reason: "repository check failed: ", kind: KindNexus,
		},
		"nexus refuses the credentials": {
			setup: func(_ *testing.T, p *pipFixture) {
				p.n.SetStatus("/service/rest/v1/repositories", http.StatusUnauthorized)
			},
			outcome: OutcomeIncomplete, reason: "repository check failed: nexus answered 401: status 401 from the fake", kind: KindNexus,
		},
		"the archive's source fails": {
			setup:   func(_ *testing.T, p *pipFixture) { p.archiveErr = fmt.Errorf("%w: minio answered 503", ErrSource) },
			outcome: OutcomeIncomplete, reason: "the archive's source failed: minio answered 503", kind: KindSource, read: true,
		},
		"cancelled while the archive is opened": {
			setup:   func(_ *testing.T, p *pipFixture) { p.cancelOpen = true },
			outcome: OutcomeIncomplete, reason: "interrupted", kind: KindInterrupted, read: true,
		},
		"cancelled while the archive is read": {
			setup:   func(_ *testing.T, p *pipFixture) { p.cancelRead = true },
			outcome: OutcomeIncomplete, reason: "interrupted", kind: KindInterrupted, read: true,
		},
		"pip manifest in the npm folder": {
			setup:   func(*testing.T, *pipFixture) {},
			folder:  archive.NPM,
			outcome: OutcomeRefused, reason: "the manifest describes a pip archive, and this folder takes npm archives: move the three files to packages/pip/",
		},
		"npm manifest in the pip folder": {
			setup: func(t *testing.T, p *pipFixture) {
				p.files.Archive, p.files.Manifest = testArchive(t, t.TempDir(), [3]string{"left-pad", "1.3.0", "left body"})
			},
			folder:  archive.Pip,
			outcome: OutcomeRefused, reason: "the manifest describes an npm archive, and this folder takes pip archives: move the three files to packages/npm/",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPipFixture(t)
			tc.setup(t, p)
			rep, opened := p.attempt(t, tc.folder)
			if rep.Outcome != tc.outcome {
				t.Fatalf("outcome %q (%s), want %q", rep.Outcome, rep.Reason, tc.outcome)
			}
			if (opened > 0) != tc.read {
				t.Errorf("the archive was opened %d times", opened)
			}
			if p.n.Uploads() != 0 {
				t.Errorf("%d uploads", p.n.Uploads())
			}
			if tc.outcome == OutcomeRefused {
				if rep.Reason != tc.reason {
					t.Errorf("reason %q, want %q", rep.Reason, tc.reason)
				}
				if len(rep.Packages) != 0 || rep.Counts != (Counts{}) {
					t.Errorf("a refused report lists %+v, counts %+v", rep.Packages, rep.Counts)
				}
				return
			}
			if len(rep.Packages) != len(p.wheels) || rep.Counts.Failed != len(p.wheels) {
				t.Fatalf("packages %+v, counts %+v", rep.Packages, rep.Counts)
			}
			for i, r := range rep.Packages {
				if r.State != Failed || r.Kind != tc.kind || !strings.HasPrefix(r.Reason, tc.reason) || r.File != p.wheels[i].File {
					t.Errorf("wheel %d: %+v, want failed %s %q", i, r, tc.kind, tc.reason)
				}
			}
			if rep.ArchiveChecked == nil || *rep.ArchiveChecked {
				t.Errorf("archiveChecked %v, want false", rep.ArchiveChecked)
			}
		})
	}
}

func TestPipAttemptPublishes(t *testing.T) {
	for _, folder := range []archive.Ecosystem{"", archive.Pip} {
		t.Run("folder "+string(folder), func(t *testing.T) {
			p := newPipFixture(t)
			var listed Report
			var checked bool
			var ended []Result
			rep, opened := p.attempt(t, folder, func(a *Attempt) {
				a.Progress = Progress{
					Listed:  func(r Report) { listed = r },
					Checked: func() { checked = true },
					Ended:   func(_ int, r Result) { ended = append(ended, r) },
				}
			})
			if rep.Outcome != OutcomeComplete || rep.ExitCode() != 0 {
				t.Fatalf("outcome %q (%s), packages %+v", rep.Outcome, rep.Reason, rep.Packages)
			}
			if opened != 1 || p.n.Uploads() != 2 || rep.Counts != (Counts{Published: 2}) {
				t.Errorf("opened %d, uploads %d, counts %+v", opened, p.n.Uploads(), rep.Counts)
			}
			if rep.Ecosystem != "pip" || rep.Target != (TargetInfo{OS: "linux", CPU: "x86_64", Python: "3.11.2", Glibc: "2.28"}) {
				t.Errorf("ecosystem %q, target %+v", rep.Ecosystem, rep.Target)
			}
			if rep.Nexus.Repository != pipRepo || rep.Archive.File != archive.PipArchiveFile || rep.ToolVersion != "0.7.0" || rep.AnalysisID != "20261120T091500Z" {
				t.Errorf("nexus %+v, archive %+v, tool %q, analysis %q", rep.Nexus, rep.Archive, rep.ToolVersion, rep.AnalysisID)
			}
			if rep.ArchiveChecked == nil || !*rep.ArchiveChecked || !checked {
				t.Errorf("archiveChecked %v, checked event %v", rep.ArchiveChecked, checked)
			}
			if listed.Ecosystem != "pip" || listed.Target.Python != "3.11.2" || len(listed.Packages) != 2 || listed.Packages[0].State != Pending {
				t.Errorf("listed %+v", listed)
			}
			if len(ended) != 2 || ended[0].State != Published || ended[1].State != Published {
				t.Errorf("ended %+v", ended)
			}
			for i, w := range p.wheels {
				if r := rep.Packages[i]; r.Name != w.Name || r.Version != w.Version || r.File != w.File || r.State != Published {
					t.Errorf("wheel %d: %+v", i, r)
				}
			}
		})
	}
}

// crossingReviewDoc is a signed review whose figures differ by how they
// count: two updates and three jumped packages, and three CVEs carried with
// a reason on two dependencies beside one carried without. Its names and
// versions read in npm and in pip.
func crossingReviewDoc() map[string]any {
	move := func(name string) map[string]any { return map[string]any{"name": name, "from": "1.0.0", "to": "2.0.0"} }
	left := func(dep, id, reason string) map[string]any {
		return map[string]any{"dependency": dep, "version": "1.0.0", "id": id, "severity": "HIGH", "package": dep, "fixedIn": "", "reason": reason}
	}
	return map[string]any{
		"project": "pdf-renderer",
		"cves":    map[string]any{"before": []any{1, 4, 6, 2, 0}, "after": []any{0, 1, 3, 1, 0}},
		"updates": []any{
			map[string]any{"name": "six", "from": "1.0.0", "to": "1.1.0", "fixed": []any{0, 1, 0, 0, 0}, "left": []any{0, 0, 0, 0, 0}},
			map[string]any{"name": "idna", "from": "3.6.0", "to": "3.7.0", "fixed": []any{1, 0, 0, 0, 0}, "left": []any{0, 0, 0, 0, 0}},
		},
		"kept": []any{},
		"jumps": []any{
			map[string]any{"family": "jinja 3", "packages": []any{move("jinja2"), move("markupsafe")}, "reason": "The templates moved to the next line."},
			map[string]any{"packages": []any{move("certifi")}, "reason": "The new line drops an old root."},
		},
		"left": []any{
			left("html5lib", "CVE-2024-0001", "No release fixes it; the parser reads our own pages only."),
			left("html5lib", "CVE-2024-0002", "No release fixes it; the parser reads our own pages only."),
			left("lxml", "CVE-2024-0003", "No release fixes it; the feature is off."),
			left("chardet", "CVE-2024-0004", ""),
		},
		"unchanged": 7,
	}
}

// wantCrossingReview is what the report keeps of crossingReviewDoc.
func wantCrossingReview() *CrossingReview {
	return &CrossingReview{Updated: 5, CVEsBefore: [5]int{1, 4, 6, 2, 0}, CVEsAfter: &[5]int{0, 1, 3, 1, 0}, Carried: 2, Jumps: 3}
}

// addReview writes review into the manifest at path and signs it again.
func addReview(t *testing.T, path string, review map[string]any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc["review"] = review
	if b, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	signManifest(t, path)
}

func TestAttemptKeepsTheCrossingAndTheReviewsFigures(t *testing.T) {
	t.Run("npm", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		addReview(t, r.opts.Manifest, crossingReviewDoc())
		a := r.attemptOf(t)
		var listed Report
		a.Progress.Listed = func(rep Report) { listed = rep }
		rep := r.runAttempt(t, a)
		if rep.Outcome != OutcomeComplete {
			t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
		}
		want := &Crossing{Project: "pdf-renderer", SealedAt: "2026-09-23T12:04:24Z", Packages: 2, Review: wantCrossingReview()}
		if !reflect.DeepEqual(rep.Crossing, want) {
			t.Errorf("crossing %+v, review %+v, want %+v, review %+v", rep.Crossing, reviewOf(rep.Crossing), want, want.Review)
		}
		if !reflect.DeepEqual(listed.Crossing, want) {
			t.Errorf("the listed report keeps the crossing %+v, want %+v", listed.Crossing, want)
		}
	})
	t.Run("pip", func(t *testing.T) {
		p := newPipFixture(t)
		addReview(t, p.files.Manifest, crossingReviewDoc())
		rep, _ := p.attempt(t, archive.Pip)
		if rep.Outcome != OutcomeComplete {
			t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
		}
		want := &Crossing{Project: "pdf-renderer", SealedAt: "2026-11-20T09:17:42Z", Packages: 2, Review: wantCrossingReview()}
		if !reflect.DeepEqual(rep.Crossing, want) {
			t.Errorf("crossing %+v, review %+v, want %+v, review %+v", rep.Crossing, reviewOf(rep.Crossing), want, want.Review)
		}
	})
	// A review whose project scan was never read has no after count. The
	// report keeps it absent, so no reader takes it for zero CVEs.
	noAfter := func() map[string]any {
		review := crossingReviewDoc()
		review["cves"] = map[string]any{"before": []any{1, 4, 6, 2, 0}}
		return review
	}
	checkNoAfter := func(t *testing.T, rep Report) {
		t.Helper()
		if rep.Outcome != OutcomeComplete {
			t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
		}
		want := wantCrossingReview()
		want.CVEsAfter = nil
		if got := reviewOf(rep.Crossing); !reflect.DeepEqual(got, want) {
			t.Errorf("review %+v, after %v, want %+v with no after count", got, afterOf(got), want)
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"cvesAfter"`) {
			t.Errorf("the report names an after count the review lacks: %s", b)
		}
	}
	t.Run("npm, a review with no after count", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		addReview(t, r.opts.Manifest, noAfter())
		checkNoAfter(t, r.runAttempt(t, r.attemptOf(t)))
	})
	t.Run("pip, a review with no after count", func(t *testing.T) {
		p := newPipFixture(t)
		addReview(t, p.files.Manifest, noAfter())
		rep, _ := p.attempt(t, archive.Pip)
		checkNoAfter(t, rep)
	})
}

// afterOf is r's after count, nil when r or its count is.
func afterOf(r *CrossingReview) *[5]int {
	if r == nil {
		return nil
	}
	return r.CVEsAfter
}

// reviewOf is c's review, nil when c is.
func reviewOf(c *Crossing) *CrossingReview {
	if c == nil {
		return nil
	}
	return c.Review
}

func TestAttemptKeepsNoCrossingBeforeTheSignatureVerifies(t *testing.T) {
	other, _ := newTestKey()
	for name, setup := range map[string]func(t *testing.T, r *runFixture, a *Attempt){
		"another key": func(_ *testing.T, _ *runFixture, a *Attempt) {
			a.Settings.PublicKey, a.Settings.PublicKeySHA256 = other, archive.PublicKeySHA256(other)
		},
		"a review changed after the signature": func(t *testing.T, r *runFixture, _ *Attempt) {
			sig, err := os.ReadFile(r.opts.Manifest + ".sig")
			if err != nil {
				t.Fatal(err)
			}
			review := crossingReviewDoc()
			review["unchanged"] = 8
			addReview(t, r.opts.Manifest, review)
			if err := os.WriteFile(r.opts.Manifest+".sig", sig, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unsigned": func(_ *testing.T, _ *runFixture, a *Attempt) {
			a.Source.Signature = func(context.Context) (io.ReadCloser, error) { return nil, ErrUnsigned }
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			addReview(t, r.opts.Manifest, crossingReviewDoc())
			a := r.attemptOf(t)
			setup(t, r, &a)
			rep := r.runAttempt(t, a)
			if rep.Outcome != OutcomeRefused {
				t.Fatalf("outcome %q (%s), want refused", rep.Outcome, rep.Reason)
			}
			if rep.Crossing != nil {
				t.Errorf("a refusal before the signature verifies keeps the crossing %+v", rep.Crossing)
			}
			b, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), `"crossing"`) || strings.Contains(string(b), "pdf-renderer") {
				t.Errorf("the refused report names the crossing: %s", b)
			}
		})
	}
	t.Run("pip, another key", func(t *testing.T) {
		p := newPipFixture(t)
		addReview(t, p.files.Manifest, crossingReviewDoc())
		p.settings.PublicKey, p.settings.PublicKeySHA256 = other, archive.PublicKeySHA256(other)
		rep, _ := p.attempt(t, archive.Pip)
		if rep.Outcome != OutcomeRefused || rep.Crossing != nil {
			t.Errorf("outcome %q, crossing %+v, want a refusal with no crossing", rep.Outcome, rep.Crossing)
		}
	})
}

func TestAttemptKeepsTheProjectOutOfAManifestWithNoReview(t *testing.T) {
	t.Run("npm", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		rep := r.runAttempt(t, r.attemptOf(t))
		want := &Crossing{SealedAt: "2026-09-23T12:04:24Z", Packages: 2}
		if rep.Outcome != OutcomeComplete || !reflect.DeepEqual(rep.Crossing, want) {
			t.Errorf("outcome %q, crossing %+v, want %+v", rep.Outcome, rep.Crossing, want)
		}
	})
	t.Run("pip", func(t *testing.T) {
		rep, _ := newPipFixture(t).attempt(t, archive.Pip)
		want := &Crossing{SealedAt: "2026-11-20T09:17:42Z", Packages: 2}
		if rep.Outcome != OutcomeComplete || !reflect.DeepEqual(rep.Crossing, want) {
			t.Errorf("outcome %q, crossing %+v, want %+v", rep.Outcome, rep.Crossing, want)
		}
	})
	t.Run("a review the import keeps out", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		review := crossingReviewDoc()
		review["unchanged"] = -1
		addReview(t, r.opts.Manifest, review)
		rep := r.runAttempt(t, r.attemptOf(t))
		want := &Crossing{SealedAt: "2026-09-23T12:04:24Z", Packages: 2}
		if rep.Outcome != OutcomeComplete || !reflect.DeepEqual(rep.Crossing, want) {
			t.Errorf("outcome %q, crossing %+v, want %+v", rep.Outcome, rep.Crossing, want)
		}
	})
}

func TestRunAttemptCancel(t *testing.T) {
	newFixture := func(t *testing.T) *runFixture {
		t.Helper()
		r := newRunFixture(t)
		r.opts.Archive, r.opts.Manifest = testArchive(t, r.archives,
			[3]string{"left-pad", "1.3.0", "left body"}, [3]string{"@scope/zeta", "2.0.0", "zeta body"}, [3]string{"right-pad", "1.0.0", "right body"})
		return r
	}
	t.Run("lets the package in flight finish and starts no other", func(t *testing.T) {
		r := newFixture(t)
		cancelled := make(chan struct{})
		r.f.onUpload = func(f *fakeNexus, u upload) {
			if info, err := npm.InspectTarball(bytes.NewReader(u.Body)); err == nil {
				f.put(info.Name, info.Version, u.Body)
			}
			// Nexus has stored the package and its answer has not left yet.
			if u.File == "left-pad-1.3.0.tgz" {
				close(cancelled)
			}
		}
		a := r.attemptOf(t)
		a.Progress.Cancelled = cancelled
		rep := r.runAttempt(t, a)
		if p := rep.Packages[0]; p.State != Published {
			t.Errorf("the package in flight = %+v, want published once read back", p)
		}
		for _, p := range rep.Packages[1:] {
			if p.State != Failed || p.Kind != KindInterrupted || p.Reason != reasonInterrupted {
				t.Errorf("%s after the cancel = %+v, want failed interrupted", p.Name, p)
			}
		}
		if n := r.f.uploadCount(); n != 1 {
			t.Errorf("%d uploads, want 1", n)
		}
		if rep.Outcome != OutcomeIncomplete || rep.Counts.Published != 1 || rep.Counts.Failed != 2 {
			t.Errorf("outcome %q, counts %+v", rep.Outcome, rep.Counts)
		}
	})
	t.Run("lets the wheel in flight finish and starts no other", func(t *testing.T) {
		p := newPipFixture(t)
		w := &cancelInFlight{cancel: make(chan struct{})}
		p.wrap = func(c Publisher) Publisher {
			w.Publisher = c
			return w
		}
		rep, _ := p.attempt(t, archive.Pip, func(a *Attempt) {
			a.Progress.Cancelled = w.cancel
			open := a.Source.Archive
			a.Source.Archive = func(ctx context.Context) (io.ReadCloser, error) {
				w.checks = ctx
				return open(ctx)
			}
		})
		if r := rep.Packages[0]; r.State != Published {
			t.Errorf("the wheel in flight = %+v, want published once read back", r)
		}
		if r := rep.Packages[1]; r.State != Failed || r.Kind != KindInterrupted || r.Reason != reasonInterrupted {
			t.Errorf("%s after the cancel = %+v, want failed interrupted", r.Name, r)
		}
		if n := p.n.Uploads(); n != 1 {
			t.Errorf("%d uploads, want 1", n)
		}
		if rep.Outcome != OutcomeIncomplete || rep.Counts.Published != 1 || rep.Counts.Failed != 1 {
			t.Errorf("outcome %q, counts %+v", rep.Outcome, rep.Counts)
		}
	})
	t.Run("stops the checks of an attempt cancelled before its first package", func(t *testing.T) {
		r := newFixture(t)
		cancelled := make(chan struct{})
		close(cancelled)
		a := r.attemptOf(t)
		a.Progress.Cancelled = cancelled
		rep := r.runAttempt(t, a)
		if rep.Outcome != OutcomeIncomplete || len(rep.Packages) != 3 || *rep.ArchiveChecked {
			t.Fatalf("outcome %q (%s), checked %v, packages %+v", rep.Outcome, rep.Reason, *rep.ArchiveChecked, rep.Packages)
		}
		for _, p := range rep.Packages {
			if p.State != Failed || p.Kind != KindInterrupted {
				t.Errorf("%s = %+v, want failed interrupted", p.Name, p)
			}
		}
		if r.f.mu.Lock(); len(r.f.requests) != 0 {
			t.Errorf("%d requests reached Nexus", len(r.f.requests))
		}
		r.f.mu.Unlock()
	})
}

// cancelInFlight cancels the attempt once Nexus has stored the first upload,
// and answers only after the cancel has ended checks, the context the archive
// was read on. An upload made on that context then fails, as one a cancel
// cut on the network would.
type cancelInFlight struct {
	Publisher
	cancel chan struct{}
	checks context.Context
	once   sync.Once
}

func (c *cancelInFlight) Upload(ctx context.Context, file string, r io.Reader) error {
	if err := c.Publisher.Upload(ctx, file, r); err != nil {
		return err
	}
	first := false
	c.once.Do(func() { first = true })
	if !first {
		return nil
	}
	close(c.cancel)
	select {
	case <-c.checks.Done():
	case <-time.After(10 * time.Second):
		return errors.New("the cancel never ended the checks")
	}
	return ctx.Err()
}
