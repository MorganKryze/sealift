package importer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/MorganKryze/sealift/archive"
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
