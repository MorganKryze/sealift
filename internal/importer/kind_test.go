package importer

import (
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
)

// stubPublisher is a Publisher whose three calls are set per test; a nil
// call answers as a Nexus that holds nothing and accepts everything.
type stubPublisher struct {
	check  func(context.Context) error
	fetch  func(context.Context) (bool, error)
	upload func(context.Context) error
}

func (s stubPublisher) CheckRepository(ctx context.Context) error {
	if s.check != nil {
		return s.check(ctx)
	}
	return nil
}

func (s stubPublisher) Fetch(ctx context.Context, _, _ string, _ io.Writer, _ int64) (bool, error) {
	if s.fetch != nil {
		return s.fetch(ctx)
	}
	return false, nil
}

func (s stubPublisher) Upload(ctx context.Context, _ string, _ io.Reader) error {
	if s.upload != nil {
		return s.upload(ctx)
	}
	return nil
}

func TestFailureKinds(t *testing.T) {
	one := func(t *testing.T, f *fakeNexus, pkg Package) Result {
		t.Helper()
		return Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())[0]
	}
	for name, tc := range map[string]struct {
		run    func(t *testing.T) Result
		state  State
		kind   Kind
		reason string
	}{
		"other bytes before the upload": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			f.put("left-pad", "1.0.0", packed(t, "left-pad", "1.0.0", "other"))
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Failed, KindConflict, "nexus holds this version with other bytes"},
		"repository check refused": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			f.repoStatus = 401
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Failed, KindNexus, "repository check failed"},
		"upload answered 500": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			f.postStatus = 500
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Failed, KindNexus, "upload failed"},
		"read back answered 502": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			p := tarballPath("left-pad", "1.0.0")
			f.onUpload = func(f *fakeNexus, _ upload) {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.getStatus[p] = 502
			}
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Failed, KindNexus, "read back failed"},
		"accepted but not served": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Failed, KindNexus, "does not serve the version"},
		"other bytes after the upload": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			f.onUpload = func(f *fakeNexus, _ upload) { f.put("left-pad", "1.0.0", packed(t, "left-pad", "1.0.0", "tampered")) }
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Failed, KindNexus, "after the upload"},
		"tarball of another name": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			if err := os.WriteFile(pkg.Path, packed(t, "right-pad", "1.0.0", "x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return one(t, f, pkg)
		}, Failed, KindMismatch, "the tarball is"},
		"checked file removed before the upload": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			if err := os.Remove(pkg.Path); err != nil {
				t.Fatal(err)
			}
			return one(t, f, pkg)
		}, Failed, KindLocal, "cannot open the checked file"},
		"nexus copy cannot be kept": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			missing := filepath.Join(t.TempDir(), "absent")
			return Publish(context.Background(), f.client(t), []Package{pkg}, missing)[0]
		}, Failed, KindLocal, "cannot keep the nexus copy"},
		"cancelled before the package starts": {func(t *testing.T) Result {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			return Publish(ctx, stubPublisher{}, []Package{pkg}, t.TempDir())[0]
		}, Failed, KindInterrupted, "interrupted"},
		"cancelled during the repository check": {func(t *testing.T) Result {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			pub := stubPublisher{check: func(context.Context) error { cancel(); return context.Canceled }}
			return Publish(ctx, pub, []Package{pkg}, t.TempDir())[0]
		}, Failed, KindInterrupted, "interrupted"},
		"cancelled during an upload": {func(t *testing.T) Result {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			pub := stubPublisher{upload: func(context.Context) error { cancel(); return context.Canceled }}
			return Publish(ctx, pub, []Package{pkg}, t.TempDir())[0]
		}, Failed, KindInterrupted, "interrupted"},
		"published": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
			f.storeUploads(pkg)
			return one(t, f, pkg)
		}, Published, "", ""},
		"present": {func(t *testing.T) Result {
			f := newFakeNexus(t)
			f.put("left-pad", "1.0.0", packed(t, "left-pad", "1.0.0", "shipped"))
			return one(t, f, stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped")))
		}, Present, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := tc.run(t)
			if r.State != tc.state || r.Kind != tc.kind {
				t.Fatalf("state %q kind %q (%s), want %q and %q", r.State, r.Kind, r.Reason, tc.state, tc.kind)
			}
			if tc.state == Failed && !strings.Contains(r.Reason, tc.reason) {
				t.Errorf("reason %q lacks %q", r.Reason, tc.reason)
			}
			if tc.kind == KindInterrupted && r.Reason != "interrupted" {
				t.Errorf("reason %q, want interrupted", r.Reason)
			}
		})
	}
}

func TestRunAttemptKinds(t *testing.T) {
	cutErr := fmt.Errorf("%w: connection reset by peer", ErrSource)
	for name, tc := range map[string]struct {
		change    func(r *runFixture, a *Attempt)
		cancelled bool
		noClient  bool
		kind      Kind
	}{
		"archive cut partway": {func(r *runFixture, a *Attempt) {
			arch, _ := os.ReadFile(r.opts.Archive)
			a.Source.Archive = func(context.Context) (io.ReadCloser, error) { return cutReader(arch, len(arch)/2, cutErr), nil }
		}, false, false, KindSource},
		"nexus client cannot be built": {func(*runFixture, *Attempt) {}, false, true, KindLocal},
		"cancelled during the checks": {func(_ *runFixture, a *Attempt) {
			a.Source.Archive = func(ctx context.Context) (io.ReadCloser, error) { return nil, ctx.Err() }
		}, true, false, KindInterrupted},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			a := r.attemptOf(t)
			newPub := func(Settings) (Publisher, error) {
				if tc.noClient {
					return nil, errors.New("no client")
				}
				return r.f.client(t), nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			tc.change(r, &a)
			if err := os.MkdirAll(a.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			rep := RunAttempt(ctx, a, newPub)
			if rep.Outcome != OutcomeIncomplete || len(rep.Packages) != 2 {
				t.Fatalf("outcome %q (%s), %d packages", rep.Outcome, rep.Reason, len(rep.Packages))
			}
			for _, p := range rep.Packages {
				if p.State != Failed || p.Kind != tc.kind {
					t.Errorf("%s: state %q kind %q, want failed %q", p.Name, p.State, p.Kind, tc.kind)
				}
			}
		})
	}
}

func TestArchiveCheckedMark(t *testing.T) {
	for name, tc := range map[string]struct {
		setup   func(r *runFixture, a *Attempt)
		outcome string
		checked bool
	}{
		"refused at the manifest": {func(_ *runFixture, a *Attempt) {
			a.Source.Manifest = func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("{")), nil }
		}, OutcomeRefused, false},
		"refused at the checks": {func(_ *runFixture, a *Attempt) { a.Settings.SignatureKey = Secret("other-key") }, OutcomeRefused, false},
		"complete":              {func(r *runFixture, _ *Attempt) { r.serveUploads() }, OutcomeComplete, true},
		"incomplete":            {func(r *runFixture, _ *Attempt) { r.f.postStatus = 500 }, OutcomeIncomplete, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			a := r.attemptOf(t)
			tc.setup(r, &a)
			rep := r.runAttempt(t, a)
			if rep.Outcome != tc.outcome {
				t.Fatalf("outcome %q (%s), want %q", rep.Outcome, rep.Reason, tc.outcome)
			}
			if rep.ArchiveChecked == nil || *rep.ArchiveChecked != tc.checked {
				t.Errorf("archiveChecked %v, want %v", rep.ArchiveChecked, tc.checked)
			}
		})
	}

	t.Run("hooks run in order", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		a := r.attemptOf(t)
		var mu sync.Mutex
		var events []string
		note := func(s string) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, s)
		}
		a.Progress = Progress{
			Listed:  func(Report) { note("listed") },
			Checked: func() { note("checked") },
			Ended:   func(i int, _ Result) { note(fmt.Sprintf("ended %d", i)) },
		}
		r.runAttempt(t, a)
		if want := []string{"listed", "checked", "ended 0", "ended 1"}; !slices.Equal(events, want) {
			t.Fatalf("events %q, want %q", events, want)
		}
	})

	t.Run("not called when the checks fail", func(t *testing.T) {
		r := newRunFixture(t)
		a := r.attemptOf(t)
		a.Settings.SignatureKey = Secret("other-key")
		var calls int
		a.Progress = Progress{Checked: func() { calls++ }}
		r.runAttempt(t, a)
		if calls != 0 {
			t.Errorf("Checked called %d times for a refused archive", calls)
		}
	})
}

func TestListedStoresNoOutcome(t *testing.T) {
	r := newRunFixture(t)
	r.serveUploads()
	a := r.attemptOf(t)
	var snap Report
	a.Progress = Progress{Listed: func(rep Report) { snap = rep }}
	rep := r.runAttempt(t, a)
	if rep.Outcome != OutcomeComplete {
		t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
	}
	if snap.Outcome != "" || snap.Reason != "" {
		t.Errorf("listed report has outcome %q and reason %q, want neither", snap.Outcome, snap.Reason)
	}
	if snap.Target.OS != "linux" || snap.Archive.File != "packages_npm.tar.gz" || snap.Archive.SHA256 == "" || snap.Nexus.Repository != testRepo || snap.Nexus.URL == "" {
		t.Errorf("listed report lacks the target, archive or nexus: %+v", snap)
	}
	if len(snap.Packages) != 2 || snap.Counts != (Counts{}) {
		t.Fatalf("listed packages %+v, counts %+v", snap.Packages, snap.Counts)
	}
	for _, p := range snap.Packages {
		if p.State != Pending || p.Kind != "" {
			t.Errorf("%s: %q %q, want pending with no kind", p.Name, p.State, p.Kind)
		}
	}
	// The later mark must not reach back into the copy handed out.
	if snap.ArchiveChecked == nil || *snap.ArchiveChecked {
		t.Errorf("listed archiveChecked %v, want false", snap.ArchiveChecked)
	}
}
