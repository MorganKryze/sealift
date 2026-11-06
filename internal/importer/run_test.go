package importer

import (
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runFixture is one archive, one fake Nexus and the settings that point at it.
type runFixture struct {
	f        *fakeNexus
	opts     Options
	built    int // calls of the publisher factory
	archives string
}

func newRunFixture(t *testing.T) *runFixture {
	t.Helper()
	f := newFakeNexus(t)
	u, _ := url.Parse(f.srv.URL)
	dir := t.TempDir()
	arch, manifest := testArchive(t, dir, testKey, [3]string{"left-pad", "1.3.0", "left body"}, [3]string{"@scope/zeta", "2.0.0", "zeta body"})
	return &runFixture{f: f, archives: dir, opts: Options{
		Settings: Settings{NexusURL: u, Repository: testRepo, User: "sealift-import", Password: Secret(testPassword), SignatureKey: Secret(testKey)},
		Archive:  arch, Manifest: manifest, ImportVersion: "0.3.0",
	}}
}

func (r *runFixture) run(t *testing.T) Report {
	t.Helper()
	return Run(context.Background(), r.opts, func(Settings) (Publisher, error) {
		r.built++
		return r.f.client(t), nil
	})
}

func (r *runFixture) serveUploads() {
	r.f.onUpload = func(f *fakeNexus, u upload) {
		switch u.File {
		case "left-pad-1.3.0.tgz":
			f.put("left-pad", "1.3.0", u.Body)
		default:
			f.put("@scope/zeta", "2.0.0", u.Body)
		}
	}
}

func TestRunRemovesTempDir(t *testing.T) {
	for name, tc := range map[string]struct {
		setup   func(r *runFixture)
		outcome string
	}{
		"complete":   {func(r *runFixture) { r.serveUploads() }, "complete"},
		"incomplete": {func(r *runFixture) { r.f.postStatus = 500 }, "incomplete"},
		"refused":    {func(r *runFixture) { r.opts.Settings.SignatureKey = Secret("other-key") }, "refused"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			tmp := filepath.Join(t.TempDir(), "tmp")
			if err := os.Mkdir(tmp, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", tmp)
			tc.setup(r)
			rep := r.run(t)
			if rep.Outcome != tc.outcome {
				t.Fatalf("outcome %q (%s), want %q", rep.Outcome, rep.Reason, tc.outcome)
			}
			left, err := os.ReadDir(tmp)
			if err != nil || len(left) != 0 {
				t.Fatalf("temporary directory holds %v, %v", left, err)
			}
		})
	}
}

func TestRefusedArchivePublishesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(t *testing.T, r *runFixture)
		reason string
	}{
		"wrong key": {func(_ *testing.T, r *runFixture) { r.opts.Settings.SignatureKey = Secret("other-key") }, "signature.key differs from the expected value"},
		"damaged archive": {func(t *testing.T, r *runFixture) {
			b, _ := os.ReadFile(r.opts.Archive)
			b[len(b)/2] ^= 0xff
			if err := os.WriteFile(r.opts.Archive, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "archive"},
		"expected sha256": {func(_ *testing.T, r *runFixture) { r.opts.ExpectedSHA256 = strings.Repeat("ab", 32) }, "differs from the expected sha256"},
		"manifest missing fields": {func(t *testing.T, r *runFixture) {
			if err := os.WriteFile(r.opts.Manifest, []byte(`{"formatVersion":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "toolVersion is missing"},
		"archive absent": {func(_ *testing.T, r *runFixture) { r.opts.Archive = filepath.Join(r.archives, "absent.tar.gz") }, "could not check the archive:"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			tc.change(t, r)
			rep := r.run(t)
			if rep.Outcome != "refused" || !strings.Contains(rep.Reason, tc.reason) {
				t.Fatalf("got %q: %q, want refused containing %q", rep.Outcome, rep.Reason, tc.reason)
			}
			if r.built != 0 || len(r.f.requests) != 0 || r.f.uploadCount() != 0 {
				t.Errorf("publisher built %d times, %d requests, %d uploads", r.built, len(r.f.requests), r.f.uploadCount())
			}
			if rep.ExitCode() != 3 {
				t.Errorf("exit code %d", rep.ExitCode())
			}
		})
	}
}

func TestRunLeavesInputUntouched(t *testing.T) {
	r := newRunFixture(t)
	r.serveUploads()
	before, _ := os.ReadFile(r.opts.Archive)
	r.run(t)
	after, _ := os.ReadFile(r.opts.Archive)
	if string(before) != string(after) {
		t.Fatal("the archive changed")
	}
	left, _ := filepath.Glob(filepath.Join(r.archives, "*"))
	if len(left) != 2 {
		t.Fatalf("directory holds %v", left)
	}
}

func TestRunPublisherSetupFails(t *testing.T) {
	r := newRunFixture(t)
	rep := Run(context.Background(), r.opts, func(Settings) (Publisher, error) { return nil, os.ErrPermission })
	if rep.Outcome != "incomplete" || rep.Counts.Failed != 2 || !strings.Contains(rep.Packages[0].Reason, "could not set up the nexus client") {
		t.Fatalf("got %+v", rep)
	}
}

func TestRunNotesStrippedPublishConfig(t *testing.T) {
	r := newRunFixture(t)
	// The manifest says the second package was rewritten, so its original
	// integrity is not compared and the report carries a note.
	b, _ := os.ReadFile(r.opts.Manifest)
	s := strings.Replace(string(b), `"publishConfigStripped":false`, `"publishConfigStripped":true`, 2)
	if err := os.WriteFile(r.opts.Manifest, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	r.serveUploads()
	rep := r.run(t)
	if rep.Outcome != "complete" || !strings.Contains(rep.Packages[0].Note, "publishConfig") {
		t.Fatalf("got %+v", rep)
	}
}

func TestRunKeepsNoteFromPublish(t *testing.T) {
	const kept = "same content, packed differently"
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"note set by publish is kept": {Result{State: Present, Note: kept}, kept},
		"empty note gets the default": {Result{State: Published}, "sealift removed publishConfig at export"},
		"failed package has no note":  {Result{State: Failed, Reason: "upload failed: x"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunFixture(t)
			b, _ := os.ReadFile(r.opts.Manifest)
			s := strings.Replace(string(b), `"publishConfigStripped":false`, `"publishConfigStripped":true`, 2)
			if err := os.WriteFile(r.opts.Manifest, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
			fake := func(_ context.Context, _ Publisher, pkgs []Package, _ string) []Result {
				out := make([]Result, len(pkgs))
				for i, p := range pkgs {
					out[i] = tc.result
					out[i].Name, out[i].Version, out[i].File = p.Name, p.Version, p.File
				}
				return out
			}
			rep := run(context.Background(), r.opts, func(Settings) (Publisher, error) { return r.f.client(t), nil }, fake)
			if len(rep.Packages) != 2 {
				t.Fatalf("got %+v", rep)
			}
			for _, p := range rep.Packages {
				if p.Note != tc.want {
					t.Errorf("%s note %q, want %q", p.Name, p.Note, tc.want)
				}
			}
		})
	}
}

// newInterruptFixture builds an archive of three packages and a fake that
// holds the second upload until the test releases it.
func newInterruptFixture(t *testing.T) (r *runFixture, held chan struct{}) {
	t.Helper()
	r = newRunFixture(t)
	arch, manifest := testArchive(t, r.archives, testKey,
		[3]string{"left-pad", "1.3.0", "left body"}, [3]string{"@scope/zeta", "2.0.0", "zeta body"}, [3]string{"right-pad", "1.0.0", "right body"})
	r.opts.Archive, r.opts.Manifest = arch, manifest
	held, release := make(chan struct{}), make(chan struct{})
	r.f.onUpload = func(f *fakeNexus, u upload) {
		if u.File == "left-pad-1.3.0.tgz" {
			f.put("left-pad", "1.3.0", u.Body)
			return
		}
		close(held)
		<-release
	}
	// Registered after the fake, so it runs first and frees the held handler.
	t.Cleanup(func() { close(release) })
	return r, held
}

func TestRunInterrupted(t *testing.T) {
	t.Run("during an upload", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		r, held := newInterruptFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan Report, 1)
		go func() {
			done <- Run(ctx, r.opts, func(Settings) (Publisher, error) { return r.f.client(t), nil })
		}()
		<-held
		r.f.mu.Lock()
		atCancel := len(r.f.requests)
		r.f.mu.Unlock()
		cancel()
		rep := <-done

		if rep.Outcome != OutcomeIncomplete || rep.ExitCode() != 1 {
			t.Fatalf("outcome %q (%s), exit %d", rep.Outcome, rep.Reason, rep.ExitCode())
		}
		if len(rep.Packages) != 3 || rep.Packages[0].State != Published {
			t.Fatalf("got %+v", rep.Packages)
		}
		for _, p := range rep.Packages[1:] {
			if p.State != Failed || p.Reason != "interrupted" {
				t.Errorf("%s: %q %q, want failed interrupted", p.Name, p.State, p.Reason)
			}
		}
		if rep.Counts.Published != 1 || rep.Counts.Failed != 2 {
			t.Errorf("counts %+v", rep.Counts)
		}
		r.f.mu.Lock()
		after := len(r.f.requests)
		r.f.mu.Unlock()
		if after != atCancel {
			t.Errorf("%d requests started after the cancel", after-atCancel)
		}
		if left, err := os.ReadDir(tmp); err != nil || len(left) != 0 {
			t.Errorf("temporary directory holds %v, %v", left, err)
		}
	})

	t.Run("during the checks", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		r, _ := newInterruptFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rep := Run(ctx, r.opts, func(Settings) (Publisher, error) {
			r.built++
			return r.f.client(t), nil
		})
		if rep.Outcome != OutcomeIncomplete || rep.ExitCode() != 1 || len(rep.Packages) != 3 || rep.Counts.Failed != 3 {
			t.Fatalf("got %q %+v", rep.Outcome, rep.Counts)
		}
		for _, p := range rep.Packages {
			if p.State != Failed || p.Reason != "interrupted" {
				t.Errorf("%s: %q %q, want failed interrupted", p.Name, p.State, p.Reason)
			}
		}
		if r.built != 0 || len(r.f.requests) != 0 {
			t.Errorf("publisher built %d times, %d requests", r.built, len(r.f.requests))
		}
		if left, err := os.ReadDir(tmp); err != nil || len(left) != 0 {
			t.Errorf("temporary directory holds %v, %v", left, err)
		}
	})
}

// cancelOnFetch ignores its context and cancels it on the first Fetch, so
// only the check between packages can stop the loop.
type cancelOnFetch struct {
	cancel context.CancelFunc
	calls  int
}

func (c *cancelOnFetch) CheckRepository(context.Context) error { return nil }

func (c *cancelOnFetch) Fetch(context.Context, string, string, io.Writer, int64) (bool, error) {
	c.calls++
	c.cancel()
	return false, context.Canceled
}

func (c *cancelOnFetch) Upload(context.Context, string, io.Reader) error {
	c.calls++
	return nil
}

func TestPublishStopsBetweenPackages(t *testing.T) {
	dir := t.TempDir()
	pkgs := []Package{
		stage(t, dir, "a", "1.0.0", []byte("a")),
		stage(t, dir, "b", "1.0.0", []byte("b")),
		stage(t, dir, "c", "1.0.0", []byte("c")),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pub := &cancelOnFetch{cancel: cancel}
	results := Publish(ctx, pub, pkgs, t.TempDir())
	if pub.calls != 1 {
		t.Errorf("%d calls reached the publisher, want 1", pub.calls)
	}
	for i, r := range results {
		if r.State != Failed || r.Reason != "interrupted" {
			t.Errorf("package %d: %q %q, want failed interrupted", i, r.State, r.Reason)
		}
	}
}

func TestPublishCheckInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFakeNexus(t)
	pkgs := []Package{stage(t, t.TempDir(), "a", "1.0.0", []byte("a"))}
	results := Publish(ctx, f.client(t), pkgs, t.TempDir())
	if results[0].Reason != "interrupted" {
		t.Fatalf("reason %q", results[0].Reason)
	}
	if len(f.requests) != 0 {
		t.Errorf("%d requests", len(f.requests))
	}
}
