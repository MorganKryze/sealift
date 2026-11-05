package importer

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hexOf(p Package) string { return hex.EncodeToString(p.SHA512) }

func TestPublishStopsWhenRepositoryCheckFails(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(f *fakeNexus)
		want  string
	}{
		"credentials refused": {func(f *fakeNexus) { f.repoStatus = 401 }, "401"},
		"repository missing":  {func(f *fakeNexus) { f.repoBody = `[{"name":"other","format":"npm","type":"hosted"}]` }, `"npm-hosted" not found`},
		"wrong format":        {func(f *fakeNexus) { f.repoBody = `[{"name":"npm-hosted","format":"maven2","type":"hosted"}]` }, "maven2 hosted"},
		"unreachable":         {func(f *fakeNexus) { f.srv.Close() }, "unreachable"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeNexus(t)
			tc.setup(f)
			stageDir := t.TempDir()
			pkgs := []Package{stage(t, stageDir, "left-pad", "1.0.0", []byte("one")), stage(t, stageDir, "right-pad", "2.0.0", []byte("two"))}
			res := Publish(context.Background(), f.client(t), pkgs, t.TempDir())
			if len(res) != 2 {
				t.Fatalf("got %d results", len(res))
			}
			for _, r := range res {
				if r.State != Failed || !strings.Contains(r.Reason, tc.want) {
					t.Errorf("%s: state %s reason %q, want failed with %q", r.Name, r.State, r.Reason, tc.want)
				}
			}
			if n := f.uploadCount(); n != 0 {
				t.Errorf("%d uploads", n)
			}
		})
	}
}

func TestPublishPresentSameBytes(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("same bytes"))
	f.put("left-pad", "1.0.0", []byte("same bytes"))
	res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
	if res[0].State != Present || res[0].Reason != "" {
		t.Fatalf("got %+v", res[0])
	}
	if n := f.uploadCount(); n != 0 {
		t.Fatalf("%d uploads", n)
	}
}

func TestPublishOtherBytesFails(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
	f.put("left-pad", "1.0.0", []byte("other"))
	other := stage(t, t.TempDir(), "x", "1.0.0", []byte("other"))
	res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
	r := res[0]
	if r.State != Failed || !strings.Contains(r.Reason, "other bytes") || !strings.Contains(r.Reason, hexOf(pkg)) || !strings.Contains(r.Reason, hexOf(other)) {
		t.Fatalf("got %+v", r)
	}
	if n := f.uploadCount(); n != 0 {
		t.Fatalf("%d uploads", n)
	}
}

func TestPublishReadBack(t *testing.T) {
	t.Run("same bytes read back", func(t *testing.T) {
		f := newFakeNexus(t)
		pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
		f.storeUploads(pkg)
		res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
		if res[0].State != Published {
			t.Fatalf("got %+v", res[0])
		}
		if f.uploads[0].Field != "npm.asset" || f.uploads[0].File != pkg.File || string(f.uploads[0].Body) != "shipped" {
			t.Fatalf("upload = %+v", f.uploads[0])
		}
	})
	t.Run("other bytes served", func(t *testing.T) {
		f := newFakeNexus(t)
		pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
		other := stage(t, t.TempDir(), "x", "1.0.0", []byte("tampered"))
		f.onUpload = func(f *fakeNexus, _ upload) { f.put("left-pad", "1.0.0", []byte("tampered")) }
		res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
		r := res[0]
		if r.State != Failed || !strings.Contains(r.Reason, "after the upload") || !strings.Contains(r.Reason, hexOf(pkg)) || !strings.Contains(r.Reason, hexOf(other)) {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("nothing served", func(t *testing.T) {
		f := newFakeNexus(t)
		pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
		res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
		if res[0].State != Failed || !strings.Contains(res[0].Reason, "does not serve") {
			t.Fatalf("got %+v", res[0])
		}
	})
}

func TestPublishNexusError(t *testing.T) {
	f := newFakeNexus(t)
	dir := t.TempDir()
	first := stage(t, dir, "aaa", "1.0.0", []byte("a"))
	cut := stage(t, dir, "bbb", "1.0.0", []byte("b"))
	last := stage(t, dir, "ccc", "1.0.0", []byte("c"))
	f.drop[tarballPath("bbb", "1.0.0")] = true
	f.postStatus = 500
	f.postBody = strings.Repeat("abcd\x00\x1b\n", 300)
	// Only the first package reaches the upload that answers 500.
	f.getStatus[tarballPath("ccc", "1.0.0")] = 502
	f.getBody[tarballPath("ccc", "1.0.0")] = "bad gateway"
	res := Publish(context.Background(), f.client(t), []Package{first, cut, last}, t.TempDir())

	want := strings.Repeat("abcd", 100)[:300]
	if r := res[0]; r.State != Failed || !strings.Contains(r.Reason, "500") || !strings.Contains(r.Reason, want) || strings.Contains(r.Reason, want+"a") || strings.ContainsAny(r.Reason, "\x00\x1b\n") {
		t.Errorf("upload error: %+v", r)
	}
	if r := res[1]; r.State != Failed || !strings.Contains(r.Reason, "unreachable") {
		t.Errorf("unreachable: %+v", r)
	}
	if r := res[2]; r.State != Failed || !strings.Contains(r.Reason, "502") || !strings.Contains(r.Reason, "bad gateway") {
		t.Errorf("last package still runs: %+v", r)
	}
}

func TestPublishOrderAndOneState(t *testing.T) {
	f := newFakeNexus(t)
	dir := t.TempDir()
	pub := stage(t, dir, "@scope/zeta", "1.0.0", []byte("zeta"))
	pre := stage(t, dir, "alpha", "2.0.0", []byte("alpha"))
	bad := stage(t, dir, "mid", "3.0.0", []byte("mid"))
	f.put("alpha", "2.0.0", []byte("alpha"))
	f.put("mid", "3.0.0", []byte("not mid"))
	f.storeUploads(pub)
	res := Publish(context.Background(), f.client(t), []Package{pub, pre, bad}, t.TempDir())
	if len(res) != 3 {
		t.Fatalf("got %d results", len(res))
	}
	for i, want := range []struct {
		pkg   Package
		state State
	}{{pub, Published}, {pre, Present}, {bad, Failed}} {
		r := res[i]
		if r.Name != want.pkg.Name || r.Version != want.pkg.Version || r.File != want.pkg.File || r.State != want.state {
			t.Errorf("result %d = %+v, want %s %s", i, r, want.pkg.Name, want.state)
		}
		if (r.State == Failed) != (r.Reason != "") {
			t.Errorf("result %d: reason %q with state %s", i, r.Reason, r.State)
		}
	}
	if n := f.uploadCount(); n != 1 {
		t.Errorf("%d uploads, want 1", n)
	}
}

func TestPublishRehashesBeforeUpload(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("checked"))
	// The file changes while Nexus is being asked, after the checks.
	f.onGet = func(string) {
		if err := os.WriteFile(pkg.Path, []byte("swapped"), 0o600); err != nil {
			t.Error(err)
		}
	}
	swapped := stage(t, t.TempDir(), "x", "1.0.0", []byte("swapped"))
	res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
	r := res[0]
	if r.State != Failed || !strings.Contains(r.Reason, "changed after the checks") || !strings.Contains(r.Reason, hexOf(pkg)) || !strings.Contains(r.Reason, hexOf(swapped)) {
		t.Fatalf("got %+v", r)
	}
	if n := f.uploadCount(); n != 0 {
		t.Fatalf("%d uploads", n)
	}
}

func TestPublishLeavesNoCopyBehind(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
	f.storeUploads(pkg)
	dir := t.TempDir()
	Publish(context.Background(), f.client(t), []Package{pkg}, dir)
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

func TestPublishSendsCredentials(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
	f.storeUploads(pkg)
	Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
	if len(f.requests) < 4 {
		t.Fatalf("%d requests", len(f.requests))
	}
	for _, r := range f.requests {
		if !strings.HasPrefix(r.Auth, "Basic ") {
			t.Errorf("%s %s sent no basic auth", r.Method, r.Path)
		}
	}
	last := f.requests[len(f.requests)-1]
	if last.Method != "GET" || last.Path != tarballPath("left-pad", "1.0.0") {
		t.Errorf("last request = %+v", last)
	}
}
