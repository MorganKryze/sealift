package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
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
	f.put("left-pad", "1.0.0", packed(t, "left-pad", "1.0.0", "same bytes"))
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
	f.put("left-pad", "1.0.0", packed(t, "left-pad", "1.0.0", "other"))
	other := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("other"))
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
		if f.uploads[0].Field != "npm.asset" || f.uploads[0].File != pkg.File || !bytes.Equal(f.uploads[0].Body, packed(t, "left-pad", "1.0.0", "shipped")) {
			t.Fatalf("upload = %+v", f.uploads[0])
		}
	})
	t.Run("other bytes served", func(t *testing.T) {
		f := newFakeNexus(t)
		pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("shipped"))
		other := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("tampered"))
		f.onUpload = func(f *fakeNexus, _ upload) { f.put("left-pad", "1.0.0", packed(t, "left-pad", "1.0.0", "tampered")) }
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
	f.put("alpha", "2.0.0", packed(t, "alpha", "2.0.0", "alpha"))
	f.put("mid", "3.0.0", packed(t, "mid", "3.0.0", "not mid"))
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
	swapped := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("swapped"))
	f.onGet = func(string) {
		data, err := os.ReadFile(swapped.Path)
		if err == nil {
			err = os.WriteFile(pkg.Path, data, 0o600)
		}
		if err != nil {
			t.Error(err)
		}
	}
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

func TestPublishCutsOversizedNexusCopy(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", []byte("one"))
	shipped, err := os.Stat(pkg.Path)
	if err != nil {
		t.Fatal(err)
	}
	// The bound is twice the shipped size plus the slack.
	f.put("left-pad", "1.0.0", make([]byte, 2*shipped.Size()+maxCopySlack+1))
	res := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())
	if r := res[0]; r.State != Failed || !strings.Contains(r.Reason, "larger than") {
		t.Fatalf("got %+v", r)
	}
	if n := f.uploadCount(); n != 0 {
		t.Errorf("%d uploads", n)
	}
}

func TestPublishRepositoryReasonIsBounded(t *testing.T) {
	f := newFakeNexus(t)
	format, _ := json.Marshal(strings.Repeat("\x1b[31m", 50000))
	f.repoBody = `[{"name":"npm-hosted","format":` + string(format) + `,"type":"hosted"}]`
	dir := t.TempDir()
	var pkgs []Package
	for _, n := range []string{"aaa", "bbb", "ccc"} {
		pkgs = append(pkgs, stage(t, dir, n, "1.0.0", []byte(n)))
	}
	for _, r := range Publish(context.Background(), f.client(t), pkgs, t.TempDir()) {
		if r.State != Failed || len(r.Reason) > 600 || strings.ContainsAny(r.Reason, "\x1b\x07") {
			t.Errorf("%s: %d bytes, %q", r.Name, len(r.Reason), r.Reason[:min(len(r.Reason), 80)])
		}
	}
}

func TestPublishFailsMismatchedTarball(t *testing.T) {
	good := func(n, v string) []byte { return packed(t, n, v, "x") }
	manifest := func(n, v string) tarEntry {
		m, _ := jsonOf(map[string]string{"name": n, "version": v})
		return tarEntry{"package/package.json", m}
	}
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"another name", good("other-pad", "1.0.0"), `the tarball is "other-pad"@"1.0.0", the manifest says left-pad@1.0.0`},
		{"another version", good("left-pad", "1.0.1"), `the tarball is "left-pad"@"1.0.1", the manifest says left-pad@1.0.0`},
		{"no name", packEntries(t, tarEntry{"package/package.json", "{}"}), `the tarball is ""@"", the manifest says`},
		{"unsafe path", packEntries(t, manifest("left-pad", "1.0.0"), tarEntry{"package/../../evil", "x"}), "unsafe path"},
		{"two package.json", packEntries(t, manifest("left-pad", "1.0.0"), manifest("left-pad", "1.0.0")), "several package.json"},
		{"not a tarball", []byte("plain bytes"), "not a valid package"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeNexus(t)
			dir := t.TempDir()
			bad := stage(t, dir, "left-pad", "1.0.0", nil)
			sum := sha512.Sum512(tc.data)
			bad.SHA512 = sum[:]
			if err := os.WriteFile(bad.Path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			next := stage(t, dir, "right-pad", "2.0.0", []byte("next"))
			f.storeUploads(next)
			res := Publish(context.Background(), f.client(t), []Package{bad, next}, t.TempDir())
			if r := res[0]; r.State != Failed || !strings.Contains(r.Reason, tc.want) {
				t.Errorf("bad package: %+v, want a reason with %q", r, tc.want)
			}
			if r := res[1]; r.State != Published {
				t.Errorf("next package: %+v", r)
			}
			if n := f.uploadCount(); n != 1 || f.uploads[0].File != next.File {
				t.Errorf("%d uploads, want only %s", n, next.File)
			}
		})
	}
	t.Run("a long name is cut", func(t *testing.T) {
		f := newFakeNexus(t)
		pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", nil)
		data := good(strings.Repeat("n", 5000)+"\x1b[31m", "1.0.0")
		sum := sha512.Sum512(data)
		pkg.SHA512 = sum[:]
		if err := os.WriteFile(pkg.Path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		r := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())[0]
		if r.State != Failed || len(r.Reason) > 300 || strings.ContainsRune(r.Reason, 0x1b) {
			t.Fatalf("got %d bytes: %.120q", len(r.Reason), r.Reason)
		}
	})
}

func TestPublishStrippedSameContent(t *testing.T) {
	const withConfig = `{"name":"left-pad","version":"1.0.0","publishConfig":{"registry":"https://example.com"}}`
	const without = `{"name":"left-pad","version":"1.0.0"}`
	shippedData := packEntries(t, tarEntry{"package/package.json", without}, tarEntry{"package/index.js", "code"})
	// The copy Nexus holds came from another packer: other order, publishConfig still in.
	nexusCopy := packEntries(t, tarEntry{"package/index.js", "code"}, tarEntry{"package/package.json", withConfig})
	changed := packEntries(t, tarEntry{"package/index.js", "code!"}, tarEntry{"package/package.json", withConfig})

	for _, tc := range []struct {
		name     string
		held     []byte
		stripped bool
		state    State
		note     string
		reason   string
	}{
		{"same content", nexusCopy, true, Present, "same content, packed differently", ""},
		{"not stripped", nexusCopy, false, Failed, "", "nexus holds this version with other bytes"},
		{"other content", changed, true, Failed, "", "nexus holds this version with other bytes"},
		{"not a tarball", []byte("plain"), true, Failed, "", "cannot compare the nexus copy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", nil)
			sum := sha512.Sum512(shippedData)
			pkg.SHA512, pkg.PublishConfigStripped = sum[:], tc.stripped
			if err := os.WriteFile(pkg.Path, shippedData, 0o600); err != nil {
				t.Fatal(err)
			}
			f.put("left-pad", "1.0.0", tc.held)
			r := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())[0]
			if r.State != tc.state || r.Note != tc.note || (tc.reason == "") != (r.Reason == "") || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("got %+v, want %s with note %q and reason %q", r, tc.state, tc.note, tc.reason)
			}
			if n := f.uploadCount(); n != 0 {
				t.Errorf("%d uploads", n)
			}
		})
	}
}

func TestPublishReasonsFromTarballTextAreClean(t *testing.T) {
	forged := "\x1b[2J\r\nleft-pad@1.0.0 published\n"
	hostile := func(name string) []byte {
		return packEntries(t, tarEntry{name, "not json"})
	}
	for _, tc := range []struct {
		name    string
		shipped []byte
		nexus   []byte // when set, the package is stripped and Nexus holds this copy
		want    string
	}{
		{"shipped entry name with control characters", hostile(forged + "/package.json"), nil, "the tarball is not a valid package"},
		{"shipped entry name near the bound", hostile(strings.Repeat("n", 4000) + "/package.json"), nil, "the tarball is not a valid package"},
		{"shipped entry name of 500 KB", hostile("package/" + strings.Repeat("n", 500_000)), nil, "the tarball is not a valid package"},
		{"nexus entry name with control characters", packed(t, "left-pad", "1.0.0", "x"), hostile(forged + "/package.json"), "cannot compare the nexus copy"},
		{"nexus entry name near the bound", packed(t, "left-pad", "1.0.0", "x"), hostile(strings.Repeat("n", 4000) + "/package.json"), "cannot compare the nexus copy"},
		{"nexus entry name of 500 KB", packed(t, "left-pad", "1.0.0", "x"), hostile("package/" + strings.Repeat("n", 500_000)), "cannot compare the nexus copy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", nil)
			sum := sha512.Sum512(tc.shipped)
			pkg.SHA512, pkg.PublishConfigStripped = sum[:], tc.nexus != nil
			if err := os.WriteFile(pkg.Path, tc.shipped, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.nexus != nil {
				f.put("left-pad", "1.0.0", tc.nexus)
			}
			r := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())[0]
			if r.State != Failed || !strings.Contains(r.Reason, tc.want) {
				t.Fatalf("got %+v, want a reason with %q", r, tc.want)
			}
			if len([]rune(r.Reason)) > 300 || strings.ContainsAny(r.Reason, "\x1b\r\n") {
				t.Fatalf("reason of %d bytes carries control characters or is not cut: %.120q", len(r.Reason), r.Reason)
			}
		})
	}
}

func TestPublishStrippedSwappedShippedFile(t *testing.T) {
	const withConfig = `{"name":"left-pad","version":"1.0.0","publishConfig":{"registry":"https://example.com"}}`
	const without = `{"name":"left-pad","version":"1.0.0"}`
	manifest, index := tarEntry{"package/package.json", without}, tarEntry{"package/index.js", "code"}
	shippedData := packEntriesAt(t, gzip.NoCompression, manifest, index)
	// The same content in another order has the same size and other bytes. It
	// replaces the shipped file while Nexus is being asked, and Nexus holds the
	// same content too.
	swapped := packEntriesAt(t, gzip.NoCompression, index, manifest)
	nexusCopy := packEntriesAt(t, gzip.NoCompression, index, tarEntry{"package/package.json", withConfig})
	if len(swapped) != len(shippedData) || bytes.Equal(swapped, shippedData) {
		t.Fatalf("fixture: %d and %d bytes", len(swapped), len(shippedData))
	}

	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "left-pad", "1.0.0", nil)
	sum := sha512.Sum512(shippedData)
	pkg.SHA512, pkg.PublishConfigStripped = sum[:], true
	if err := os.WriteFile(pkg.Path, shippedData, 0o600); err != nil {
		t.Fatal(err)
	}
	f.put("left-pad", "1.0.0", nexusCopy)
	f.onGet = func(string) {
		if err := os.WriteFile(pkg.Path, swapped, 0o600); err != nil {
			t.Error(err)
		}
	}
	r := Publish(context.Background(), f.client(t), []Package{pkg}, t.TempDir())[0]
	if r.State != Failed || !strings.Contains(r.Reason, "nexus holds this version with other bytes") {
		t.Fatalf("got %+v", r)
	}
	if n := f.uploadCount(); n != 0 {
		t.Errorf("%d uploads", n)
	}
}

func TestCleanStripsControlCharactersAndCuts(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain text", "left-pad@1.0.0", "left-pad@1.0.0"},
		{"escape and line breaks", "a\x1b[2Jb\r\nc", "a[2Jbc"},
		{"nul, tab and delete", "a\x00b\tc\x7fd", "abcd"},
		{"invalid utf-8", "a\xffb", "ab"},
		{"multibyte text kept", "paquet-été", "paquet-été"},
		{"cut at 300 characters", strings.Repeat("é", 400), strings.Repeat("é", 300)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clean(tc.in); got != tc.want {
				t.Fatalf("clean(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
