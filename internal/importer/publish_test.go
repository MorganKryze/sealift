package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/importtest"
	"github.com/MorganKryze/sealift/internal/nexus"
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
	// pnpm refuses entries after the end marker, so such a copy is not the same content.
	withTail := packEntriesThen(t, gzip.DefaultCompression, tarBytes(t, tarEntry{"package/install.js", "x"}),
		tarEntry{"package/index.js", "code"}, tarEntry{"package/package.json", withConfig})
	padded := packEntriesThen(t, gzip.DefaultCompression, make([]byte, 9216),
		tarEntry{"package/index.js", "code"}, tarEntry{"package/package.json", withConfig})

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
		{"zero padding after the end marker", padded, true, Present, "same content, packed differently", ""},
		{"data after the end marker", withTail, true, Failed, "", "shipped sha512 "},
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

func TestPublishEachReportsEachPackageAsItEnds(t *testing.T) {
	f := newFakeNexus(t)
	dir := t.TempDir()
	first := stage(t, dir, "alpha", "1.0.0", []byte("alpha"))
	second := stage(t, dir, "beta", "2.0.0", []byte("beta"))
	f.storeUploads(first)
	// Nexus holds other bytes for the second package, so it fails.
	f.put("beta", "2.0.0", packed(t, "beta", "2.0.0", "not beta"))

	var mu sync.Mutex
	var ended []int
	var states []State
	var endedBeforeSecond []int
	f.onGet = func(path string) {
		if path == tarballPath("beta", "2.0.0") {
			mu.Lock()
			endedBeforeSecond = append([]int(nil), ended...)
			mu.Unlock()
		}
	}
	res := PublishEach(context.Background(), f.client(t), []Package{first, second}, t.TempDir(), func(i int, r Result) {
		mu.Lock()
		defer mu.Unlock()
		ended = append(ended, i)
		states = append(states, r.State)
	})

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(ended, []int{0, 1}) || !slices.Equal(states, []State{Published, Failed}) {
		t.Fatalf("callbacks %v %v, want [0 1] [published failed]", ended, states)
	}
	if !slices.Equal(endedBeforeSecond, []int{0}) {
		t.Errorf("when package 1 reached nexus the callbacks were %v, want [0]", endedBeforeSecond)
	}
	if len(res) != 2 || res[0].State != Published || res[1].State != Failed {
		t.Errorf("results %+v", res)
	}
}

func TestPublishEachReportsEveryPackageOfAFailedCheck(t *testing.T) {
	f := newFakeNexus(t)
	f.repoStatus = 500
	pkgs := []Package{stage(t, t.TempDir(), "a", "1.0.0", []byte("a")), stage(t, t.TempDir(), "b", "1.0.0", []byte("b"))}
	var ended []int
	PublishEach(context.Background(), f.client(t), pkgs, t.TempDir(), func(i int, r Result) {
		if r.State != Failed || !strings.Contains(r.Reason, "repository check failed") {
			t.Errorf("package %d: %q %q", i, r.State, r.Reason)
		}
		ended = append(ended, i)
	})
	if !slices.Equal(ended, []int{0, 1}) {
		t.Fatalf("callbacks %v, want [0 1]", ended)
	}
}

// describing is a publisher that answers Nexus's upload facts from its fields
// and records each lookup.
type describing struct {
	Publisher
	facts nexus.AssetFacts
	found bool
	err   error
	mu    sync.Mutex
	calls []string
}

func (d *describing) lookup(key string) (nexus.AssetFacts, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, key)
	return d.facts, d.found, d.err
}

func (d *describing) Asset(_ context.Context, name, version string) (nexus.AssetFacts, bool, error) {
	return d.lookup(name + "@" + version)
}

func (d *describing) AssetFile(_ context.Context, project, file string) (nexus.AssetFacts, bool, error) {
	return d.lookup(project + "/" + file)
}

var uploadedAt = time.Date(2025, 10, 3, 9, 12, 44, 0, time.UTC)

func TestPublishRecordsNexusStatusOnARefusedUpload(t *testing.T) {
	f := newFakeNexus(t)
	dir := t.TempDir()
	large := stage(t, dir, "@next/swc-linux-x64-gnu", "15.5.6", []byte("large"))
	cut := stage(t, dir, "typescript", "5.6.3", []byte("cut"))
	f.postStatus = http.StatusRequestEntityTooLarge
	f.drop[tarballPath("typescript", "5.6.3")] = true
	res := Publish(context.Background(), f.client(t), []Package{large, cut}, t.TempDir())
	if r := res[0]; r.Kind != KindNexus || r.NexusStatus != http.StatusRequestEntityTooLarge {
		t.Errorf("refused upload: %+v", r)
	}
	if r := res[1]; r.Kind != KindNexus || r.NexusStatus != 0 {
		t.Errorf("no answer: %+v", r)
	}

	f.repoStatus = http.StatusUnauthorized
	res = Publish(context.Background(), f.client(t), []Package{large}, t.TempDir())
	if r := res[0]; r.Kind != KindNexus || r.NexusStatus != http.StatusUnauthorized {
		t.Errorf("refused repository check: %+v", r)
	}
}

func TestPublishRecordsTheSizeOfEachPackage(t *testing.T) {
	f := newFakeNexus(t)
	dir := t.TempDir()
	published := stage(t, dir, "aaa", "1.0.0", []byte("published"))
	present := stage(t, dir, "bbb", "1.0.0", []byte("present"))
	conflict := stage(t, dir, "ccc", "1.0.0", []byte("conflict"))
	f.storeUploads(published)
	f.put("bbb", "1.0.0", packed(t, "bbb", "1.0.0", "present"))
	f.put("ccc", "1.0.0", packed(t, "ccc", "1.0.0", "other"))
	pkgs := []Package{published, present, conflict}
	check := func(res []Result) {
		t.Helper()
		for i, r := range res {
			info, err := os.Stat(pkgs[i].Path)
			if err != nil {
				t.Fatal(err)
			}
			if r.Size != info.Size() || r.Size == 0 {
				t.Errorf("%s: size %d, want %d", r.Name, r.Size, info.Size())
			}
		}
	}
	check(Publish(context.Background(), f.client(t), pkgs, t.TempDir()))
	f.repoStatus = http.StatusInternalServerError
	check(Publish(context.Background(), f.client(t), pkgs, t.TempDir()))
}

func TestPublishReadsNexusUploadFactsOnAConflictOnly(t *testing.T) {
	f := newFakeNexus(t)
	dir := t.TempDir()
	published := stage(t, dir, "aaa", "1.0.0", []byte("published"))
	present := stage(t, dir, "bbb", "1.0.0", []byte("present"))
	conflict := stage(t, dir, "is-number", "7.0.0", []byte("shipped"))
	refused := stage(t, dir, "ddd", "1.0.0", []byte("refused"))
	f.storeUploads(published)
	f.put("bbb", "1.0.0", packed(t, "bbb", "1.0.0", "present"))
	f.put("is-number", "7.0.0", packed(t, "is-number", "7.0.0", "other"))
	f.getStatus[tarballPath("ddd", "1.0.0")] = http.StatusBadGateway
	d := &describing{Publisher: f.client(t), facts: nexus.AssetFacts{Uploader: "ci-publish", LastModified: uploadedAt}, found: true}
	res := Publish(context.Background(), d, []Package{published, present, conflict, refused}, t.TempDir())
	if !slices.Equal(d.calls, []string{"is-number@7.0.0"}) {
		t.Fatalf("lookups = %v, want the conflict's only", d.calls)
	}
	if r := res[2]; r.Kind != KindConflict || r.NexusUploader != "ci-publish" || r.NexusUploadedAt == nil || !r.NexusUploadedAt.Equal(uploadedAt) {
		t.Errorf("conflict: %+v", r)
	}
	for _, i := range []int{0, 1, 3} {
		if r := res[i]; r.NexusUploader != "" || r.NexusUploadedAt != nil {
			t.Errorf("%s holds upload facts: %+v", r.Name, r)
		}
	}
	if res[3].Kind != KindNexus {
		t.Errorf("refused: %+v", res[3])
	}
}

func TestPublishWheelsReadsNexusUploadFactsOnAConflict(t *testing.T) {
	six := importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any")
	other := importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any", importtest.Entry{Name: "six/extra.py", Body: []byte("x = 1\n")})
	n := importtest.NewPyPINexus(t, pipRepo)
	n.Put("six", six.File, other.Body)
	d := &describing{Publisher: pypiClient(t, n), facts: nexus.AssetFacts{Uploader: "jo"}, found: true}
	res := PublishWheels(context.Background(), d, []Package{stageWheel(t, t.TempDir(), six)}, "", nil)
	if !slices.Equal(d.calls, []string{"six/" + six.File}) {
		t.Fatalf("lookups = %v", d.calls)
	}
	if r := res[0]; r.Kind != KindConflict || r.NexusUploader != "jo" || r.NexusUploadedAt != nil {
		t.Errorf("conflict: %+v", r)
	}
}

func TestPublishKeepsAConflictWhenTheLookupFails(t *testing.T) {
	for name, d := range map[string]*describing{
		"lookup error": {err: errors.New("nexus answered 500")},
		"not found":    {},
		"no facts":     {found: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeNexus(t)
			pkg := stage(t, t.TempDir(), "is-number", "7.0.0", []byte("shipped"))
			f.put("is-number", "7.0.0", packed(t, "is-number", "7.0.0", "other"))
			d.Publisher = f.client(t)
			r := Publish(context.Background(), d, []Package{pkg}, t.TempDir())[0]
			if r.State != Failed || r.Kind != KindConflict || !strings.Contains(r.Reason, "other bytes") || r.NexusUploader != "" || r.NexusUploadedAt != nil || r.NexusStatus != 0 {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestPublishNeverUploadsOverAConflictingCopy(t *testing.T) {
	f := newFakeNexus(t)
	pkg := stage(t, t.TempDir(), "is-number", "7.0.0", []byte("shipped"))
	f.put("is-number", "7.0.0", packed(t, "is-number", "7.0.0", "other"))
	d := &describing{Publisher: f.client(t), facts: nexus.AssetFacts{Uploader: "ci-publish"}, found: true}
	only := onlyListed{Publisher: d, kept: &kept{only: map[string]bool{pkg.File: true}, refused: map[string]bool{}}}
	r := Publish(context.Background(), only, []Package{pkg}, t.TempDir())[0]
	if r.Kind != KindConflict || r.NexusUploader != "ci-publish" {
		t.Fatalf("got %+v", r)
	}
	if n := f.uploadCount(); n != 0 {
		t.Fatalf("%d uploads", n)
	}
}

func TestRetryOfOneCauseKeepsTheEarlierCauseNexusFacts(t *testing.T) {
	k := &kept{
		only: map[string]bool{},
		before: map[string]Result{
			"large.tgz": {File: "large.tgz", State: Failed, Kind: KindNexus, Reason: "upload failed: nexus answered 413", NexusStatus: 413, Size: 9},
			"other.tgz": {File: "other.tgz", State: Failed, Kind: KindConflict, Reason: "nexus holds this version with other bytes", NexusUploader: "ci-publish", NexusUploadedAt: &uploadedAt},
		},
		refused: map[string]bool{"large.tgz": true, "other.tgz": true},
	}
	large := k.result(Result{Name: "large", File: "large.tgz", State: Failed, Kind: KindNexus, Reason: "upload failed: not part of this retry", Size: 7})
	if large.Kind != KindNexus || large.NexusStatus != 413 || large.Size != 7 || !strings.Contains(large.Reason, "413") {
		t.Errorf("too large: %+v", large)
	}
	other := k.result(Result{Name: "other", File: "other.tgz", State: Failed, Kind: KindNexus, Size: 3})
	if other.Kind != KindConflict || other.NexusUploader != "ci-publish" || other.NexusUploadedAt == nil || other.Size != 3 {
		t.Errorf("conflict: %+v", other)
	}
}

func TestNexusFailedKeepsOnlyAnHTTPStatusOfANexusFailure(t *testing.T) {
	pkg := Package{Name: "left-pad", Version: "1.0.0", File: "left-pad-1.0.0.tgz"}
	cases := []struct {
		name   string
		kind   Kind
		status int
		want   int
	}{
		{"a nexus answer", KindNexus, http.StatusInternalServerError, http.StatusInternalServerError},
		{"the lowest status", KindNexus, 100, 100},
		{"the highest status", KindNexus, 599, 599},
		{"a status below the range", KindNexus, 99, 0},
		{"a status above the range", KindNexus, 600, 0},
		{"a local failure", KindLocal, http.StatusInternalServerError, 0},
		{"a conflict", KindConflict, http.StatusConflict, 0},
	}
	for _, tc := range cases {
		r := nexusFailed(context.Background(), pkg, tc.kind, "upload failed: ", &nexus.Error{Status: tc.status})
		if r.Kind != tc.kind || r.NexusStatus != tc.want {
			t.Errorf("%s: kind %q, status %d, want %d", tc.name, r.Kind, r.NexusStatus, tc.want)
		}
	}
}
