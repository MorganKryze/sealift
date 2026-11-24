package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/store"
)

const (
	uvTestVersion = "0.13.7"
	uvTestTag     = "py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64"
	uvTestWheel   = "uv-0.13.7-" + uvTestTag + ".whl"
	uvTestEntry   = "uv-0.13.7.data/scripts/uv"
	uvTestScript  = "#!/bin/sh\necho uv 0.13.7\n"
)

// uvIndex serves a piptest index through a front that counts every request,
// and can list another sha256 or serve other bytes for the wheel.
type uvIndex struct {
	ix  *piptest.Index
	srv *httptest.Server

	mu       sync.Mutex
	requests int
	sha256   string // listed instead of the real one when set
	wheel    []byte // served instead of the index's file when set
	wheelLen int64  // a body of this many zero bytes is served when set
}

func newUvIndex(t *testing.T, uploaded time.Time) *uvIndex {
	t.Helper()
	u := &uvIndex{ix: piptest.NewIndex(t)}
	u.ix.Add(piptest.Dist{
		Name: "uv", Version: uvTestVersion, Tag: uvTestTag, Uploaded: uploaded,
		Payload: map[string][]byte{uvTestEntry: []byte(uvTestScript)},
	})
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *uvIndex) URL() string { return u.srv.URL + "/simple/" }

func (u *uvIndex) Requests() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests
}

// serveCrafted makes the index serve data as the wheel and list its sha256.
func (u *uvIndex) serveCrafted(data []byte) {
	sum := sha256.Sum256(data)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.wheel, u.sha256 = data, hex.EncodeToString(sum[:])
}

func (u *uvIndex) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.requests++
	sha, wheel, wheelLen := u.sha256, u.wheel, u.wheelLen
	u.mu.Unlock()

	if strings.HasPrefix(r.URL.Path, "/files/") {
		switch {
		case wheel != nil:
			_, _ = w.Write(wheel)
			return
		case wheelLen > 0:
			_, _ = io.CopyN(w, zeros{}, wheelLen)
			return
		}
	}
	if sha == "" || !strings.HasPrefix(r.URL.Path, "/simple/") {
		u.ix.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	u.ix.ServeHTTP(rec, r)
	var page map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	files, _ := page["files"].([]any)
	for _, f := range files {
		f.(map[string]any)["hashes"] = map[string]string{"sha256": sha}
	}
	w.Header().Set("Content-Type", rec.Header().Get("Content-Type"))
	_ = json.NewEncoder(w).Encode(page)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func newUvManager(t *testing.T, index string, client *http.Client) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	m := NewManager(fakeVolume{root: root, settings: store.Settings{MinReleaseAgeDays: 14}}, client, nil)
	m.PipIndex = index
	m.Arch = "amd64"
	return m, root
}

var monthOld = time.Now().Add(-30 * 24 * time.Hour)

// zipEntry is one entry of a crafted wheel. declared, when set, replaces
// the uncompressed size the entry's header states.
type zipEntry struct {
	name     string
	body     []byte
	declared uint64
}

func craftWheel(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		size := uint64(len(e.body))
		if e.declared > 0 {
			size = e.declared
		}
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name: e.name, Method: zip.Store, CRC32: crc32.ChecksumIEEE(e.body),
			CompressedSize64: uint64(len(e.body)), UncompressedSize64: size,
		})
		if err != nil {
			t.Fatalf("create %s: %v", e.name, err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// listFiles returns every file under root that is not a directory,
// relative to it.
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestEnsureUvInstallsTheWheelsBinary(t *testing.T) {
	idx := newUvIndex(t, monthOld)
	m, root := newUvManager(t, idx.URL(), nil)

	bin, err := m.EnsureUv(context.Background(), uvTestVersion)
	if err != nil {
		t.Fatalf("EnsureUv: %v", err)
	}
	want := filepath.Join(root, "tools", "uv", uvTestVersion, "uv")
	if bin != want {
		t.Fatalf("EnsureUv = %q, want %q", bin, want)
	}
	info, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("stat uv: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("uv mode = %v, want 0755", info.Mode().Perm())
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != uvTestScript {
		t.Errorf("uv holds %q, want the wheel's script %q", data, uvTestScript)
	}
	installed, err := m.InstalledUv()
	if err != nil {
		t.Fatal(err)
	}
	if len(installed) != 1 || installed[0] != uvTestVersion {
		t.Errorf("InstalledUv = %v, want [%s]", installed, uvTestVersion)
	}
}

func TestEnsureUvChecksSha256(t *testing.T) {
	idx := newUvIndex(t, monthOld)
	idx.sha256 = strings.Repeat("ab", 32)
	m, root := newUvManager(t, idx.URL(), nil)

	_, err := m.EnsureUv(context.Background(), uvTestVersion)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("EnsureUv error = %v, want a sha256 mismatch", err)
	}
	if files := listFiles(t, root); len(files) != 0 {
		t.Errorf("a wheel that fails its sha256 left %v", files)
	}
	if n := idx.ix.Requests("/files/" + uvTestWheel); n != 1 {
		t.Errorf("wheel downloads = %d, want exactly 1 (no retry)", n)
	}
}

func TestEnsureUvRefusesYoungRelease(t *testing.T) {
	idx := newUvIndex(t, time.Now().Add(-24*time.Hour))
	m, root := newUvManager(t, idx.URL(), nil)

	_, err := m.EnsureUv(context.Background(), uvTestVersion)
	if !errors.Is(err, ErrReleaseTooRecent) {
		t.Fatalf("EnsureUv error = %v, want ErrReleaseTooRecent", err)
	}
	for _, part := range []string{"uv 0.13.7", "14 days", "pin an older uv", "wait"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("refusal %q does not name %q", err, part)
		}
	}
	if strings.Contains(err.Error(), "force") {
		t.Errorf("refusal %q points to a force install no route offers", err)
	}
	if files := listFiles(t, root); len(files) != 0 {
		t.Errorf("a refused release left %v", files)
	}
}

func TestEnsureUvRefusesAReleaseWithNoUploadTime(t *testing.T) {
	idx := newUvIndex(t, time.Time{})
	m, _ := newUvManager(t, idx.URL(), nil)

	_, err := m.EnsureUv(context.Background(), uvTestVersion)
	if !errors.Is(err, ErrReleaseTooRecent) || !strings.Contains(err.Error(), "no upload time") {
		t.Fatalf("EnsureUv error = %v, want ErrReleaseTooRecent naming the missing upload time", err)
	}
	if strings.Contains(err.Error(), "force") || !strings.Contains(err.Error(), "pin") {
		t.Errorf("refusal %q does not say what to do now", err)
	}
}

func TestEnsureUvCopiesOnlyTheBinary(t *testing.T) {
	script := []byte(uvTestScript)
	cases := []struct {
		name    string
		entries []zipEntry
		wantErr string
	}{
		{
			name: "only the binary is written",
			entries: []zipEntry{
				{name: "../evil", body: []byte("escaped")},
				{name: "uv/__init__.py", body: []byte("import os\n")},
				{name: "uv-0.13.7.data/scripts/huge", body: []byte("tiny"), declared: 200 << 20},
				{name: uvTestEntry, body: script},
				{name: "uv-0.13.7.dist-info/RECORD", body: []byte("")},
			},
		},
		{
			name:    "an oversize binary is refused",
			entries: []zipEntry{{name: uvTestEntry, body: script, declared: 128<<20 + 1}},
			wantErr: "128 MiB",
		},
		{
			name:    "a wheel with no binary is refused",
			entries: []zipEntry{{name: "uv/__init__.py", body: []byte("")}},
			wantErr: uvTestEntry,
		},
		{
			name:    "a wheel with the binary twice is refused",
			entries: []zipEntry{{name: uvTestEntry, body: script}, {name: uvTestEntry, body: []byte("other")}},
			wantErr: "more than once",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := newUvIndex(t, monthOld)
			idx.serveCrafted(craftWheel(t, c.entries))
			m, root := newUvManager(t, idx.URL(), nil)

			_, err := m.EnsureUv(context.Background(), uvTestVersion)
			files := listFiles(t, root)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("EnsureUv error = %v, want one naming %q", err, c.wantErr)
				}
				if len(files) != 0 {
					t.Errorf("a refused wheel left %v", files)
				}
				return
			}
			if err != nil {
				t.Fatalf("EnsureUv: %v", err)
			}
			want := []string{"tools/uv/0.13.7/uv"}
			if strings.Join(files, ",") != strings.Join(want, ",") {
				t.Errorf("files written = %v, want %v", files, want)
			}
		})
	}
}

func TestEnsureUvRefusesAWheelOverItsBound(t *testing.T) {
	idx := newUvIndex(t, monthOld)
	idx.wheelLen = 64<<20 + 1
	m, root := newUvManager(t, idx.URL(), nil)

	_, err := m.EnsureUv(context.Background(), uvTestVersion)
	if err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("EnsureUv error = %v, want a refusal naming 64 MiB", err)
	}
	if files := listFiles(t, root); len(files) != 0 {
		t.Errorf("an oversize wheel left %v", files)
	}
}

func TestEnsureUvSkipsAnInstalledVersion(t *testing.T) {
	idx := newUvIndex(t, monthOld)
	m, _ := newUvManager(t, idx.URL(), nil)
	first, err := m.EnsureUv(context.Background(), uvTestVersion)
	if err != nil {
		t.Fatalf("first EnsureUv: %v", err)
	}
	before := idx.Requests()

	again, err := m.EnsureUv(context.Background(), uvTestVersion)
	if err != nil {
		t.Fatalf("second EnsureUv: %v", err)
	}
	if again != first {
		t.Errorf("second EnsureUv = %q, want %q", again, first)
	}
	if n := idx.Requests() - before; n != 0 {
		t.Errorf("an installed version made %d index requests, want 0", n)
	}
}

// hostRecorder records the host of every request a client sends.
type hostRecorder struct {
	mu    sync.Mutex
	hosts []string
}

func (h *hostRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	h.hosts = append(h.hosts, r.URL.Host)
	h.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func TestEnsureUvReadsOnlyTheIndex(t *testing.T) {
	idx := newUvIndex(t, monthOld)
	rec := &hostRecorder{}
	m, _ := newUvManager(t, idx.URL(), &http.Client{Transport: rec, Timeout: 10 * time.Second})
	m.GitHubAPI = "http://192.0.2.1"
	m.NPMRegistry = "http://192.0.2.1"

	if _, err := m.EnsureUv(context.Background(), uvTestVersion); err != nil {
		t.Fatalf("EnsureUv: %v", err)
	}
	u, _ := url.Parse(idx.URL())
	if len(rec.hosts) == 0 {
		t.Fatal("EnsureUv sent no request")
	}
	for _, h := range rec.hosts {
		if h != u.Host {
			t.Errorf("request to %s, want only the index %s", h, u.Host)
		}
	}
}

func TestEnsureUvRefusesBadVersion(t *testing.T) {
	idx := newUvIndex(t, monthOld)
	m, root := newUvManager(t, idx.URL(), nil)
	for _, v := range []string{"", "0.13", "0.13.7.1", "v0.13.7", "latest", "../0.13.7", "0.13.7/../../x", "0.13.7 ", "12345.0.0"} {
		t.Run(v, func(t *testing.T) {
			_, err := m.EnsureUv(context.Background(), v)
			if !errors.Is(err, ErrInvalidUvVersion) || !strings.Contains(err.Error(), "such as 0.13.7") {
				t.Fatalf("EnsureUv(%q) error = %v, want ErrInvalidUvVersion with an example", v, err)
			}
		})
	}
	if n := idx.Requests(); n != 0 {
		t.Errorf("bad versions made %d index requests, want 0", n)
	}
	if files := listFiles(t, root); len(files) != 0 {
		t.Errorf("bad versions left %v", files)
	}
}

func TestEnsureUvChoosesTheHostsCPU(t *testing.T) {
	cases := []struct {
		arch, wantErr string
	}{
		{"arm64", "aarch64"},
		{"riscv64", "riscv64"},
	}
	for _, c := range cases {
		t.Run(c.arch, func(t *testing.T) {
			idx := newUvIndex(t, monthOld)
			m, root := newUvManager(t, idx.URL(), nil)
			m.Arch = c.arch
			_, err := m.EnsureUv(context.Background(), uvTestVersion)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("EnsureUv error = %v, want one naming %q", err, c.wantErr)
			}
			if files := listFiles(t, root); len(files) != 0 {
				t.Errorf("a host with no wheel left %v", files)
			}
		})
	}
}

func TestInstalledUvListsOnlyVersions(t *testing.T) {
	m, root := newUvManager(t, "", nil)
	if got, err := m.InstalledUv(); err != nil || len(got) != 0 {
		t.Fatalf("InstalledUv on an empty volume = %v, %v, want none", got, err)
	}
	for _, d := range []string{"0.13.7", "0.9.1", "0.13.7.tmp", "0.13.7.old-0a1b2c3d", "notes"} {
		if err := os.MkdirAll(filepath.Join(root, "tools", "uv", d), 0o770); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.InstalledUv()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "0.13.7,0.9.1" {
		t.Errorf("InstalledUv = %v, want [0.13.7 0.9.1]", got)
	}
}

func TestParseIndexURL(t *testing.T) {
	cases := []struct {
		raw, want, wantErr string
	}{
		{raw: "", want: DefaultPipIndex},
		{raw: "https://mirror.example.org/simple/", want: "https://mirror.example.org/simple/"},
		{raw: "http://127.0.0.1:9/simple/", want: "http://127.0.0.1:9/simple/"},
		{raw: "http://localhost:9/simple/", want: "http://localhost:9/simple/"},
		{raw: "http://[::1]:9/simple/", want: "http://[::1]:9/simple/"},
		{raw: "ftp://mirror.example.org/simple/", wantErr: "https"},
		{raw: "http://example.org/simple/", wantErr: "loopback"},
		{raw: "http://localhost.evil.com/simple/", wantErr: "loopback"},
		{raw: "https://u:p@host/simple/", wantErr: "credentials"},
		{raw: "https://u@host/simple/", wantErr: "credentials"},
		{raw: "https:///simple/", wantErr: "host"},
		{raw: "https://mirror.example.org/simple/?token=1", wantErr: "query"},
		{raw: "mirror.example.org/simple/", wantErr: "https"},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := ParseIndexURL(c.raw)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("ParseIndexURL(%q) = %q, %v, want an error naming %q", c.raw, got, err, c.wantErr)
				}
				if c.raw != "" && strings.Contains(err.Error(), c.raw) {
					t.Errorf("error %q repeats the value", err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("ParseIndexURL(%q) = %q, %v, want %q", c.raw, got, err, c.want)
			}
		})
	}
}

func TestParseRegistryURL(t *testing.T) {
	cases := []struct {
		raw       string
		allowHTTP bool
		want      string
		insecure  bool
		wantErr   string
	}{
		{raw: "", want: ""},
		{raw: "https://npm.example.org/", want: "https://npm.example.org/"},
		{raw: "https://ci:s3cret@npm.example.org/", want: "https://ci:s3cret@npm.example.org/"},
		{raw: "http://127.0.0.1:4873", want: "http://127.0.0.1:4873"},
		{raw: "http://localhost:4873", want: "http://localhost:4873"},
		{raw: "http://registry:4873", wantErr: "SEALIFT_ALLOW_HTTP_REGISTRY"},
		{raw: "http://localhost.evil.com", wantErr: "SEALIFT_ALLOW_HTTP_REGISTRY"},
		{raw: "http://ci:s3cret@registry:4873", wantErr: "SEALIFT_ALLOW_HTTP_REGISTRY"},
		{raw: "http://registry:4873", allowHTTP: true, want: "http://registry:4873", insecure: true},
		{raw: "ftp://npm.example.org/", allowHTTP: true, wantErr: "https"},
		{raw: "https:///", wantErr: "host"},
		{raw: "npm.example.org", wantErr: "https"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s allow=%v", c.raw, c.allowHTTP), func(t *testing.T) {
			got, insecure, err := ParseRegistryURL(c.raw, c.allowHTTP)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("ParseRegistryURL(%q) = %q, %v, want an error naming %q", c.raw, got, err, c.wantErr)
				}
				if strings.Contains(err.Error(), c.raw) || strings.Contains(err.Error(), "s3cret") {
					t.Errorf("error %q repeats the value", err)
				}
				return
			}
			if err != nil || got != c.want || insecure != c.insecure {
				t.Fatalf("ParseRegistryURL(%q) = %q, %v, %v, want %q, %v", c.raw, got, insecure, err, c.want, c.insecure)
			}
		})
	}
}

func TestUvMinimumAgeBoundary(t *testing.T) {
	m := NewManager(fakeVolume{root: t.TempDir(), settings: store.Settings{MinReleaseAgeDays: 14}}, nil, nil)
	var tooRecent releaseTooRecent
	if err := m.checkUvAge("0.9.0", time.Now().Add(-13*24*time.Hour)); !errors.As(err, &tooRecent) {
		t.Errorf("13 days old: got %v, want a refusal", err)
	}
	if err := m.checkUvAge("0.9.0", time.Now().Add(-14*24*time.Hour-time.Hour)); err != nil {
		t.Errorf("14 days and one hour old: got %v, want nil", err)
	}
}
