package npm

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sriOf(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func testClient(url string) *Client {
	return &Client{Registry: url, Backoff: func(int) time.Duration { return 0 }}
}

func TestPackument(t *testing.T) {
	const doc = `{
	  "name": "@scope/pkg",
	  "versions": {
	    "1.0.0": {"version": "1.0.0", "engines": ["node >= 0.4"], "deprecated": false, "_npmUser": {"name": "alice"}},
	    "2.0.0": {"version": "2.0.0", "engines": {"node": ">=18"}, "deprecated": "use 3.x",
	              "scripts": {"postinstall": "node setup.js"}, "peerDependencies": {"react": "^19.0.0"},
	              "dist": {"integrity": "sha512-AA==", "attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x"}}}
	  },
	  "time": {"created": "2024-01-01T00:00:00.000Z", "1.0.0": "2024-01-02T00:00:00.000Z", "unpublished": {"time": "2024-02-01"}}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/@scope%2Fpkg" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	p, err := testClient(srv.URL).Packument(context.Background(), "@scope/pkg")
	if err != nil {
		t.Fatal(err)
	}
	v1, v2 := p.Versions["1.0.0"], p.Versions["2.0.0"]
	if len(v1.Engines) != 0 || v1.Deprecated != "" || v1.NPMUser.Name != "alice" || v1.HasInstallScript() || v1.HasProvenance() {
		t.Errorf("1.0.0 = %+v", v1)
	}
	if v2.Engines["node"] != ">=18" || v2.Deprecated != "use 3.x" || !v2.HasInstallScript() || !v2.HasProvenance() || v2.PeerDependencies["react"] != "^19.0.0" {
		t.Errorf("2.0.0 = %+v", v2)
	}
	if at, ok := p.Published("1.0.0"); !ok || !at.Equal(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Published(1.0.0) = %v, %v", at, ok)
	}
	if _, ok := p.Published("2.0.0"); ok {
		t.Error("Published(2.0.0) found a time that does not exist")
	}

	if _, err := testClient(srv.URL).Packument(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing package: err = %v, want ErrNotFound", err)
	}
}

// TestPackumentRefusesADocumentOverTheBound serves a valid packument padded
// with whitespace: at the bound it decodes, one byte over it is refused, with
// the package and the bound named and no retry, so the analysis never works
// from a document cut short.
func TestPackumentRefusesADocumentOverTheBound(t *testing.T) {
	const doc = `{"name": "big", "versions": {"1.0.0": {"version": "1.0.0"}}}`
	for _, c := range []struct {
		name string
		size int
		ok   bool
	}{
		{"at the bound", maxPackument, true},
		{"one byte over", maxPackument + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = w.Write([]byte(doc))
				pad := bytes.Repeat([]byte(" "), 1<<20)
				for left := c.size - len(doc); left > 0; left -= len(pad) {
					if _, err := w.Write(pad[:min(left, len(pad))]); err != nil {
						return
					}
				}
			}))
			defer srv.Close()

			p, err := testClient(srv.URL).Packument(context.Background(), "big")
			if c.ok {
				if err != nil || p.Versions["1.0.0"].Version != "1.0.0" {
					t.Fatalf("Packument = %+v, %v", p, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Packument read a %d-byte document, over the %d-byte bound", c.size, maxPackument)
			}
			if !strings.Contains(err.Error(), "big") || !strings.Contains(err.Error(), "256 MiB") {
				t.Errorf("err = %v, want the package and the bound named", err)
			}
			if p.Name != "" || p.Versions != nil {
				t.Errorf("Packument returned %+v beside its error", p)
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("registry asked %d times, want 1: an oversized document does not shrink on retry", n)
			}
		})
	}
}

func TestEnginesKeepsTheStringValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want Engines
	}{
		{name: "all strings", doc: `{"node": ">=18", "npm": ">=9"}`, want: Engines{"node": ">=18", "npm": ">=9"}},
		{name: "one value is a number", doc: `{"node": ">=18", "npm": 7}`, want: Engines{"node": ">=18"}},
		{name: "node is not a string", doc: `{"node": 18, "npm": ">=9"}`, want: Engines{"npm": ">=9"}},
		{name: "only value is not a string", doc: `{"node": {"min": 18}}`, want: Engines{}},
		{name: "array", doc: `["node >= 0.4"]`, want: nil},
		{name: "null", doc: `null`, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var e Engines
			if err := json.Unmarshal([]byte(tc.doc), &e); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if len(e) != len(tc.want) || (len(e) > 0 && !reflect.DeepEqual(e, tc.want)) {
				t.Errorf("Engines = %#v, want %#v", e, tc.want)
			}
		})
	}
}

func TestDownloadFile(t *testing.T) {
	tarball := []byte("tarball bytes")
	for _, tc := range []struct {
		name      string
		failures  int // 503 responses before the real one
		body      []byte
		status    int
		wantErr   error
		wantCalls int32
	}{
		{name: "first try", body: tarball, status: http.StatusOK, wantCalls: 1},
		{name: "retries then succeeds", failures: 2, body: tarball, status: http.StatusOK, wantCalls: 3},
		{name: "gives up", failures: 5, body: tarball, status: http.StatusOK, wantErr: errors.New("any"), wantCalls: 3},
		{name: "integrity mismatch", body: []byte("tampered"), status: http.StatusOK, wantErr: ErrIntegrity, wantCalls: 1},
		{name: "not found", status: http.StatusNotFound, wantErr: ErrNotFound, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.URL.Path != "/demo/-/demo-1.0.0.tgz" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if int(n) <= tc.failures {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			defer srv.Close()

			path := filepath.Join(t.TempDir(), "demo-1.0.0.tgz")
			sha512Hex, err := testClient(srv.URL).DownloadFile(context.Background(), "demo", "1.0.0", sriOf(tarball), path)
			if calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
			if _, statErr := os.Stat(path + ".part"); !os.IsNotExist(statErr) {
				t.Error(".part file left behind")
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatal(err)
				}
				got, _ := os.ReadFile(path)
				if string(got) != string(tarball) {
					t.Errorf("file = %q", got)
				}
				sum := sha512.Sum512(tarball)
				if want := hex.EncodeToString(sum[:]); sha512Hex != want {
					t.Errorf("sha512 = %q, want %q", sha512Hex, want)
				}
				return
			}
			if sha512Hex != "" {
				t.Errorf("sha512 = %q, want empty on error", sha512Hex)
			}
			if err == nil {
				t.Fatal("want an error")
			}
			if (errors.Is(tc.wantErr, ErrIntegrity) || errors.Is(tc.wantErr, ErrNotFound)) && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Error("file exists after a failed download")
			}
		})
	}
}

func TestParseIntegrityPicksTheStrongestHash(t *testing.T) {
	sha1Sum := base64.StdEncoding.EncodeToString(make([]byte, 20))
	sha512Sum := base64.StdEncoding.EncodeToString(make([]byte, 64))
	tests := []struct {
		name, sri string
		size      int
	}{
		{"sha512 alone", "sha512-" + sha512Sum, 64},
		{"sha1 alone", "sha1-" + sha1Sum, 20},
		{"sha1 first", "sha1-" + sha1Sum + " sha512-" + sha512Sum, 64},
		{"sha512 first", "sha512-" + sha512Sum + " sha1-" + sha1Sum, 64},
		{"sha384 beside sha512", "sha384-AAAA sha512-" + sha512Sum, 64},
		{"an option after the digest", "sha1-" + sha1Sum + "?x=1 sha512-" + sha512Sum + "?x=1", 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newHash, sum, err := ParseIntegrity(tt.sri)
			if err != nil {
				t.Fatalf("ParseIntegrity: %v", err)
			}
			if newHash().Size() != tt.size || len(sum) != tt.size {
				t.Errorf("hash size = %d, digest = %d bytes, want %d", newHash().Size(), len(sum), tt.size)
			}
		})
	}
}

func TestParseIntegrityRejects(t *testing.T) {
	sha1Sum := base64.StdEncoding.EncodeToString(make([]byte, 20))
	for _, sri := range []string{
		"", "sha512", "md5-AA==", "sha512-not base64!",
		"sha512-", "sha512-AAAA", "sha1-AAAA",
		"sha1-" + sha1Sum + " sha512-",
		"sha1-" + sha1Sum + " sha512-!!!!",
		"sha384-AAAA sha1-" + sha1Sum,
		"SHA512-AAAA sha1-" + sha1Sum,
	} {
		if _, _, err := ParseIntegrity(sri); err == nil {
			t.Errorf("ParseIntegrity(%q): want an error", sri)
		}
	}
}

// TestDownloadFileWritesThroughNoLink plants a link at the .part path, as
// another account that writes the directory could: the download must not
// write the tarball into the link's target.
func TestDownloadFileWritesThroughNoLink(t *testing.T) {
	tarball := []byte("tarball bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "demo-1.0.0.tgz")
	if err := os.Symlink(victim, path+".part"); err != nil {
		t.Fatal(err)
	}
	if _, err := testClient(srv.URL).DownloadFile(context.Background(), "demo", "1.0.0", sriOf(tarball), path); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "victim" {
		t.Errorf("the link's target now holds %q", got)
	}
	if got, _ := os.ReadFile(path); string(got) != string(tarball) {
		t.Errorf("file = %q", got)
	}
}
