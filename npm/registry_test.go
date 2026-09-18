package npm

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestParseIntegrityRejects(t *testing.T) {
	for _, sri := range []string{"", "sha512", "md5-AA==", "sha512-not base64!"} {
		if _, _, err := parseIntegrity(sri); err == nil {
			t.Errorf("parseIntegrity(%q): want an error", sri)
		}
	}
}
