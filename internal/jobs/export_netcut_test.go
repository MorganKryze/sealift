package jobs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/npm"
)

// cutRegistry fronts the harness's registry and serves the first `serve`
// tarballs, then fails every later request with cut until restore is
// called.
type cutRegistry struct {
	srv      *httptest.Server
	served   atomic.Int32
	restored atomic.Bool
}

func newCutRegistry(t *testing.T, h *testHarness, serve int32, cut func(w http.ResponseWriter, r *http.Request)) *cutRegistry {
	t.Helper()
	c := &cutRegistry{}
	upstream := h.registry.Config.Handler
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.restored.Load() || c.served.Add(1) <= serve {
			upstream.ServeHTTP(w, r)
			return
		}
		cut(w, r)
	}))
	// A stalled handler waits on its request's context, so closing the
	// client connections first lets Close return.
	t.Cleanup(func() { c.srv.CloseClientConnections(); c.srv.Close() })
	return c
}

func closeConnection(w http.ResponseWriter, _ *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func unavailable(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "registry down", http.StatusServiceUnavailable)
}

func stall(_ http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
}

// assertOnlyStatusLeft proves a failed export keeps nothing a reader could
// take for its output: no archive, no manifest, no partial tarball.
func assertOnlyStatusLeft(t *testing.T, exportDir string) {
	t.Helper()
	_ = filepath.Walk(exportDir, func(path string, _ os.FileInfo, err error) error {
		if err != nil || path == exportDir {
			return err
		}
		if rel, _ := filepath.Rel(exportDir, path); rel != "status.json" {
			t.Errorf("%s survived a failed export, want only status.json", rel)
		}
		return nil
	})
}

func TestExportRegistryCutMidDownload(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func(http.ResponseWriter, *http.Request)
	}{
		{"connection closed", closeConnection},
		{"service unavailable", unavailable},
		{"body cut short", cutBody},
		{"stalled past the timeout", stall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			reg := newCutRegistry(t, h, 1, tc.cut)
			analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
			h.buildAnalysis(analysisDir)

			exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
			exp := h.newExport(t, analysisDir, exportDir, false)
			exp.Registry = &npm.Client{
				Registry: reg.srv.URL,
				HTTP:     &http.Client{Timeout: 200 * time.Millisecond},
				Backoff:  func(int) time.Duration { return 0 },
			}
			exp.Settings.DownloadParallelism = 1

			done := make(chan error, 1)
			go func() { done <- exp.Run(context.Background(), noopEmit) }()
			var err error
			select {
			case err = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Run still running 30s after the registry went away")
			}
			if err == nil {
				t.Fatal("Run = <nil>, want the cut registry to fail the export")
			}
			assertExportFailedStatus(t, exportDir, "download", "jobs: download ")
			assertCauseNamesAPackage(t, exportDir)
			assertOnlyStatusLeft(t, exportDir)

			reg.restored.Store(true)
			retryDir := filepath.Join(t.TempDir(), "exports", "20260917T101600Z.tmp")
			retry := h.newExport(t, analysisDir, retryDir, false)
			retry.Registry = exp.Registry
			if err := retry.Run(context.Background(), noopEmit); err != nil {
				t.Fatalf("retry after the registry came back: %v", err)
			}
			for _, name := range []string{"manifest.json", "packages_npm.tar.gz"} {
				if _, err := os.Stat(filepath.Join(retryDir, name)); err != nil {
					t.Errorf("retry: %s: %v", name, err)
				}
			}
		})
	}
}

func assertCauseNamesAPackage(t *testing.T, exportDir string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(exportDir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"widgets", "@scope/gadget", "helper"} {
		if strings.Contains(string(data), name+"@") {
			return
		}
	}
	t.Errorf("status.json = %s, want the failed step's cause to name a package", data)
}

// cutBody promises a full tarball, sends a few bytes of it and drops the
// connection, so the download has already started writing to disk.
func cutBody(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Length", "4096")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00})
	w.(http.Flusher).Flush()
	if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
		_ = conn.Close()
	}
}
