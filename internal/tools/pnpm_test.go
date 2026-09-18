package tools

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
)

func sriIntegrity(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// pnpmRegistry serves a packument with the given versions, each backed by
// its own tarball, and counts every request it receives.
func pnpmRegistry(t *testing.T, tarballs map[string][]byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32

	pkg := npm.Packument{Name: "pnpm", Versions: map[string]npm.VersionMeta{}}
	for version, data := range tarballs {
		meta := npm.VersionMeta{Version: version}
		meta.Dist.Integrity = sriIntegrity(data)
		pkg.Versions[version] = meta
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pnpm", func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(pkg)
	})
	for version, data := range tarballs {
		path := fmt.Sprintf("/pnpm/-/pnpm-%s.tgz", version)
		body := data
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = w.Write(body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestEnsurePnpmDownloadsAndExtracts(t *testing.T) {
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"10.34.5"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\nconsole.log('pnpm')\n",
	})
	srv, requests := pnpmRegistry(t, map[string][]byte{"10.34.5": tarball})

	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	bin, err := m.EnsurePnpm(context.Background(), "10.34.5")
	if err != nil {
		t.Fatalf("EnsurePnpm: %v", err)
	}
	want := filepath.Join(root, "tools", "pnpm", "10.34.5", "package", "bin", "pnpm.cjs")
	if bin != want {
		t.Fatalf("bin = %q, want %q", bin, want)
	}
	content, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read installed bin: %v", err)
	}
	if string(content) != "#!/usr/bin/env node\nconsole.log('pnpm')\n" {
		t.Fatalf("installed bin content = %q", content)
	}

	before := requests.Load()
	bin2, err := m.EnsurePnpm(context.Background(), "10.34.5")
	if err != nil {
		t.Fatalf("second EnsurePnpm: %v", err)
	}
	if bin2 != bin {
		t.Fatalf("second EnsurePnpm bin = %q, want %q", bin2, bin)
	}
	if got := requests.Load(); got != before {
		t.Fatalf("second EnsurePnpm made %d more requests, want an already-installed version to skip the network", got-before)
	}
}

func TestEnsurePnpmMissingBinGivesClearError(t *testing.T) {
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"9.0.0"}`,
	})
	srv, _ := pnpmRegistry(t, map[string][]byte{"9.0.0": tarball})

	m := NewManager(fakeVolume{root: t.TempDir()}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	_, err := m.EnsurePnpm(context.Background(), "9.0.0")
	if err == nil {
		t.Fatal("EnsurePnpm with no package/bin/pnpm.cjs: want error, got nil")
	}
	if !errors.Is(err, errPnpmBinMissing) {
		t.Fatalf("EnsurePnpm error = %v, want it to wrap errPnpmBinMissing", err)
	}
}

// TestEnsurePnpmRetrySucceedsAfterBadExtraction proves installDir can
// replace an install a previous, failed EnsurePnpm call left on disk: the
// first tarball lacks package/bin/pnpm.cjs, so tools/pnpm/10.34.5 exists
// but is unusable; the retry must still succeed once the registry serves a
// complete tarball for the same version.
func TestEnsurePnpmRetrySucceedsAfterBadExtraction(t *testing.T) {
	badTarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm"}`,
	})
	goodTarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	badSrv, _ := pnpmRegistry(t, map[string][]byte{"10.34.5": badTarball})
	goodSrv, _ := pnpmRegistry(t, map[string][]byte{"10.34.5": goodTarball})

	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, http.DefaultClient, nil)

	m.NPMRegistry = badSrv.URL
	if _, err := m.EnsurePnpm(context.Background(), "10.34.5"); !errors.Is(err, errPnpmBinMissing) {
		t.Fatalf("first EnsurePnpm error = %v, want errPnpmBinMissing", err)
	}

	m.NPMRegistry = goodSrv.URL
	bin, err := m.EnsurePnpm(context.Background(), "10.34.5")
	if err != nil {
		t.Fatalf("retry EnsurePnpm: %v", err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("stat installed bin after retry: %v", err)
	}
}

func TestEnsurePnpmUnknownVersion(t *testing.T) {
	srv, _ := pnpmRegistry(t, map[string][]byte{})
	m := NewManager(fakeVolume{root: t.TempDir(), settings: store.Settings{}}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	if _, err := m.EnsurePnpm(context.Background(), "0.0.1"); err == nil {
		t.Fatal("EnsurePnpm with an unpublished version: want error, got nil")
	}
}
