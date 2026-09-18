//go:build integration

// Integration tests against the real pnpm and Trivy binaries (spec section
// 9). They skip with a clear message instead of failing when a tool is
// absent from PATH, so a machine without Trivy still runs the rest of the
// suite. Download retries, integrity mismatches and an unreachable
// registry are already covered against httptest, with no build tag, in
// npm/registry_test.go: that coverage needs no real tool and no network,
// so it stays a unit test instead of being duplicated here.
package runner

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/sbom"
)

// threeDepManifest is a package.json with three exact-version direct
// dependencies, the shape spec section 9 asks the integration level to
// resolve with the real pnpm binary.
const threeDepManifest = `{
  "name": "sealift-integration-fixture",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.21",
    "chalk": "4.1.2",
    "uuid": "9.0.1"
  }
}`

func testTarget() store.Target {
	return store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"}
}

// testVolume is the narrow store.Volume tools.Manager needs, backed by a
// throwaway directory instead of a full store.Store.
type testVolume struct{ root string }

func (v testVolume) Root() string             { return v.root }
func (v testVolume) Settings() store.Settings { return store.Settings{Target: testTarget()} }

func TestPnpmResolvesThreeDependencyProject(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found on PATH: install Node.js to run this test")
	}

	dataDir := t.TempDir()
	mgr := tools.NewManager(testVolume{root: dataDir}, &http.Client{Timeout: 2 * time.Minute}, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pnpmBin, err := mgr.EnsurePnpm(ctx, "10.34.5")
	if err != nil {
		t.Fatalf("EnsurePnpm: %v", err)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(threeDepManifest), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	cacheDir := filepath.Join(dataDir, "cache", "pnpm")
	cli := NewPnpmCLI(pnpmBin, cacheDir, nil)

	res, err := cli.Resolve(ctx, ResolveInput{Dir: projectDir, Manifest: []byte(threeDepManifest), Target: testTarget()})
	if err != nil {
		t.Fatalf("Resolve: %v\noutput:\n%s", err, res.Output)
	}

	pkgs, err := npm.ParseLockfile(bytes.NewReader(res.Lockfile))
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if len(pkgs) < 3 {
		t.Fatalf("resolved %d packages, want at least the 3 direct dependencies", len(pkgs))
	}
}

func TestTrivyScansResolvedProject(t *testing.T) {
	trivyBin, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy not found on PATH: install Trivy (https://github.com/aquasecurity/trivy) to run this test")
	}

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.cdx.json")
	reportPath := filepath.Join(dir, "report.trivy.json")

	f, err := os.Create(sbomPath)
	if err != nil {
		t.Fatalf("create sbom: %v", err)
	}
	err = sbom.WriteCycloneDX(f, []sbom.Component{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "chalk", Version: "4.1.2"},
		{Name: "uuid", Version: "9.0.1"},
	})
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cli := NewTrivyCLI(trivyBin, filepath.Join(dir, "trivy-cache"), nil)

	// ScanSBOM passes --skip-db-update: production refreshes the database
	// once per job, not once per scan. This test's own cache starts empty
	// under t.TempDir, and Trivy refuses --skip-db-update against a cache
	// with no database at all, so the scan below needs this download
	// first, the same order the analysis job itself follows.
	if _, err := cli.UpdateDB(ctx); err != nil {
		t.Skipf("trivy UpdateDB: %v (no network access to download the vulnerability database)", err)
	}

	if _, err := cli.ScanSBOM(ctx, sbomPath, reportPath); err != nil {
		t.Fatalf("ScanSBOM: %v", err)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("stat report: %v", err)
	}
}
