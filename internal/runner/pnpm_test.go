package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
)

// installFakeNode writes a fake node executable to a temporary directory
// and prepends it to PATH, so PnpmCLI.Resolve's "node <pnpm.cjs> install"
// call runs body instead of a real Node.js. body reads the resolution's
// working directory as its own cwd.
func installFakeNode(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "node")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake node: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestPnpmCLI_Resolve_Success(t *testing.T) {
	captureDir := t.TempDir()
	t.Setenv("CAPTURE_DIR", captureDir)
	installFakeNode(t, `cp package.json "$CAPTURE_DIR/package.json"
cp pnpm-workspace.yaml "$CAPTURE_DIR/workspace.yaml"
printf '%s\n' "$@" > "$CAPTURE_DIR/args.txt"
printf 'lockfileVersion: "9.0"\npackages: {}\n' > pnpm-lock.yaml
echo "resolution done"
`)

	workDir := t.TempDir()
	cacheDir := t.TempDir()
	manifest := []byte(`{"name":"probe","version":"0.0.0","dependencies":{"left-pad":"1.3.0"}}`)
	target := store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"}
	pnpmCJS := "/opt/tools/pnpm/10.34.5/package/bin/pnpm.cjs"

	cli := NewPnpmCLI(pnpmCJS, cacheDir, nil)
	result, err := cli.Resolve(context.Background(), ResolveInput{Dir: workDir, Manifest: manifest, Target: target})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	wantLock := "lockfileVersion: \"9.0\"\npackages: {}\n"
	if string(result.Lockfile) != wantLock {
		t.Errorf("Lockfile = %q, want %q", result.Lockfile, wantLock)
	}
	if !strings.Contains(result.Output, "resolution done") {
		t.Errorf("Output = %q, want it to contain %q", result.Output, "resolution done")
	}

	gotManifest, err := os.ReadFile(filepath.Join(captureDir, "package.json"))
	if err != nil {
		t.Fatalf("read captured package.json: %v", err)
	}
	if string(gotManifest) != string(manifest) {
		t.Errorf("package.json = %q, want %q", gotManifest, manifest)
	}

	gotWorkspace, err := os.ReadFile(filepath.Join(captureDir, "workspace.yaml"))
	if err != nil {
		t.Fatalf("read captured pnpm-workspace.yaml: %v", err)
	}
	wantWorkspace := "nodeVersion: 22.17.1\n" +
		"supportedArchitectures:\n" +
		"    os:\n" +
		"        - linux\n" +
		"    cpu:\n" +
		"        - x64\n" +
		"    libc:\n" +
		"        - glibc\n"
	if string(gotWorkspace) != wantWorkspace {
		t.Errorf("pnpm-workspace.yaml = %q, want %q", gotWorkspace, wantWorkspace)
	}

	gotArgs, err := os.ReadFile(filepath.Join(captureDir, "args.txt"))
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	wantArgs := strings.Join([]string{
		pnpmCJS,
		"install",
		"--lockfile-only",
		"--store-dir", filepath.Join(cacheDir, "store"),
		"--cache-dir", filepath.Join(cacheDir, "metadata"),
	}, "\n") + "\n"
	if string(gotArgs) != wantArgs {
		t.Errorf("args = %q, want %q", gotArgs, wantArgs)
	}
}

func TestPnpmCLI_Resolve_Failure(t *testing.T) {
	installFakeNode(t, `echo "ERR_PNPM_NO_MATCHING_VERSION left-pad@99.0.0" >&2
exit 1
`)

	workDir := t.TempDir()
	cacheDir := t.TempDir()
	manifest := []byte(`{"name":"probe","version":"0.0.0","dependencies":{"left-pad":"99.0.0"}}`)
	target := store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"}

	cli := NewPnpmCLI("/opt/tools/pnpm/10.34.5/package/bin/pnpm.cjs", cacheDir, nil)
	result, err := cli.Resolve(context.Background(), ResolveInput{Dir: workDir, Manifest: manifest, Target: target})
	if err == nil {
		t.Fatal("Resolve: want error, got nil")
	}
	if result.Lockfile != nil {
		t.Errorf("Lockfile = %q, want nil on failure", result.Lockfile)
	}
	if !strings.Contains(result.Output, "ERR_PNPM_NO_MATCHING_VERSION") {
		t.Errorf("Output = %q, want it to contain pnpm's error", result.Output)
	}
}
