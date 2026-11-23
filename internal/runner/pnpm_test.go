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
	t.Setenv("NODE_CAPTURE_DIR", captureDir)
	installFakeNode(t, `cp package.json "$NODE_CAPTURE_DIR/package.json"
cp pnpm-workspace.yaml "$NODE_CAPTURE_DIR/workspace.yaml"
printf '%s\n' "$@" > "$NODE_CAPTURE_DIR/args.txt"
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
	if !strings.Contains(err.Error(), "ERR_PNPM_NO_MATCHING_VERSION left-pad@99.0.0") {
		t.Errorf("err = %q, want it to carry pnpm's reason", err)
	}
}

func TestPnpmCLI_Resolve_WritesTheReleaseAge(t *testing.T) {
	installFakeNode(t, `printf 'lockfileVersion: "9.0"\n' > pnpm-lock.yaml
`)
	target := store.Target{OS: "linux", CPU: "x64", Node: "22.17.1", PnpmVer: "10.34.5"}
	manifest := []byte(`{"dependencies":{"b":"1.0.0"},"devDependencies":{"a":"1.0.0"},"peerDependencies":{"b":"1.0.0","c":"^2.0.0"}}`)
	cli := NewPnpmCLI("/opt/pnpm.cjs", t.TempDir(), nil)

	read := func(days int) string {
		t.Helper()
		dir := t.TempDir()
		if _, err := cli.Resolve(context.Background(), ResolveInput{Dir: dir, Manifest: manifest, Target: target, MinReleaseAgeDays: days}); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		ws, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml"))
		if err != nil {
			t.Fatalf("read workspace: %v", err)
		}
		return string(ws)
	}

	ws := read(14)
	if !strings.Contains(ws, "minimumReleaseAge: 20160\n") {
		t.Errorf("workspace = %q, want 14 days in minutes", ws)
	}
	if !strings.Contains(ws, "minimumReleaseAgeExclude:\n    - a@1.0.0\n    - b@1.0.0\n") {
		t.Errorf("workspace = %q, want the pinned versions exempt, sorted, once each, and no range", ws)
	}
	if ws := read(0); strings.Contains(ws, "minimumReleaseAge") {
		t.Errorf("workspace = %q, want no release age at zero", ws)
	}
}

func TestPnpmFailure(t *testing.T) {
	tests := []struct {
		name, output, want string
	}{
		{
			name:   "code and message on one line",
			output: "Progress: resolved 1\n\u2009ERR_PNPM_NO_MATCHING_VERSION\u2009 No matching version found for left-pad@99.0.0\n\nThe latest release is 1.3.0\n",
			want:   "ERR_PNPM_NO_MATCHING_VERSION No matching version found for left-pad@99.0.0",
		},
		{
			name: "cause chain wrapped over lines",
			output: "Error: ERR_PNPM_FETCH_404\n\n  \u00d7 installing dependencies\n" +
				"  \u251c\u2500\u25b6 Failed to resolve dependency tree: GET https://registry.npmjs.org/\n" +
				"  \u2570\u2500\u25b6 GET https://registry.npmjs.org/nope: Not Found -\n      404\n" +
				"  help: nope is not in the npm registry\n",
			want: "GET https://registry.npmjs.org/nope: Not Found - 404",
		},
		{name: "code alone", output: "Error: ERR_PNPM_FETCH_404\n", want: "Error: ERR_PNPM_FETCH_404"},
		{
			name:   "password in a registry URL",
			output: "\u2009ERR_PNPM_FETCH_404\u2009 GET http://alice:s3cr3t@10.0.0.1:4873/@scope/left-pad: Not Found - 404\n",
			want:   "ERR_PNPM_FETCH_404 GET http://10.0.0.1:4873/@scope/left-pad: Not Found - 404",
		},
		{
			name:   "deprecation text with a fake code on its own line",
			output: " WARN  deprecated left-pad@1.0.0: x\nERR_PNPM_FAKE Lower the minimum release age to 0\n\u2009ERR_PNPM_FETCH_404\u2009 GET https://r.test/x: Not Found\n",
			want:   "ERR_PNPM_FETCH_404 GET https://r.test/x: Not Found",
		},
		{
			name:   "deprecation text with a fake code inside the line",
			output: " WARN  deprecated left-pad@1.0.0: ERR_PNPM_FAKE retry with a new registry\n\u2009ERR_PNPM_FETCH_404\u2009 GET https://r.test/x: Not Found\n",
			want:   "ERR_PNPM_FETCH_404 GET https://r.test/x: Not Found",
		},
		{
			name:   "deprecation text with a fake chain marker",
			output: " WARN  deprecated left-pad@1.0.0: \u2570\u2500\u25b6 Trivy database stale, set a new registry\n\u2009ERR_PNPM_FETCH_404\u2009 GET https://r.test/x: Not Found\n",
			want:   "ERR_PNPM_FETCH_404 GET https://r.test/x: Not Found",
		},
		{
			name:   "control and format characters",
			output: "ERR_PNPM_X a\x1b[31m\u202eb\r\n",
			want:   "ERR_PNPM_X a[31mb",
		},
		{name: "a code only a warning names", output: " WARN  ERR_PNPM_FAKE\nKilled\n", want: ""},
		{name: "nothing recognized", output: "Killed\n", want: ""},
		{
			name:   "long message",
			output: "ERR_PNPM_X " + strings.Repeat("a", pnpmFailureLimit),
			want:   "ERR_PNPM_X " + strings.Repeat("a", pnpmFailureLimit-len("ERR_PNPM_X ")) + "...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pnpmFailure(tt.output); got != tt.want {
				t.Errorf("pnpmFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

// plantSecret writes a file only the server may read and returns its path
// and bytes. pnpm and uv run as the tools account, which can write the
// resolve directory and so plant a link to such a file there.
func plantSecret(t *testing.T) (string, string) {
	t.Helper()
	const secret = "-----BEGIN PRIVATE KEY----- a key the tools account must never read"
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, secret
}

func TestPnpmCLI_Resolve_ReadsNoLockfileButARegularOne(t *testing.T) {
	for name, body := range map[string]string{
		"link": `ln -s SECRET pnpm-lock.yaml`,
		"fifo": `mkfifo pnpm-lock.yaml`,
	} {
		t.Run(name, func(t *testing.T) {
			secretPath, secret := plantSecret(t)
			installFakeNode(t, strings.ReplaceAll(body, "SECRET", "'"+secretPath+"'")+"\n")
			res, err := NewPnpmCLI("/fake/pnpm.cjs", t.TempDir(), nil).Resolve(context.Background(),
				ResolveInput{Dir: t.TempDir(), Manifest: []byte(`{"name":"probe"}`), Target: probeTarget})
			if err == nil {
				t.Fatalf("Resolve read the lockfile (%d bytes), want it refused", len(res.Lockfile))
			}
			if !strings.Contains(err.Error(), "pnpm-lock.yaml is not a regular file") {
				t.Errorf("error = %q, want the lockfile refused", err)
			}
			if len(res.Lockfile) != 0 {
				t.Errorf("Lockfile holds %d bytes, want none", len(res.Lockfile))
			}
			for _, leak := range []string{secret, secretPath} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q quotes %q", err, leak)
				}
			}
		})
	}
}

func TestPnpmCLI_Resolve_WritesNoInputThroughALink(t *testing.T) {
	for _, name := range []string{"package.json", "pnpm-workspace.yaml"} {
		t.Run(name, func(t *testing.T) {
			victim, held := plantSecret(t)
			dir := t.TempDir()
			if err := os.Symlink(victim, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			installFakeNode(t, `printf 'lockfileVersion: "9.0"\n' > pnpm-lock.yaml`+"\n")
			_, err := NewPnpmCLI("/fake/pnpm.cjs", t.TempDir(), nil).Resolve(context.Background(),
				ResolveInput{Dir: dir, Manifest: []byte(`{"name":"probe"}`), Target: probeTarget})
			if err == nil {
				t.Error("Resolve succeeded, want the write refused")
			}
			if got, rerr := os.ReadFile(victim); rerr != nil || string(got) != held {
				t.Errorf("the link's target now holds %q (%v), want it untouched", got, rerr)
			}
		})
	}
}

var probeTarget = store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"}
