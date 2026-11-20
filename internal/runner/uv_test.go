package runner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

func TestUvArgs(t *testing.T) {
	cut := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	base := CompileInput{
		Bin:          "/data/tools/uv/0.13.7/uv",
		Dir:          "/data/cache/resolve/abc",
		Requirements: []byte("mypy==1.11.2\nrequests==2.32.3\n"),
		Target:       store.DefaultPipTarget,
		Index:        "https://pypi.org/simple/",
		ExcludeNewer: cut,
		Exempt:       []string{"mypy", "requests"},
		ExemptUntil:  start,
	}
	withConstraints := base
	withConstraints.Constraints = []byte("urllib3==2.2.3\n")
	newer := base
	newer.Target = store.PipTarget{Python: "3.12.4", OS: "linux", CPU: "x86_64", Glibc: "2.31", UvVer: "0.13.7"}

	tail := []string{
		"--no-build", "--no-config", "--no-python-downloads",
		"--index-url", "https://pypi.org/simple/",
		"--cache-dir", "/data/cache/uv",
		"--exclude-newer", "2026-11-06T10:00:00Z",
		"--exclude-newer-package", "mypy=2026-11-20T10:00:00Z",
		"--exclude-newer-package", "requests=2026-11-20T10:00:00Z",
		"--no-header", "--no-annotate",
		"--output-file", "requirements.lock",
	}
	cases := []struct {
		name string
		in   CompileInput
		want []string
	}{
		{"requirements only", base, slices.Concat([]string{
			"pip", "compile", "requirements.in",
			"--python", "/usr/bin/python3",
			"--python-version", "3.11.2",
			"--python-platform", "x86_64-manylinux_2_28",
		}, tail)},
		{"with constraints", withConstraints, slices.Concat([]string{
			"pip", "compile", "requirements.in", "-c", "constraints.txt",
			"--python", "/usr/bin/python3",
			"--python-version", "3.11.2",
			"--python-platform", "x86_64-manylinux_2_28",
		}, tail)},
		{"another target", newer, slices.Concat([]string{
			"pip", "compile", "requirements.in",
			"--python", "/usr/bin/python3",
			"--python-version", "3.12.4",
			"--python-platform", "x86_64-manylinux_2_31",
		}, tail)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := uvArgs(c.in, "/usr/bin/python3", "/data/cache/uv")
			if !slices.Equal(got, c.want) {
				t.Errorf("uvArgs =\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

func TestUvChildEnvDropsIndexVariables(t *testing.T) {
	dropped := []string{"UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_CONFIG_FILE", "UV_PYTHON", "PIP_INDEX_URL", "VIRTUAL_ENV", "PYTHONPATH"}
	for _, name := range dropped {
		t.Setenv(name, "http://127.0.0.1:9/decoy")
	}
	env := childEnv()
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(dropped, name) {
			t.Errorf("childEnv holds %s", kv)
		}
	}
	if !slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "PATH=") }) {
		t.Errorf("childEnv = %q, lost PATH", env)
	}
}

func TestParseLock(t *testing.T) {
	cases := []struct {
		name    string
		lock    string
		want    []Resolved
		wantErr string
	}{
		{
			name: "comments, blank lines and markers",
			lock: "# a comment\n\nrequests==2.32.3\n  # an indented comment\nAsync_Timeout==5.0.1 ; python_full_version < '3.11.3'\r\nidna==3.10  # trailing comment\n",
			want: []Resolved{{"async-timeout", "5.0.1"}, {"idna", "3.10"}, {"requests", "2.32.3"}},
		},
		{name: "empty", lock: "", want: []Resolved{}},
		{name: "a range", lock: "requests==2.32.3\nidna>=3\n", wantErr: "line 2"},
		{name: "no version", lock: "requests\n", wantErr: "line 1"},
		{name: "an option", lock: "--index-url https://example.com/simple\n", wantErr: "line 1"},
		{name: "a bad version", lock: "requests==2.*\n", wantErr: "line 1"},
		{name: "a name twice", lock: "requests==2.32.3\nRequests==2.31.0\n", wantErr: "line 2"},
		{name: "too large", lock: strings.Repeat("#", uvLockLimit+1), wantErr: "8 MiB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseLock([]byte(c.lock))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("parseLock error = %v, want it to name %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLock: %v", err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("parseLock = %+v, want %+v", got, c.want)
			}
		})
	}
}

// The outputs below are uv 0.13's own, captured against a local index.
const (
	uvConflictOutput = `error: No solution found when resolving dependencies
  cause: Because all versions of alpha depend on beta{python_full_version < '3.11.3'}==2.0.0 and you require alpha==1.0.0, we can conclude that you require beta==2.0.0.
         And because you require beta==3.0.0, we can conclude that your requirements are unsatisfiable.
`
	uvSamePackageOutput = `error: No solution found when resolving dependencies
  cause: Because you require mypy-extensions==1.0.0 and mypy-extensions==1.1.0, we can conclude that your requirements are unsatisfiable.
`
	uvNoWheelOutput = `error: No solution found when resolving dependencies
  cause: Because eps==1.0.0 has no usable wheels and all versions of omega depend on eps==1.0.0, we can conclude that all versions of omega cannot be used.
         And because you require omega==1.0.0, we can conclude that your requirements are unsatisfiable.

hint: Wheels are required for ` + "`eps`" + ` because building from source is disabled for all packages (i.e., with ` + "`--no-build`" + `)
`
	uvFetchOutput = `warning: a warning a package cannot reach
error: Request failed after 3 retries
  Caused by: Failed to fetch: ` + "`http://user:secret@127.0.0.1:1/simple/alpha/`" + `
  Caused by: client error (Connect)
`
)

func TestUvFailure(t *testing.T) {
	cases := []struct {
		name, output, want string
	}{
		{
			name:   "conflict across two files",
			output: uvConflictOutput,
			want:   "No solution found when resolving dependencies: Because all versions of alpha depend on beta{python_full_version < '3.11.3'}==2.0.0 and you require alpha==1.0.0, we can conclude that you require beta==2.0.0. And because you require beta==3.0.0, we can conclude that your requirements are unsatisfiable.",
		},
		{
			name:   "the same package twice",
			output: uvSamePackageOutput,
			want:   "No solution found when resolving dependencies: Because you require mypy-extensions==1.0.0 and mypy-extensions==1.1.0, we can conclude that your requirements are unsatisfiable.",
		},
		{
			name:   "no usable wheels, with the hint",
			output: uvNoWheelOutput,
			want:   "No solution found when resolving dependencies: Because eps==1.0.0 has no usable wheels and all versions of omega depend on eps==1.0.0, we can conclude that all versions of omega cannot be used. And because you require omega==1.0.0, we can conclude that your requirements are unsatisfiable. hint: Wheels are required for `eps` because building from source is disabled for all packages (i.e., with `--no-build`)",
		},
		{
			name:   "a cause chain, credentials stripped",
			output: uvFetchOutput,
			want:   "Request failed after 3 retries: Failed to fetch: `http://127.0.0.1:1/simple/alpha/` client error (Connect)",
		},
		{name: "no error line", output: "Resolved 2 packages in 34ms\n", want: ""},
		{
			name:   "control characters removed",
			output: "error: bad\x1b[31m name\u200b here\n",
			want:   "bad[31m name here",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := uvFailure(c.output); got != c.want {
				t.Errorf("uvFailure =\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

func TestUvFailureIsCut(t *testing.T) {
	got := uvFailure("error: " + strings.Repeat("é", 2000) + "\n")
	if n := len([]rune(got)); n != uvFailureLimit+3 || !strings.HasSuffix(got, "...") {
		t.Errorf("uvFailure = %d runes ending %q, want %d runes and ...", n, got[len(got)-3:], uvFailureLimit+3)
	}
}

// writeFakeUv writes an executable that stands in for uv: it copies its
// inputs and arguments to capture, then runs body.
func writeFakeUv(t *testing.T, capture, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "uv")
	script := "#!/bin/sh\ncp requirements.in \"" + capture + "/requirements.in\"\n" +
		"[ -f constraints.txt ] && cp constraints.txt \"" + capture + "/constraints.txt\"\n" +
		"printf '%s\\n' \"$@\" > \"" + capture + "/args.txt\"\n" + body
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake uv: %v", err)
	}
	return path
}

func TestUvCompileWritesTheInputsAndReadsTheLock(t *testing.T) {
	capture := t.TempDir()
	bin := writeFakeUv(t, capture, "printf 'idna==3.10\\nrequests==2.32.3\\n' > requirements.lock\necho 'Resolved 2 packages'\n")
	in := CompileInput{
		Bin: bin, Dir: t.TempDir(),
		Requirements: []byte("requests==2.32.3\n"), Constraints: []byte("idna==3.10\n"),
		Target: store.DefaultPipTarget, Index: "http://127.0.0.1:1/simple/",
		ExcludeNewer: time.Now(), Exempt: []string{"idna", "requests"}, ExemptUntil: time.Now(),
	}
	res, err := NewUvCLI("/usr/bin/python3", t.TempDir(), nil).Compile(context.Background(), in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if string(res.Lock) != "idna==3.10\nrequests==2.32.3\n" {
		t.Errorf("Lock = %q", res.Lock)
	}
	if want := []Resolved{{"idna", "3.10"}, {"requests", "2.32.3"}}; !slices.Equal(res.Set, want) {
		t.Errorf("Set = %+v, want %+v", res.Set, want)
	}
	if !strings.Contains(res.Output, "Resolved 2 packages") {
		t.Errorf("Output = %q, want uv's output", res.Output)
	}
	for name, want := range map[string]string{"requirements.in": "requests==2.32.3\n", "constraints.txt": "idna==3.10\n"} {
		got, err := os.ReadFile(filepath.Join(capture, name))
		if err != nil || string(got) != want {
			t.Errorf("uv read %s = %q (%v), want %q", name, got, err, want)
		}
	}
	args, _ := os.ReadFile(filepath.Join(capture, "args.txt"))
	if !strings.Contains(string(args), "-c\nconstraints.txt\n") {
		t.Errorf("args = %q, want -c constraints.txt", args)
	}
}

func TestUvCompileWritesNoConstraintsFileWhenThereAreNone(t *testing.T) {
	capture := t.TempDir()
	bin := writeFakeUv(t, capture, "printf 'requests==2.32.3\\n' > requirements.lock\n")
	dir := t.TempDir()
	in := CompileInput{Bin: bin, Dir: dir, Requirements: []byte("requests==2.32.3\n"), Target: store.DefaultPipTarget, Index: "http://127.0.0.1:1/simple/"}
	if _, err := NewUvCLI("/usr/bin/python3", t.TempDir(), nil).Compile(context.Background(), in); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "constraints.txt")); !os.IsNotExist(err) {
		t.Errorf("constraints.txt exists (%v), want none", err)
	}
}

func TestUvCompileFailureCarriesTheCause(t *testing.T) {
	capture := t.TempDir()
	bin := writeFakeUv(t, capture, "cat <<'EOF' >&2\n"+uvConflictOutput+"EOF\nexit 1\n")
	in := CompileInput{Bin: bin, Dir: t.TempDir(), Requirements: []byte("alpha==1.0.0\nbeta==3.0.0\n"), Target: store.DefaultPipTarget, Index: "http://127.0.0.1:1/simple/"}
	res, err := NewUvCLI("/usr/bin/python3", t.TempDir(), nil).Compile(context.Background(), in)
	if err == nil {
		t.Fatal("Compile succeeded, want the conflict")
	}
	if !strings.Contains(err.Error(), "you require beta==3.0.0") {
		t.Errorf("error = %q, want uv's cause", err)
	}
	if !strings.Contains(res.Output, "No solution found") {
		t.Errorf("Output = %q, want uv's whole output", res.Output)
	}
}

func TestUvCompileNeedsAnInterpreter(t *testing.T) {
	in := CompileInput{Bin: "/nonexistent/uv", Dir: t.TempDir(), Requirements: []byte("requests==2.32.3\n"), Target: store.DefaultPipTarget}
	_, err := NewUvCLI("", t.TempDir(), nil).Compile(context.Background(), in)
	want := "uv needs a Python interpreter to start; none was found on the server's PATH"
	if err == nil || err.Error() != want {
		t.Fatalf("Compile error = %v, want %q", err, want)
	}
}
