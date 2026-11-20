package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// Uv resolves a pip project's pins into the full set of packages it
// installs, without building or installing anything.
type Uv interface {
	Compile(ctx context.Context, in CompileInput) (CompileResult, error)
}

// CompileInput is one resolution. Requirements and Constraints are the
// files uv reads, written by the caller from the project's pins: uv never
// reads the files a user uploaded.
//
// ExcludeNewer holds every package back to releases uploaded before it.
// Each name in Exempt is held back to ExemptUntil instead: the pins fix
// those versions, and the caller judges their age itself.
type CompileInput struct {
	Bin          string // the installed uv
	Dir          string // a fresh resolve directory the caller owns
	Requirements []byte // requirements.in
	Constraints  []byte // constraints.txt, empty when none
	Target       store.PipTarget
	Index        string
	ExcludeNewer time.Time
	Exempt       []string // normalized names of every pin
	ExemptUntil  time.Time
}

// Resolved is one package of a resolution, by normalized name.
type Resolved struct{ Name, Version string }

// CompileResult is the outcome of a resolution.
type CompileResult struct {
	Lock   []byte     // requirements.lock as uv wrote it
	Set    []Resolved // parsed from Lock, sorted by normalized name
	Output string     // uv's stderr and stdout, credentials stripped, for the log
}

// UvCLI resolves with the uv binary each input names.
type UvCLI struct {
	python   string
	cacheDir string
	asUser   *Credential
}

// NewUvCLI builds a UvCLI. python is the interpreter uv needs to start: it
// never builds or runs a package, and the target's Python version decides
// the resolution. Empty means the server found none. cacheDir holds uv's
// cache. asUser is nil outside the container.
func NewUvCLI(python, cacheDir string, asUser *Credential) *UvCLI {
	return &UvCLI{python: python, cacheDir: cacheDir, asUser: asUser}
}

const (
	// uvLockLimit bounds the lock uv writes. A lock line runs under 100
	// bytes, so this holds tens of thousands of packages.
	uvLockLimit = 8 << 20
	// uvOutputLimit bounds the part of uv's output kept for the log. The
	// cause of a failure comes last, so the end is kept.
	uvOutputLimit = 1 << 20
	// uvFailureLimit bounds the part of uv's output a failure message
	// carries; the job's log keeps the rest.
	uvFailureLimit = 600
)

// Compile writes the inputs into in.Dir, runs uv there and reads the lock
// back. uv builds nothing, reads no configuration file, downloads no Python
// and uses in.Index alone.
func (c *UvCLI) Compile(ctx context.Context, in CompileInput) (CompileResult, error) {
	if c.python == "" {
		return CompileResult{}, errors.New("uv needs a Python interpreter to start; none was found on the server's PATH")
	}
	if err := os.WriteFile(filepath.Join(in.Dir, "requirements.in"), in.Requirements, 0o664); err != nil {
		return CompileResult{}, fmt.Errorf("write requirements.in: %w", err)
	}
	if len(in.Constraints) > 0 {
		if err := os.WriteFile(filepath.Join(in.Dir, "constraints.txt"), in.Constraints, 0o664); err != nil {
			return CompileResult{}, fmt.Errorf("write constraints.txt: %w", err)
		}
	}

	output, runErr := run(ctx, in.Dir, in.Bin, uvArgs(in, c.python, c.cacheDir), c.asUser)
	output = keepTail(StripURLCredentials(output), uvOutputLimit)
	if runErr != nil {
		if reason := uvFailure(output); reason != "" {
			return CompileResult{Output: output}, fmt.Errorf("uv pip compile: %s: %w", reason, runErr)
		}
		return CompileResult{Output: output}, fmt.Errorf("uv pip compile: %w", runErr)
	}

	lock, err := readBounded(filepath.Join(in.Dir, "requirements.lock"), uvLockLimit)
	if err != nil {
		return CompileResult{Output: output}, fmt.Errorf("read requirements.lock: %w", err)
	}
	set, err := parseLock(lock)
	if err != nil {
		return CompileResult{Output: output}, err
	}
	return CompileResult{Lock: lock, Set: set, Output: output}, nil
}

// uvArgs is uv's command line for in. Only the files written into the
// resolve directory and these flags reach uv: childEnv drops every UV_,
// PIP_ and PYTHON variable, and --no-config skips uv.toml and pip.conf.
func uvArgs(in CompileInput, python, cacheDir string) []string {
	args := []string{"pip", "compile", "requirements.in"}
	if len(in.Constraints) > 0 {
		args = append(args, "-c", "constraints.txt")
	}
	args = append(args,
		"--python", python,
		"--python-version", in.Target.Python,
		"--python-platform", in.Target.CPU+"-manylinux_"+strings.ReplaceAll(in.Target.Glibc, ".", "_"),
		"--no-build", "--no-config", "--no-python-downloads",
		"--index-url", in.Index,
		"--cache-dir", cacheDir,
		"--exclude-newer", uvTime(in.ExcludeNewer),
	)
	until := uvTime(in.ExemptUntil)
	for _, name := range in.Exempt {
		args = append(args, "--exclude-newer-package", name+"="+until)
	}
	return append(args, "--no-header", "--no-annotate", "--output-file", "requirements.lock")
}

func uvTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// lockLine is one package line of a lock uv writes: name==version, then
// an optional marker.
var lockLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)\s*(?:;.*)?$`)

// parseLock reads the packages of a lock uv wrote, refusing any line that
// is not one exact package version.
func parseLock(data []byte) ([]Resolved, error) {
	if len(data) > uvLockLimit {
		return nil, fmt.Errorf("requirements.lock is larger than %d MiB", uvLockLimit>>20)
	}
	set := []Resolved{}
	seen := map[string]int{}
	for i, line := range strings.Split(string(data), "\n") {
		n := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if at := strings.Index(line, " #"); at >= 0 {
			line = strings.TrimSpace(line[:at])
		}
		m := lockLine.FindStringSubmatch(line)
		if m == nil || !pip.ValidName(m[1]) || !pip.IsExactVersion(m[2]) {
			return nil, fmt.Errorf("requirements.lock line %d: %q is not one exact package version", n, cleanLimited(line, 200))
		}
		name := pip.Normalize(m[1])
		if first, dup := seen[name]; dup {
			return nil, fmt.Errorf("requirements.lock line %d: %s is already on line %d", n, name, first)
		}
		seen[name] = n
		set = append(set, Resolved{Name: name, Version: m[2]})
	}
	slices.SortFunc(set, func(a, b Resolved) int { return strings.Compare(a.Name, b.Name) })
	return set, nil
}

// uvFailure picks the explanation of a failed run out of uv's output: the
// first error line, the cause or "Caused by" lines under it, and the hint
// lines, cleaned and cut to uvFailureLimit runes. Only lines that start
// with error: or hint: open a part, so a warning uv prints never counts.
func uvFailure(output string) string {
	var head string
	var body []string
	open := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		indented := strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
		switch {
		case line == "":
			open = false
		case strings.HasPrefix(raw, "error:"):
			if head == "" {
				head = strings.TrimSpace(strings.TrimPrefix(line, "error:"))
				open = true
			} else {
				open = false
			}
		case strings.HasPrefix(raw, "hint:") && head != "":
			body = append(body, line)
			open = true
		case open && indented:
			for _, prefix := range []string{"cause:", "Caused by:"} {
				line = strings.TrimSpace(strings.TrimPrefix(line, prefix))
			}
			body = append(body, line)
		default:
			open = false
		}
	}
	if head == "" {
		return ""
	}
	if len(body) > 0 {
		head += ": " + strings.Join(body, " ")
	}
	return cleanLimited(head, uvFailureLimit)
}

// keepTail keeps the last limit bytes of s, and says it cut the rest.
func keepTail(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return fmt.Sprintf("[uv output cut to its last %d MiB]\n", limit>>20) + s[len(s)-limit:]
}

// readBounded reads the file at path, refusing one above limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(f, limit+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB", filepath.Base(path), limit>>20)
	}
	return buf.Bytes(), nil
}
