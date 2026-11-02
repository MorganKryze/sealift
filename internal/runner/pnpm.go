package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/MorganKryze/sealift/internal/store"
)

// Pnpm resolves a package.json into a pnpm-lock.yaml without installing
// anything, so a resolution only pays for registry metadata.
type Pnpm interface {
	Resolve(ctx context.Context, in ResolveInput) (ResolveResult, error)
}

// ResolveInput is a resolution request. Dir is a temporary directory the
// caller owns; Resolve writes the manifest and workspace file into it and
// reads pnpm-lock.yaml back from it.
type ResolveInput struct {
	Dir      string
	Manifest []byte
	Target   store.Target
}

// ResolveResult is the outcome of a resolution.
type ResolveResult struct {
	Lockfile []byte // pnpm-lock.yaml
	Output   string // combined stdout and stderr, shown to the user on failure
}

// PnpmCLI resolves dependencies by running the pnpm CLI through Node.js,
// the packaging pnpm ships.
type PnpmCLI struct {
	pnpmCJS  string
	cacheDir string
	asUser   *Credential
}

// NewPnpmCLI builds a PnpmCLI. bin is the path to pnpm's own entry point,
// <pnpm dir>/package/bin/pnpm.cjs, run through node. cacheDir holds pnpm's
// content store and registry metadata cache. asUser is nil outside the
// container.
func NewPnpmCLI(bin, cacheDir string, asUser *Credential) *PnpmCLI {
	return &PnpmCLI{pnpmCJS: bin, cacheDir: cacheDir, asUser: asUser}
}

// workspaceFile is the subset of pnpm-workspace.yaml that pins a
// resolution to a target: the Node version engines checks run against, and
// the platforms pnpm downloads optional dependencies for.
type workspaceFile struct {
	NodeVersion            string                 `yaml:"nodeVersion"`
	SupportedArchitectures supportedArchitectures `yaml:"supportedArchitectures"`
}

type supportedArchitectures struct {
	OS   []string `yaml:"os"`
	CPU  []string `yaml:"cpu"`
	Libc []string `yaml:"libc,omitempty"`
}

// Resolve writes the manifest and a pnpm-workspace.yaml pinned to
// in.Target, runs "pnpm install --lockfile-only" and reads the resulting
// lockfile back. The store and cache sit under cacheDir, so resolutions
// share downloaded metadata across calls.
func (c *PnpmCLI) Resolve(ctx context.Context, in ResolveInput) (ResolveResult, error) {
	if err := os.WriteFile(filepath.Join(in.Dir, "package.json"), in.Manifest, 0o664); err != nil {
		return ResolveResult{}, fmt.Errorf("write package.json: %w", err)
	}

	ws := workspaceFile{
		NodeVersion: in.Target.Node,
		SupportedArchitectures: supportedArchitectures{
			OS:  []string{in.Target.OS},
			CPU: []string{in.Target.CPU},
		},
	}
	if in.Target.Libc != "" {
		ws.SupportedArchitectures.Libc = []string{in.Target.Libc}
	}
	wsBytes, err := yaml.Marshal(ws)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("marshal pnpm-workspace.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(in.Dir, "pnpm-workspace.yaml"), wsBytes, 0o664); err != nil {
		return ResolveResult{}, fmt.Errorf("write pnpm-workspace.yaml: %w", err)
	}

	args := []string{
		c.pnpmCJS,
		"install",
		"--lockfile-only",
		"--store-dir", filepath.Join(c.cacheDir, "store"),
		"--cache-dir", filepath.Join(c.cacheDir, "metadata"),
	}
	output, runErr := run(ctx, in.Dir, "node", args, c.asUser)
	if runErr != nil {
		if reason := pnpmFailure(output); reason != "" {
			return ResolveResult{Output: output}, fmt.Errorf("pnpm install: %s: %w", reason, runErr)
		}
		return ResolveResult{Output: output}, fmt.Errorf("pnpm install: %w", runErr)
	}

	lockfile, err := os.ReadFile(filepath.Join(in.Dir, "pnpm-lock.yaml"))
	if err != nil {
		return ResolveResult{Output: output}, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}
	return ResolveResult{Lockfile: lockfile, Output: output}, nil
}

// pnpmFailureLimit bounds the part of pnpm's output a failure message
// carries; the job's log keeps all of it.
const pnpmFailureLimit = 300

// urlCredentials matches the user and password of a URL, which pnpm prints
// as configured.
var urlCredentials = regexp.MustCompile(`://[^/\s]*@`)

// pnpmFailure picks the sentence that explains a failed install out of
// pnpm's output. pnpm 10 prints it on its ERR_PNPM_ line. Later versions
// print the code alone, then a cause chain whose last link is the root
// cause, wrapped over several lines. Both shapes run in production, since
// the target picks the pnpm version.
//
// A package controls its deprecation text, which pnpm prints on a WARN line
// before the error, line breaks included. So only a line that starts with a
// code counts, the last one wins, and the chain is read after it.
func pnpmFailure(output string) string {
	lines := strings.Split(output, "\n")
	header := -1
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ERR_PNPM_") || strings.HasPrefix(line, "Error: ERR_PNPM_") {
			header = i
		}
	}
	if header < 0 {
		return ""
	}
	for i, line := range lines[header+1:] {
		cause, ok := strings.CutPrefix(strings.TrimSpace(line), "\u2570\u2500\u25b6")
		if !ok {
			continue
		}
		parts := []string{cause}
		for _, next := range lines[header+i+2:] {
			next = strings.TrimSpace(next)
			if next == "" || strings.HasPrefix(next, "help:") {
				break
			}
			parts = append(parts, next)
		}
		return cleanFailure(strings.Join(parts, " "))
	}
	return cleanFailure(lines[header])
}

// cleanFailure readies pnpm's text for the screen and the API: no URL
// credentials, no control or format characters, a bounded length.
func cleanFailure(s string) string {
	s = urlCredentials.ReplaceAllString(s, "://")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	runes := []rune(strings.Join(strings.Fields(s), " "))
	if len(runes) <= pnpmFailureLimit {
		return string(runes)
	}
	return string(runes[:pnpmFailureLimit]) + "..."
}
