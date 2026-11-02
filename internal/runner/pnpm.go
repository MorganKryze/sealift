package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
)

// Pnpm resolves a package.json into a pnpm-lock.yaml without installing
// anything, so a resolution only pays for registry metadata.
type Pnpm interface {
	Resolve(ctx context.Context, in ResolveInput) (ResolveResult, error)
}

// ResolveInput is a resolution request. Dir is a temporary directory the
// caller owns; Resolve writes the manifest and workspace file into it and
// reads pnpm-lock.yaml back from it.
//
// MinReleaseAgeDays above zero holds every package back to releases at
// least that old. The exact versions the manifest pins stay exempt: the
// caller picked those and judges their age itself. The exemption names the
// version, so the same package elsewhere in the tree still waits.
type ResolveInput struct {
	Dir               string
	Manifest          []byte
	Target            store.Target
	MinReleaseAgeDays int
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
	NodeVersion              string                 `yaml:"nodeVersion"`
	SupportedArchitectures   supportedArchitectures `yaml:"supportedArchitectures"`
	MinimumReleaseAge        int                    `yaml:"minimumReleaseAge,omitempty"` // minutes
	MinimumReleaseAgeExclude []string               `yaml:"minimumReleaseAgeExclude,omitempty"`
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
	if in.MinReleaseAgeDays > 0 {
		pinned, err := pinnedDependencies(in.Manifest)
		if err != nil {
			return ResolveResult{}, fmt.Errorf("read manifest: %w", err)
		}
		ws.MinimumReleaseAge = in.MinReleaseAgeDays * 24 * 60
		ws.MinimumReleaseAgeExclude = pinned
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

// pinnedDependencies lists the name@version pairs a manifest pins exactly,
// sorted so the workspace file stays reproducible.
func pinnedDependencies(manifest []byte) ([]string, error) {
	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(manifest, &doc); err != nil {
		return nil, err
	}
	pinned := map[string]bool{}
	for _, group := range []map[string]string{doc.Dependencies, doc.DevDependencies, doc.OptionalDependencies, doc.PeerDependencies} {
		for name, version := range group {
			if npm.IsExactVersion(version) {
				pinned[name+"@"+version] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(pinned)), nil
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
