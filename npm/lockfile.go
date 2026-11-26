package npm

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// LockPackage is one resolved package of a pnpm lockfile.
type LockPackage struct {
	Name      string
	Version   string
	Integrity string // SRI string, such as "sha512-..."
	OS        []string
	CPU       []string
	Libc      []string
	Engines   map[string]string
}

// Key returns "name@version", the form Trivy findings and rank indexes use.
func (p LockPackage) Key() string {
	return p.Name + "@" + p.Version
}

type rawLockfile struct {
	LockfileVersion string `yaml:"lockfileVersion"`
	Packages        map[string]struct {
		Resolution struct {
			Integrity string `yaml:"integrity"`
		} `yaml:"resolution"`
		// Decoded loosely by the document's own decoder, whose alias limit
		// then covers it, and read through Engines as a packument's are.
		Engines any      `yaml:"engines"`
		OS      []string `yaml:"os"`
		CPU     []string `yaml:"cpu"`
		Libc    []string `yaml:"libc"`
	} `yaml:"packages"`
}

// ParseLockfile reads a pnpm lockfile in format 9.0 and returns its packages
// sorted by name, then version. Every package must come from a registry.
func ParseLockfile(r io.Reader) ([]LockPackage, error) {
	var raw rawLockfile
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse pnpm lockfile: %w", err)
	}
	if raw.LockfileVersion != "9.0" {
		return nil, fmt.Errorf("pnpm lockfile version %q: only 9.0 is supported", raw.LockfileVersion)
	}
	pkgs := make([]LockPackage, 0, len(raw.Packages))
	for key, p := range raw.Packages {
		name, version, ok := splitKey(key)
		if !ok {
			return nil, fmt.Errorf("pnpm lockfile: malformed package key %q", key)
		}
		if !ValidName(name) {
			return nil, fmt.Errorf("pnpm lockfile: %q has an invalid package name", key)
		}
		if !IsExactVersion(version) {
			return nil, fmt.Errorf("pnpm lockfile: %q has a version that is not exact", key)
		}
		if p.Resolution.Integrity == "" {
			return nil, fmt.Errorf("pnpm lockfile: %s has no registry integrity", key)
		}
		pkgs = append(pkgs, LockPackage{
			Name:      name,
			Version:   version,
			Integrity: p.Resolution.Integrity,
			OS:        p.OS,
			CPU:       p.CPU,
			Libc:      p.Libc,
			Engines:   lockEngines(p.Engines),
		})
	}
	slices.SortFunc(pkgs, func(a, b LockPackage) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version))
	})
	return pkgs, nil
}

// lockEngines reads a lockfile's engines with the rules Engines applies to a
// packument. A value JSON cannot hold, such as a map with a key that is not a
// string, reads as no ranges.
func lockEngines(v any) map[string]string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil
	}
	var e Engines
	_ = json.Unmarshal(b.Bytes(), &e)
	return e
}

// splitKey splits "name@version" and "@scope/name@version".
func splitKey(key string) (name, version string, ok bool) {
	i := strings.LastIndex(key, "@")
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}
