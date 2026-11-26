package npm

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
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
		// then covers it, and read by lockEngines as a packument's are.
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
// packument: string values are kept, null reads as "", and a node value of
// another kind, other than 0 or false, reads as "not a string: " and its
// first 64 bytes. The value is walked, never copied whole, since a lockfile
// can alias one large value from every package.
func lockEngines(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for name, value := range m {
		switch x := value.(type) {
		case string:
			out[name] = x
		case nil:
			out[name] = ""
		default:
			if name == "node" && x != 0 && x != 0.0 && x != false {
				var b strings.Builder
				writeBounded(&b, x)
				t := b.String()
				if len(t) > 64 {
					t = strings.ToValidUTF8(t[:64], "")
				}
				out[name] = "not a string: " + t
			}
		}
	}
	return out
}

// writeBounded writes v in JSON form until b holds more than 64 bytes.
func writeBounded(b *strings.Builder, v any) {
	if b.Len() > 64 {
		return
	}
	switch x := v.(type) {
	case string:
		var q bytes.Buffer
		enc := json.NewEncoder(&q)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(strings.ToValidUTF8(x[:min(len(x), 65)], ""))
		b.Write(bytes.TrimSuffix(q.Bytes(), []byte("\n")))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if b.Len() > 64 {
				return
			}
			if i > 0 {
				b.WriteByte(',')
			}
			writeBounded(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		b.WriteByte('{')
		for i, k := range slices.Sorted(maps.Keys(x)) {
			if b.Len() > 64 {
				return
			}
			if i > 0 {
				b.WriteByte(',')
			}
			writeBounded(b, k)
			b.WriteByte(':')
			writeBounded(b, x[k])
		}
		b.WriteByte('}')
	case nil:
		b.WriteString("null")
	case bool, int, int64, uint64, float64:
		fmt.Fprint(b, x)
	default:
		// A kind yaml does not give today, such as a map with keys that are
		// not strings, is named rather than printed whole.
		b.WriteString("?")
	}
}

// splitKey splits "name@version" and "@scope/name@version".
func splitKey(key string) (name, version string, ok bool) {
	i := strings.LastIndex(key, "@")
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}
