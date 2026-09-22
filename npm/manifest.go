// Package npm reads npm and pnpm data: package.json manifests, pnpm
// lockfiles, registry metadata and package tarballs.
package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// DependencyKind names the package.json field a dependency comes from.
type DependencyKind string

// Dependency kinds, in the order ParseManifest returns them.
const (
	Prod     DependencyKind = "dependencies"
	Dev      DependencyKind = "devDependencies"
	Optional DependencyKind = "optionalDependencies"
)

// Dependency is a direct dependency declared in a package.json.
type Dependency struct {
	Name    string
	Version string
	Kind    DependencyKind
}

// Problem describes one package.json entry that blocks an analysis.
type Problem struct {
	Field  string // "dependencies", "pnpm.overrides", ...
	Name   string // dependency name, empty for a field-level problem
	Value  string
	Reason string
}

// Manifest holds the parts of a package.json that sealift reads.
type Manifest struct {
	Name         string
	Dependencies []Dependency
	unsupported  []string
}

type rawManifest struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Overrides            json.RawMessage   `json:"overrides"`
	Resolutions          json.RawMessage   `json:"resolutions"`
	PNPM                 struct {
		Overrides           json.RawMessage `json:"overrides"`
		PatchedDependencies json.RawMessage `json:"patchedDependencies"`
	} `json:"pnpm"`
}

// ParseManifest reads a package.json. Dependencies come back grouped by kind
// and sorted by name within each kind.
func ParseManifest(r io.Reader) (Manifest, error) {
	var raw rawManifest
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field == "" {
			return Manifest{}, errors.New("parse package.json: the file holds JSON, but not an object like a package.json")
		}
		return Manifest{}, fmt.Errorf("parse package.json: %w", err)
	}
	m := Manifest{Name: raw.Name}
	groups := []struct {
		kind DependencyKind
		deps map[string]string
	}{{Prod, raw.Dependencies}, {Dev, raw.DevDependencies}, {Optional, raw.OptionalDependencies}}
	for _, g := range groups {
		for _, name := range slices.Sorted(maps.Keys(g.deps)) {
			m.Dependencies = append(m.Dependencies, Dependency{Name: name, Version: g.deps[name], Kind: g.kind})
		}
	}
	fields := map[string]json.RawMessage{
		"overrides":                raw.Overrides,
		"resolutions":              raw.Resolutions,
		"pnpm.overrides":           raw.PNPM.Overrides,
		"pnpm.patchedDependencies": raw.PNPM.PatchedDependencies,
	}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		if len(fields[field]) > 0 {
			m.unsupported = append(m.unsupported, field)
		}
	}
	return m, nil
}

// Validate lists every entry that blocks an analysis: unsupported fields
// first, then dependencies that are not exact registry versions.
func (m Manifest) Validate() []Problem {
	var problems []Problem
	for _, field := range m.unsupported {
		problems = append(problems, Problem{Field: field, Reason: "not supported"})
	}
	if len(m.Dependencies) == 0 {
		problems = append(problems, Problem{Field: "dependencies", Reason: "lists no dependency to update"})
	}
	for _, d := range m.Dependencies {
		if reason := specProblem(d.Version); reason != "" {
			problems = append(problems, Problem{Field: string(d.Kind), Name: d.Name, Value: d.Version, Reason: reason})
		}
	}
	return problems
}

var sourcePrefixes = []string{"npm:", "git+", "git:", "github:", "file:", "link:", "workspace:", "http:", "https:"}

func specProblem(spec string) string {
	for _, prefix := range sourcePrefixes {
		if strings.HasPrefix(spec, prefix) {
			return "only npm registry versions are supported"
		}
	}
	if !IsExactVersion(spec) {
		return "version must be exact, such as 1.2.3"
	}
	return ""
}

// exactVersion is the SemVer 2.0.0 grammar, with no range operator.
var exactVersion = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// IsExactVersion reports whether s is a single SemVer 2.0.0 version.
func IsExactVersion(s string) bool {
	return exactVersion.MatchString(s)
}
