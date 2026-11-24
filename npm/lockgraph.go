package npm

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type lockRef struct {
	Version string `yaml:"version"`
}

type rawLockGraph struct {
	LockfileVersion string `yaml:"lockfileVersion"`
	Importers       map[string]struct {
		Dependencies         map[string]lockRef `yaml:"dependencies"`
		DevDependencies      map[string]lockRef `yaml:"devDependencies"`
		OptionalDependencies map[string]lockRef `yaml:"optionalDependencies"`
	} `yaml:"importers"`
	Snapshots map[string]struct {
		Dependencies         map[string]string `yaml:"dependencies"`
		OptionalDependencies map[string]string `yaml:"optionalDependencies"`
	} `yaml:"snapshots"`
}

// LockHolders reads a pnpm 9.0 lockfile and maps each package it holds,
// keyed "name@version", to the sorted names of the importer's direct
// dependencies whose tree reaches it. A package no direct dependency
// reaches is absent.
func LockHolders(r io.Reader) (map[string][]string, error) {
	var raw rawLockGraph
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse pnpm lockfile: %w", err)
	}
	if raw.LockfileVersion != "9.0" {
		return nil, fmt.Errorf("pnpm lockfile version %q: only 9.0 is supported", raw.LockfileVersion)
	}
	edges := map[string][]string{}
	for key, s := range raw.Snapshots {
		from := snapshotKey(key)
		for _, deps := range []map[string]string{s.Dependencies, s.OptionalDependencies} {
			for name, version := range deps {
				edges[from] = append(edges[from], refKey(name, version))
			}
		}
	}
	holders := map[string][]string{}
	for _, imp := range raw.Importers {
		for _, deps := range []map[string]lockRef{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for direct, ref := range deps {
				seen := map[string]bool{}
				queue := []string{refKey(direct, ref.Version)}
				for len(queue) > 0 {
					key := queue[0]
					queue = queue[1:]
					if seen[key] {
						continue
					}
					seen[key] = true
					if !slices.Contains(holders[key], direct) {
						holders[key] = append(holders[key], direct)
					}
					queue = append(queue, edges[key]...)
				}
			}
		}
	}
	for key := range holders {
		slices.Sort(holders[key])
	}
	return holders, nil
}

// snapshotKey drops the peer suffix of a snapshot key.
func snapshotKey(key string) string {
	if i := strings.Index(key, "("); i > 0 {
		return key[:i]
	}
	return key
}

// refKey is the "name@version" a dependency reference points to: an alias
// such as "other@1.0.0" names its own package, a plain version the
// dependency's name. The peer suffix is dropped.
func refKey(name, version string) string {
	version = snapshotKey(strings.TrimPrefix(version, "npm:"))
	if i := strings.LastIndex(version, "@"); i > 0 {
		return version
	}
	return name + "@" + version
}
