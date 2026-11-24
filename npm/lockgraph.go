package npm

import (
	"errors"
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

// maxLockVisits caps the packages a LockHolders call visits, summed over
// its keys. A real lockfile holds a few thousand packages and the walk
// asks about a handful of them, so a million visits leaves wide room while
// keeping a crafted lockfile from holding an export for minutes.
var maxLockVisits = 1_000_000

// ErrLockTooLarge is LockHolders refusing a walk past maxLockVisits.
var ErrLockTooLarge = errors.New("pnpm lockfile too large to walk")

// LockHolders reads a pnpm 9.0 lockfile and maps each of keys, written
// "name@version", to the sorted names of the importer's direct
// dependencies whose tree reaches it. A key no direct dependency reaches
// is absent. It walks back from each key and refuses a lockfile that
// would take more than maxLockVisits visits.
func LockHolders(r io.Reader, keys []string) (map[string][]string, error) {
	var raw rawLockGraph
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse pnpm lockfile: %w", err)
	}
	if raw.LockfileVersion != "9.0" {
		return nil, fmt.Errorf("pnpm lockfile version %q: only 9.0 is supported", raw.LockfileVersion)
	}
	parents := map[string][]string{}
	for key, s := range raw.Snapshots {
		from := snapshotKey(key)
		for _, deps := range []map[string]string{s.Dependencies, s.OptionalDependencies} {
			for name, version := range deps {
				to := refKey(name, version)
				parents[to] = append(parents[to], from)
			}
		}
	}
	directs := map[string][]string{}
	for _, imp := range raw.Importers {
		for _, deps := range []map[string]lockRef{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for direct, ref := range deps {
				root := refKey(direct, ref.Version)
				if !slices.Contains(directs[root], direct) {
					directs[root] = append(directs[root], direct)
				}
			}
		}
	}
	holders := map[string][]string{}
	visits := 0
	for _, target := range keys {
		if _, done := holders[target]; done {
			continue
		}
		var found []string
		seen := map[string]bool{target: true}
		queue := []string{target}
		for len(queue) > 0 {
			key := queue[0]
			queue = queue[1:]
			if visits++; visits > maxLockVisits {
				return nil, fmt.Errorf("%w: walking back to its packages takes more than %d visits", ErrLockTooLarge, maxLockVisits)
			}
			for _, d := range directs[key] {
				if !slices.Contains(found, d) {
					found = append(found, d)
				}
			}
			for _, p := range parents[key] {
				if !seen[p] {
					seen[p] = true
					queue = append(queue, p)
				}
			}
		}
		slices.Sort(found)
		holders[target] = found
	}
	for key, found := range holders {
		if len(found) == 0 {
			delete(holders, key)
		}
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
