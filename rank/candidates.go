package rank

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// Signal names a fact about a candidate version worth the user's attention.
type Signal string

// Signals. The first four block a candidate from being the best one.
const (
	TooRecent          Signal = "too-recent"
	NodeMismatch       Signal = "node-mismatch"
	Unresolvable       Signal = "does-not-resolve"
	Deprecated         Signal = "deprecated"
	InstallScriptAdded Signal = "install-script-added"
	ProvenanceLost     Signal = "provenance-lost"
	PublisherChanged   Signal = "publisher-changed"
	MajorJump          Signal = "major-jump"
)

// Blocking reports whether the signal keeps a candidate from being the best one.
func (s Signal) Blocking() bool {
	return s == TooRecent || s == NodeMismatch || s == Unresolvable || s == Deprecated
}

// Hit is a signal with the evidence behind it.
type Hit struct {
	Signal   Signal
	Evidence string
}

// Facts are what the registry and the resolution say about one version.
type Facts struct {
	Version          string
	Published        time.Time
	Deprecated       string
	NodeRange        string
	NodeCompatible   bool
	Resolves         bool
	HasInstallScript bool
	HasProvenance    bool
	Publisher        string
}

// Policy holds the settings signals depend on.
type Policy struct {
	Now           time.Time
	MinReleaseAge time.Duration
	TargetNode    string
}

// Signals compares a candidate with the current version and returns every
// signal that applies, blocking ones first. A zero candidate.Published
// counts as too recent.
func Signals(current, candidate Facts, p Policy) []Hit {
	var hits []Hit
	if candidate.Published.IsZero() {
		hits = append(hits, Hit{TooRecent, "the registry lists no publication time"})
	} else if age := p.Now.Sub(candidate.Published); age < p.MinReleaseAge {
		hits = append(hits, Hit{TooRecent, fmt.Sprintf("published on %s, %d days ago; the minimum is %d days",
			candidate.Published.Format(time.DateOnly), int(age.Hours()/24), int(p.MinReleaseAge.Hours()/24))})
	}
	if !candidate.NodeCompatible {
		hits = append(hits, Hit{NodeMismatch, fmt.Sprintf("engines.node %q excludes Node %s", candidate.NodeRange, p.TargetNode)})
	}
	if !candidate.Resolves {
		hits = append(hits, Hit{Unresolvable, "pnpm could not resolve this version with the project's peer dependencies"})
	}
	if candidate.Deprecated != "" {
		hits = append(hits, Hit{Deprecated, candidate.Deprecated})
	}
	if candidate.HasInstallScript && !current.HasInstallScript {
		hits = append(hits, Hit{InstallScriptAdded, "runs an install script; " + current.Version + " does not"})
	}
	if current.HasProvenance && !candidate.HasProvenance {
		hits = append(hits, Hit{ProvenanceLost, current.Version + " has a provenance attestation; this version has none"})
	}
	if candidate.Publisher != "" && current.Publisher != "" && candidate.Publisher != current.Publisher {
		hits = append(hits, Hit{PublisherChanged, fmt.Sprintf("published by %s; %s was published by %s", candidate.Publisher, current.Version, current.Publisher)})
	}
	if JumpOf(current.Version, candidate.Version) == OtherMajor {
		hits = append(hits, Hit{MajorJump, "leaves major version " + majorOf(current.Version)})
	}
	return hits
}

// Jump classifies the distance between two versions.
type Jump int

// Jumps, smallest first.
const (
	SameMinor Jump = iota
	SameMajor
	OtherMajor
)

// JumpOf classifies the move between two versions. A string that is not a
// version counts as OtherMajor.
func JumpOf(from, to string) Jump {
	a, errA := semver.StrictNewVersion(from)
	b, errB := semver.StrictNewVersion(to)
	switch {
	case errA != nil || errB != nil || a.Major() != b.Major():
		return OtherMajor
	case a.Minor() != b.Minor():
		return SameMajor
	}
	return SameMinor
}

func majorOf(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

// Candidate is a newer version with its vulnerability vector and signals.
type Candidate struct {
	Version string
	Vector  Vector
	Hits    []Hit
}

// Blocked reports whether a blocking signal applies to the candidate.
func (c Candidate) Blocked() bool {
	return slices.ContainsFunc(c.Hits, func(h Hit) bool { return h.Signal.Blocking() })
}

// Best returns the unblocked candidate with the lowest vector. Ties go to
// the smallest jump from current, then to the lower version. It returns
// false when no unblocked candidate has a lower vector than current.
func Best(current string, currentVector Vector, candidates []Candidate) (Candidate, bool) {
	var open []Candidate
	for _, c := range candidates {
		if !c.Blocked() {
			open = append(open, c)
		}
	}
	if len(open) == 0 {
		return Candidate{}, false
	}
	slices.SortFunc(open, func(a, b Candidate) int {
		return cmp.Or(
			a.Vector.Compare(b.Vector),
			cmp.Compare(JumpOf(current, a.Version), JumpOf(current, b.Version)),
			compareVersions(a.Version, b.Version),
		)
	})
	if open[0].Vector.Compare(currentVector) >= 0 {
		return Candidate{}, false
	}
	return open[0], true
}

// KeyVersions picks the candidates to resolve first: for each fixed version
// Trivy reports, the lowest candidate at or above it; then the latest patch,
// the latest in the current major, and the latest overall. newer must be
// ascending, as npm.NewerStable returns it.
func KeyVersions(current string, newer, fixed []string) []string {
	var keys []string
	add := func(v string) {
		if v != "" && !slices.Contains(keys, v) {
			keys = append(keys, v)
		}
	}
	for _, list := range fixed {
		for _, f := range strings.Split(list, ",") {
			fv, err := semver.StrictNewVersion(strings.TrimSpace(f))
			if err != nil {
				continue
			}
			for _, v := range newer {
				if nv, err := semver.StrictNewVersion(v); err == nil && !nv.LessThan(fv) {
					add(v)
					break
				}
			}
		}
	}
	var patch, minor string
	for _, v := range newer {
		switch JumpOf(current, v) {
		case SameMinor:
			patch, minor = v, v
		case SameMajor:
			minor = v
		case OtherMajor:
		}
	}
	add(patch)
	add(minor)
	if len(newer) > 0 {
		add(newer[len(newer)-1])
	}
	return keys
}

func compareVersions(a, b string) int {
	va, errA := semver.StrictNewVersion(a)
	vb, errB := semver.StrictNewVersion(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	return va.Compare(vb)
}

// Status tells how an update changes a vulnerability.
type Status string

// Statuses of a vulnerability after an update.
const (
	Fixed      Status = "fixed"
	Remaining  Status = "remaining"
	Introduced Status = "introduced"
)

// Change is one vulnerability with its status after an update.
type Change struct {
	Finding Finding
	Status  Status
}

// Diff compares the vulnerability sets before and after an update. Changes
// come sorted by ID; remaining and introduced ones carry the finding after
// the update.
func Diff(before, after map[string]Finding) []Change {
	var changes []Change
	for id, f := range before {
		if a, ok := after[id]; ok {
			changes = append(changes, Change{a, Remaining})
		} else {
			changes = append(changes, Change{f, Fixed})
		}
	}
	for id, f := range after {
		if _, ok := before[id]; !ok {
			changes = append(changes, Change{f, Introduced})
		}
	}
	slices.SortFunc(changes, func(a, b Change) int { return strings.Compare(a.Finding.ID, b.Finding.ID) })
	return changes
}
