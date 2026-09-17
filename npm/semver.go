package npm

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
)

var (
	operatorSpace = regexp.MustCompile(`(>=|<=|>|<|=|\^|~)\s+`)
	wildcardTail  = regexp.MustCompile(`(\d+)((?:\.(?:x|X|\*))+)`)
)

// SatisfiesNode reports whether nodeVersion falls inside an engines.node
// range written with npm syntax. An empty range accepts every version.
func SatisfiesNode(rangeExpr, nodeVersion string) (bool, error) {
	if strings.TrimSpace(rangeExpr) == "" {
		return true, nil
	}
	v, err := semver.StrictNewVersion(nodeVersion)
	if err != nil {
		return false, fmt.Errorf("node version %q: %w", nodeVersion, err)
	}
	c, err := semver.NewConstraint(normalizeRange(rangeExpr))
	if err != nil {
		return false, fmt.Errorf("engines range %q: %w", rangeExpr, err)
	}
	return c.Check(v), nil
}

// normalizeRange rewrites the npm range syntax the semver package does not
// read: a space after an operator (">= 10") and wildcard segments ("10.x").
func normalizeRange(r string) string {
	r = operatorSpace.ReplaceAllString(strings.TrimSpace(r), "$1")
	return wildcardTail.ReplaceAllString(r, "$1")
}

// NewerStable returns the versions greater than current without a
// prerelease tag, in ascending order. It skips strings that are not versions.
func NewerStable(current string, versions []string) ([]string, error) {
	cur, err := semver.StrictNewVersion(current)
	if err != nil {
		return nil, fmt.Errorf("current version %q: %w", current, err)
	}
	var newer []*semver.Version
	for _, s := range versions {
		v, err := semver.StrictNewVersion(s)
		if err != nil || v.Prerelease() != "" || !v.GreaterThan(cur) {
			continue
		}
		newer = append(newer, v)
	}
	slices.SortFunc(newer, func(a, b *semver.Version) int { return a.Compare(b) })
	out := make([]string, len(newer))
	for i, v := range newer {
		out[i] = v.Original()
	}
	return out, nil
}
