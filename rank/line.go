package rank

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// SameLine reports whether to falls inside npm's caret range of from: the
// same major from 1.0.0, the same minor below it, the same patch below
// 0.1.0. It is false when either string is not a version.
func SameLine(from, to string) bool {
	a, errA := semver.StrictNewVersion(from)
	b, errB := semver.StrictNewVersion(to)
	if errA != nil || errB != nil || b.LessThan(a) {
		return false
	}
	// npm's caret admits a pre-release only on the tuple from already pins.
	if b.Prerelease() != "" && (a.Prerelease() == "" || a.Major() != b.Major() || a.Minor() != b.Minor() || a.Patch() != b.Patch()) {
		return false
	}
	return lineOf(a) == lineOf(b)
}

// LineOf names the line a version belongs to: "4", "0.18" or "0.0.3". It
// returns "" when version is not one.
func LineOf(version string) string {
	v, err := semver.StrictNewVersion(version)
	if err != nil {
		return ""
	}
	return lineOf(v)
}

func lineOf(v *semver.Version) string {
	switch {
	case v.Major() > 0:
		return fmt.Sprint(v.Major())
	case v.Minor() > 0:
		return fmt.Sprintf("0.%d", v.Minor())
	}
	return fmt.Sprintf("0.0.%d", v.Patch())
}

// leavesLine is the evidence of a major-jump signal.
func leavesLine(current string) string {
	v, err := semver.StrictNewVersion(current)
	switch {
	case err != nil:
		return "leaves the line of " + current
	case v.Major() > 0:
		return fmt.Sprintf("leaves major version %d", v.Major())
	case v.Minor() > 0:
		return fmt.Sprintf("leaves 0.%d.x", v.Minor())
	}
	return "leaves " + lineOf(v)
}
