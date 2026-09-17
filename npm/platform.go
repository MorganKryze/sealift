package npm

import "strings"

// Platform is the system packages get installed on.
type Platform struct {
	OS   string // "linux"
	CPU  string // "x64"
	Libc string // "glibc" or "musl"
}

// Accepts reports whether npm would install p on the platform. It follows
// npm's rules: an empty list or ["any"] accepts every value, "!value"
// excludes a value, and the libc list only applies on linux.
func (pl Platform) Accepts(p LockPackage) bool {
	if !matches(p.OS, pl.OS) || !matches(p.CPU, pl.CPU) {
		return false
	}
	return pl.OS != "linux" || matches(p.Libc, pl.Libc)
}

// Filter returns the packages the platform accepts, in their original order.
func (pl Platform) Filter(pkgs []LockPackage) []LockPackage {
	var kept []LockPackage
	for _, p := range pkgs {
		if pl.Accepts(p) {
			kept = append(kept, p)
		}
	}
	return kept
}

func matches(list []string, value string) bool {
	if len(list) == 0 || (len(list) == 1 && list[0] == "any") {
		return true
	}
	negations := 0
	match := false
	for _, item := range list {
		if name, negated := strings.CutPrefix(item, "!"); negated {
			if name == value {
				return false
			}
			negations++
		} else if item == value {
			match = true
		}
	}
	return match || negations == len(list)
}
