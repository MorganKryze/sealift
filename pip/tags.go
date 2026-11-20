package pip

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Platform is the install target: the interpreter and the machine a wheel
// has to suit.
type Platform struct {
	Python string // such as 3.11.2
	OS     string // linux
	CPU    string // x86_64, or aarch64 for the uv host wheel only
	Glibc  string // such as 2.28
}

// Tag is one compatibility triple of a wheel.
type Tag struct{ Interpreter, ABI, Platform string }

// WheelName is a parsed wheel file name, with its compressed tag sets
// expanded.
type WheelName struct {
	Name, Version, Build string
	Tags                 []Tag
}

const (
	maxFileNameBytes = 255
	maxTagSetSize    = 256
	oldestGlibcMinor = 5
	maxGlibcMinor    = 99
)

var (
	pythonRE = regexp.MustCompile(`^3\.(\d{1,2})(?:\.\d{1,3})?$`)
	glibcRE  = regexp.MustCompile(`^2\.(\d{1,2})$`)
	buildRE  = regexp.MustCompile(`^\d[A-Za-z0-9_.]*$`)
	tagPart  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

// Tags lists the tags the target accepts, most preferred first. It never
// lists a linux_<cpu> platform: such a wheel is not portable.
func Tags(p Platform) ([]Tag, error) {
	m := pythonRE.FindStringSubmatch(p.Python)
	if m == nil {
		return nil, fmt.Errorf("pip: python %q is not a CPython 3 version", p.Python)
	}
	minor, _ := strconv.Atoi(m[1])
	if p.OS != "linux" {
		return nil, fmt.Errorf("pip: os %q is not supported, only linux", p.OS)
	}
	if p.CPU != "x86_64" && p.CPU != "aarch64" {
		return nil, fmt.Errorf("pip: cpu %q is not supported, only x86_64 and aarch64", p.CPU)
	}
	g := glibcRE.FindStringSubmatch(p.Glibc)
	if g == nil {
		return nil, fmt.Errorf("pip: glibc %q is not a 2.x version", p.Glibc)
	}
	glibc, _ := strconv.Atoi(g[1])
	if glibc < oldestGlibcMinor || glibc > maxGlibcMinor {
		return nil, fmt.Errorf("pip: glibc %q is outside 2.%d to 2.%d", p.Glibc, oldestGlibcMinor, maxGlibcMinor)
	}
	plats := manylinuxTags(p.CPU, glibc)

	cp := fmt.Sprintf("cp3%d", minor)
	var tags []Tag
	add := func(interp, abi string, platforms []string) {
		for _, pl := range platforms {
			tags = append(tags, Tag{interp, abi, pl})
		}
	}
	add(cp, cp, plats)
	for v := minor; v >= 2; v-- {
		add(fmt.Sprintf("cp3%d", v), "abi3", plats)
	}
	add(cp, "none", plats)
	for _, py := range pyRange(minor) {
		add(py, "none", plats)
	}
	add(cp, "none", []string{"any"})
	for _, py := range pyRange(minor) {
		add(py, "none", []string{"any"})
	}
	return tags, nil
}

// pyRange lists py3<minor>, py3, then py3<minor-1> down to py30.
func pyRange(minor int) []string {
	out := []string{fmt.Sprintf("py3%d", minor), "py3"}
	for v := minor - 1; v >= 0; v-- {
		out = append(out, fmt.Sprintf("py3%d", v))
	}
	return out
}

// manylinuxTags lists manylinux_2_<g> down to the oldest the CPU has, each
// followed by its legacy alias.
func manylinuxTags(cpu string, glibc int) []string {
	oldest := oldestGlibcMinor
	if cpu == "aarch64" {
		oldest = 17
	}
	aliases := map[int]string{17: "manylinux2014", 12: "manylinux2010", 5: "manylinux1"}
	var out []string
	for g := glibc; g >= oldest; g-- {
		out = append(out, fmt.Sprintf("manylinux_2_%d_%s", g, cpu))
		if a, ok := aliases[g]; ok {
			out = append(out, fmt.Sprintf("%s_%s", a, cpu))
		}
	}
	return out
}

// ParseWheelName reads a wheel file name and expands its tag sets.
func ParseWheelName(file string) (WheelName, error) {
	if len(file) > maxFileNameBytes {
		return WheelName{}, fmt.Errorf("pip: wheel name is longer than %d bytes", maxFileNameBytes)
	}
	if strings.ContainsAny(file, "/\\") {
		return WheelName{}, errors.New("pip: wheel name has a path separator")
	}
	stem, ok := strings.CutSuffix(file, ".whl")
	if !ok {
		return WheelName{}, errors.New("pip: file is not a wheel")
	}
	parts := strings.Split(stem, "-")
	if len(parts) != 5 && len(parts) != 6 {
		return WheelName{}, errors.New("pip: wheel name needs name, version, tags")
	}
	w := WheelName{Name: parts[0], Version: parts[1]}
	if !ValidName(w.Name) || strings.Contains(w.Name, "-") {
		return WheelName{}, errors.New("pip: wheel name has an invalid project name")
	}
	if !IsExactVersion(w.Version) {
		return WheelName{}, errors.New("pip: wheel name has an invalid version")
	}
	if len(parts) == 6 {
		w.Build = parts[2]
		if !buildRE.MatchString(w.Build) {
			return WheelName{}, errors.New("pip: wheel name has an invalid build tag")
		}
	}
	sets := parts[len(parts)-3:]
	var lists [3][]string
	size := 1
	for i, s := range sets {
		lists[i] = strings.Split(s, ".")
		for _, e := range lists[i] {
			if !tagPart.MatchString(e) {
				return WheelName{}, errors.New("pip: wheel name has an invalid tag")
			}
		}
		size *= len(lists[i])
		if size > maxTagSetSize {
			return WheelName{}, fmt.Errorf("pip: wheel name expands to more than %d tags", maxTagSetSize)
		}
	}
	for _, i := range lists[0] {
		for _, a := range lists[1] {
			for _, pl := range lists[2] {
				w.Tags = append(w.Tags, Tag{i, a, pl})
			}
		}
	}
	return w, nil
}
