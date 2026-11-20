// Package store keeps sealift's data volume: settings, projects, analyses and
// exports.
package store

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Target is the system an export gets prepared for, plus the toolchain
// versions the resolution pins.
type Target struct {
	OS      string `json:"os"`      // "linux"
	CPU     string `json:"cpu"`     // "x64"
	Libc    string `json:"libc"`    // "glibc" or "musl"
	Node    string `json:"node"`    // "22.17.1"
	PnpmVer string `json:"pnpmVer"` // "10.34.5"
}

// Ecosystem names the package manager a project belongs to.
type Ecosystem string

// The ecosystems a project can have.
const (
	NPM Ecosystem = "npm"
	Pip Ecosystem = "pip"
)

// PipTarget is the system a pip resolution is prepared for.
type PipTarget struct {
	Python string `json:"python"` // "3.11.2"
	OS     string `json:"os"`     // "linux"
	CPU    string `json:"cpu"`    // "x86_64"
	Glibc  string `json:"glibc"`  // "2.28"
	UvVer  string `json:"uvVer"`  // "0.13.7"
}

// DefaultPipTarget is the target a pip project gets when its creator names none.
var DefaultPipTarget = PipTarget{Python: "3.11.2", OS: "linux", CPU: "x86_64", Glibc: "2.28", UvVer: "0.13.7"}

var (
	pipPythonRE = regexp.MustCompile(`^3\.\d{1,3}\.\d{1,3}$`)
	pipGlibcRE  = regexp.MustCompile(`^2\.(\d{1,3})$`)
	pipUvVerRE  = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)
)

// ValidatePipTarget refuses a target the resolver cannot honor, naming each
// field at fault. The glibc range is the manylinux range uv 0.13.7 accepts.
func ValidatePipTarget(t PipTarget) error {
	var problems []string
	if !pipPythonRE.MatchString(t.Python) {
		problems = append(problems, fmt.Sprintf("python must be 3.<minor>.<patch>, such as 3.11.2, not %q", t.Python))
	}
	if t.OS != "linux" {
		problems = append(problems, fmt.Sprintf("os must be linux, not %q", t.OS))
	}
	if t.CPU != "x86_64" {
		problems = append(problems, fmt.Sprintf("cpu is only x86_64 for now, not %q", t.CPU))
	}
	if m := pipGlibcRE.FindStringSubmatch(t.Glibc); m == nil || !glibcInRange(m[1]) {
		problems = append(problems, fmt.Sprintf("glibc must be 2.17 to 2.40, not %q", t.Glibc))
	}
	if !pipUvVerRE.MatchString(t.UvVer) {
		problems = append(problems, fmt.Sprintf("uvVer must be exact, such as 0.13.7, not %q", t.UvVer))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidTarget, strings.Join(problems, "; "))
	}
	return nil
}

func glibcInRange(minor string) bool {
	n, err := strconv.Atoi(minor)
	return err == nil && n >= 17 && n <= 40
}

// Settings holds every value the interface can change.
type Settings struct {
	Target              Target `json:"target"`
	MinReleaseAgeDays   int    `json:"minReleaseAgeDays"`
	ResolveParallelism  int    `json:"resolveParallelism"`
	DownloadParallelism int    `json:"downloadParallelism"`
}

// State is the state of an analysis, an export or a queued job.
type State string

// States of a job and of the directory it writes.
const (
	Queued      State = "queued"
	Running     State = "running"
	Done        State = "done"
	Failed      State = "failed"
	Cancelled   State = "cancelled"
	Interrupted State = "interrupted"
)
