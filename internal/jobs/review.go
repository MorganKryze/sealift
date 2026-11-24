package jobs

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/rank"
)

// ReasonKind names what a reason answers for.
type ReasonKind string

// The two kinds of reason a selection may need.
const (
	MajorJumpReason     ReasonKind = "major-jump"
	CVEWithoutFixReason ReasonKind = "cve-without-fix"
)

// Reason is why a selection takes its dependencies out of their line, or
// keeps a CVE that no version fixes. One reason covers a family or a lone
// jump, or every such CVE of one dependency.
type Reason struct {
	Kind         ReasonKind `json:"kind"`
	Dependencies []string   `json:"dependencies"`
	Text         string     `json:"text"`
}

// ErrInvalidReasons reports a selection whose reasons are missing, refused
// by the policy, unreadable or covering nothing. No problem repeats a
// reason's text.
type ErrInvalidReasons struct {
	Problems []string
}

func (e *ErrInvalidReasons) Error() string {
	return "jobs: the export's reasons do not fit its selection: " + strings.Join(e.Problems, "; ")
}

// asked is what one dependency of a selection asks a reason for.
type asked struct {
	dep      DependencyResult
	jumps    []string // selected versions outside the current line
	kept     string   // the version an install keeps, the current one when none is selected
	keptCVEs []CVE
	held     []held // the versions of this entry the archive holds
	leftOut  bool   // the archive holds no version of this entry: the project keeps the current one
}

// held is one version the archive holds, with its CVEs.
type held struct {
	version string
	cves    []CVE
	noFix   []string // ids of its CVEs that no version fixes
}

// maxReasonTextRunes is the contract's maxLength on a reason's text, which
// counts characters before trimming.
const maxReasonTextRunes = 1200

func askedOf(r Result, req ExportRequest) []asked {
	out := make([]asked, 0, len(r.Dependencies))
	for _, d := range r.Dependencies {
		if req.IncludeProject {
			d.CVEs = append(slices.Clone(d.CVEs), projectCVEs(d, req.ProjectFindings)...)
		}
		a := asked{dep: d}
		selected := req.Selection[d.Name]
		for _, v := range selected {
			if v != d.Current && !rank.SameLine(d.Current, v) && !slices.Contains(a.jumps, v) {
				a.jumps = append(a.jumps, v)
			}
		}
		holds := slices.Clone(selected)
		if req.IncludeProject {
			// The project tree ships its lockfile, which pins the current
			// version: a frozen install keeps it.
			holds = append(holds, d.Current)
		}
		for _, v := range holds {
			if slices.ContainsFunc(a.held, func(h held) bool { return h.version == v }) {
				continue
			}
			// A version of another entry of the same name is that entry's.
			if h, ok := heldOf(d, v); ok {
				a.held = append(a.held, h)
			}
		}
		// An entry none of the selected versions belongs to keeps its
		// current version in the project, even when the name has others.
		a.leftOut = len(a.held) == 0
		if a.leftOut {
			holds = []string{d.Current}
			h, _ := heldOf(d, d.Current)
			a.held = []held{h}
		}
		a.kept, a.keptCVEs, _ = pickedCVEs(d, holds)
		if a.kept == "" {
			a.kept, a.keptCVEs = d.Current, d.CVEs
		}
		out = append(out, a)
	}
	return out
}

// heldOf is version v of d with its CVEs, false when d lists no such version.
func heldOf(d DependencyResult, v string) (held, bool) {
	h := held{version: v, cves: d.CVEs}
	if v != d.Current {
		c, ok := findCandidate(d.Candidates, v)
		if !ok {
			return held{}, false
		}
		h.cves = c.CVEs
	}
	for _, c := range h.cves {
		if withoutFix(c) && !slices.Contains(h.noFix, c.ID) {
			h.noFix = append(h.noFix, c.ID)
		}
	}
	return h, true
}

// projectCVEs is what the lockfile's scan finds without a fix on d's
// current tree and d's own scan missed: a finding on d at its current
// version, or on a package d's scan already places under d.
func projectCVEs(d DependencyResult, findings []rank.Finding) []CVE {
	var out []CVE
	for _, f := range findings {
		if strings.TrimSpace(f.FixedVersion) != "" || !underDependency(d, f) {
			continue
		}
		c := CVE{ID: f.ID, Severity: severityText(f.Severity), Package: f.Package + "@" + f.Version}
		known := func(o CVE) bool { return o.ID == c.ID && packageName(o.Package) == f.Package }
		if !slices.ContainsFunc(d.CVEs, known) && !slices.ContainsFunc(out, known) {
			out = append(out, c)
		}
	}
	return out
}

// underDependency is true when finding f sits in d's current tree as far
// as the analysis knows it.
func underDependency(d DependencyResult, f rank.Finding) bool {
	if f.Package == d.Name {
		return f.Version == d.Current
	}
	return slices.ContainsFunc(d.CVEs, func(c CVE) bool { return packageName(c.Package) == f.Package })
}

// unplacedWithoutFix words, per package, the lockfile's CVEs without a fix
// that no dependency's tree places.
func unplacedWithoutFix(r Result, findings []rank.Finding) []string {
	var order []string
	ids := map[string][]string{}
	for _, f := range findings {
		if strings.TrimSpace(f.FixedVersion) != "" || slices.ContainsFunc(r.Dependencies, func(d DependencyResult) bool { return underDependency(d, f) }) {
			continue
		}
		key := f.Package + " " + f.Version
		if _, ok := ids[key]; !ok {
			order = append(order, key)
		}
		if !slices.Contains(ids[key], f.ID) {
			ids[key] = append(ids[key], f.ID)
		}
	}
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, fmt.Sprintf("the project tree keeps %s with %s, which no version fixes", key, andList(ids[key])))
	}
	return out
}

// noFix is true when a version a holds keeps a CVE no version fixes.
func (a asked) noFix() bool {
	return slices.ContainsFunc(a.held, func(h held) bool { return len(h.noFix) > 0 })
}

// withoutFix is true for a CVE no version fixes, and for one whose fix was
// never recorded, as in an analysis of sealift 0.7.0.
func withoutFix(c CVE) bool {
	return strings.TrimSpace(c.FixedIn) == ""
}

// coverage maps each kind to the dependencies a reason covers, and each of
// those to the index of the first reason that names it.
type coverage map[ReasonKind]map[string]int

// cover matches the reasons to what the selection asks, and words a
// problem for each reason that is unreadable or covers nothing.
func cover(r Result, asks []asked, reasons []Reason) (coverage, []string) {
	known := map[string]bool{}
	for _, d := range r.Dependencies {
		known[d.Name] = true
	}
	// A name listed under two dependency kinds has two entries: it needs
	// what either of them needs.
	needs := map[ReasonKind]map[string]bool{MajorJumpReason: {}, CVEWithoutFixReason: {}}
	for _, a := range asks {
		needs[MajorJumpReason][a.dep.Name] = needs[MajorJumpReason][a.dep.Name] || len(a.jumps) > 0
		needs[CVEWithoutFixReason][a.dep.Name] = needs[CVEWithoutFixReason][a.dep.Name] || a.noFix()
	}
	covered := coverage{MajorJumpReason: {}, CVEWithoutFixReason: {}}
	var problems []string
	for i, reason := range reasons {
		if needs[reason.Kind] == nil {
			problems = append(problems, fmt.Sprintf("reason %d has an unknown kind", i+1))
			continue
		}
		at := fmt.Sprintf("reason %d (%s)", i+1, reason.Kind)
		if utf8.RuneCountInString(reason.Text) > maxReasonTextRunes {
			problems = append(problems, fmt.Sprintf("%s: the reason is longer than %d characters before trimming", at, maxReasonTextRunes))
		} else if err := archive.CheckReason(reason.Text); err != nil {
			problems = append(problems, at+": "+err.Error())
		}
		if len(reason.Dependencies) == 0 {
			problems = append(problems, at+" names no dependency")
			continue
		}
		// An unknown name is caller text: the problem leaves it out.
		unknown := slices.ContainsFunc(reason.Dependencies, func(name string) bool { return !known[name] })
		if unknown {
			problems = append(problems, at+" names a dependency the analysis does not hold")
		}
		coversSome := false
		for _, name := range reason.Dependencies {
			if _, done := covered[reason.Kind][name]; needs[reason.Kind][name] && !done {
				covered[reason.Kind][name] = i
				coversSome = true
			}
		}
		if !coversSome && !unknown {
			problems = append(problems, at+" covers nothing the selection takes")
		}
	}
	return covered, problems
}

// CheckReasons returns one worded problem for each jump or CVE without fix
// the request carries with no reason or against the policy, and for each
// reason that is unreadable or covers nothing. Every selected version counts
// for a jump. For CVEs, each version the archive holds counts on its own:
// the selected ones, and the current one when the project tree ships. A
// dependency the archive leaves out keeps its current version in the
// project: its CVEs ask a reason, and the policy never refuses them.
// Empty when the export may go.
func CheckReasons(r Result, req ExportRequest, p policy.Review) []string {
	asks := askedOf(r, req)
	covered, reasonProblems := cover(r, asks, req.Reasons)
	var problems []string
	for _, a := range asks {
		d := a.dep
		for _, v := range a.jumps {
			_, ok := covered[MajorJumpReason][d.Name]
			switch {
			case p.MajorJump == policy.Refuse:
				problems = append(problems, fmt.Sprintf("review.majorJump is refuse: %s %s to %s cannot cross", d.Name, d.Current, v))
			case !ok:
				problems = append(problems, fmt.Sprintf("%s %s to %s leaves %s and needs a reason", d.Name, d.Current, v, lineWords(d.Current)))
			}
		}
		_, ok := covered[CVEWithoutFixReason][d.Name]
		for _, h := range a.held {
			if len(h.noFix) == 0 {
				continue
			}
			keeps := fmt.Sprintf("%s %s keeps %s, which no version fixes", d.Name, h.version, andList(h.noFix))
			switch {
			case p.CVEWithoutFix == policy.Refuse && !a.leftOut:
				problems = append(problems, "review.cveWithoutFix is refuse: "+keeps+", and cannot cross")
			case !ok:
				problems = append(problems, keeps+", and needs a reason")
			}
		}
	}
	// A lockfile package no dependency's tree places has no dependency for
	// a reason to name; only the refusal applies to it.
	if req.IncludeProject && p.CVEWithoutFix == policy.Refuse {
		for _, keeps := range unplacedWithoutFix(r, req.ProjectFindings) {
			problems = append(problems, "review.cveWithoutFix is refuse: "+keeps+", and cannot cross")
		}
	}
	// A name listed twice may word one problem twice.
	return append(slices.Compact(problems), reasonProblems...)
}

// lineWords names the line a current version belongs to.
func lineWords(current string) string {
	switch line := rank.LineOf(current); {
	case line == "":
		return "its line"
	case strings.Contains(line, "."):
		return "line " + line
	default:
		return "major " + line
	}
}

func andList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// ReviewOf is the review a manifest signs for a request whose reasons
// CheckReasons accepts. projected is the estimate summary.md prints, nil
// when the project scan could not be read. The review names no person: the
// import attaches who brought the archive in.
func ReviewOf(r Result, req ExportRequest, projected *rank.Vector) archive.Review {
	asks := askedOf(r, req)
	reasons := req.Reasons
	covered, _ := cover(r, asks, reasons)
	reasonFor := func(kind ReasonKind, name string) (int, string) {
		i, ok := covered[kind][name]
		if !ok {
			return -1, ""
		}
		return i, strings.TrimSpace(reasons[i].Text)
	}

	review := archive.Review{
		CVEs:    archive.ReviewCVEs{Before: [5]int(r.Before)},
		Updates: []archive.ReviewUpdate{},
		Kept:    []archive.ReviewKept{},
		Jumps:   []archive.ReviewJump{},
		Left:    []archive.ReviewCVE{},
	}
	if projected != nil {
		after := [5]int(*projected)
		review.CVEs.After = &after
	}
	jumpAt := map[string]int{}
	for _, a := range asks {
		d := a.dep
		version, cves := a.kept, a.keptCVEs

		if len(a.jumps) > 0 {
			i, text := reasonFor(MajorJumpReason, d.Name)
			// A family moves as one jump per reason given for it; a lone
			// dependency is a jump of its own.
			key := "dependency " + d.Name
			if d.Family != "" {
				key = fmt.Sprintf("family %d %s", i, d.Family)
			}
			at, ok := jumpAt[key]
			if !ok {
				at = len(review.Jumps)
				jumpAt[key] = at
				review.Jumps = append(review.Jumps, archive.ReviewJump{Family: d.Family, Packages: []archive.ReviewMove{}, Reason: text})
			}
			for _, v := range a.jumps {
				review.Jumps[at].Packages = append(review.Jumps[at].Packages, archive.ReviewMove{Name: d.Name, From: d.Current, To: v})
			}
		} else if d.Jump != "" {
			review.Kept = append(review.Kept, archive.ReviewKept{Name: d.Name, Version: version, Jump: d.Jump})
		}

		updated := version != d.Current && rank.SameLine(d.Current, version)
		if updated {
			review.Updates = append(review.Updates, archive.ReviewUpdate{
				Name: d.Name, From: d.Current, To: version,
				Fixed: cveCounts(fixedBy(d.CVEs, cves)), Left: cveCounts(cves),
			})
		}
		if !updated && len(a.jumps) == 0 && d.Jump == "" {
			review.Unchanged++
		}

		_, text := reasonFor(CVEWithoutFixReason, d.Name)
		for _, h := range a.held {
			for _, c := range h.cves {
				left := archive.ReviewCVE{
					Dependency: d.Name, Version: h.version, ID: c.ID,
					Severity: severityText(rank.ParseSeverity(c.Severity)),
					Package:  packageName(c.Package), FixedIn: shortFixedIn(c.FixedIn),
				}
				if withoutFix(c) {
					left.Reason = text
				}
				if !slices.Contains(review.Left, left) {
					review.Left = append(review.Left, left)
				}
			}
		}
	}
	return review
}

// maxFixedInBytes is the import's bound on a review's text fields.
const maxFixedInBytes = 256

// shortFixedIn keeps the versions of a Trivy fixedIn that fit the import's
// bound, whole ones only, so a long list never fails the export. The
// archive's Trivy report keeps the full value. A lone version past the
// bound is cut on a character.
func shortFixedIn(fixedIn string) string {
	if len(fixedIn) <= maxFixedInBytes {
		return fixedIn
	}
	if i := strings.LastIndex(fixedIn[:min(len(fixedIn), maxFixedInBytes+2)], ", "); i > 0 {
		return fixedIn[:i]
	}
	cut := maxFixedInBytes
	for cut > 0 && !utf8.RuneStart(fixedIn[cut]) {
		cut--
	}
	return fixedIn[:cut]
}

// fixedBy returns the CVEs of before that none of after carries.
func fixedBy(before, after []CVE) []CVE {
	var fixed []CVE
	for _, c := range before {
		if !slices.ContainsFunc(after, func(o CVE) bool { return o.ID == c.ID }) {
			fixed = append(fixed, c)
		}
	}
	return fixed
}

// cveCounts counts distinct ids by severity, the most serious one winning,
// as a Vector does.
func cveCounts(cves []CVE) [5]int {
	worst := map[string]rank.Severity{}
	for _, c := range cves {
		sev := rank.ParseSeverity(c.Severity)
		if prev, ok := worst[c.ID]; !ok || sev < prev {
			worst[c.ID] = sev
		}
	}
	var v [5]int
	for _, sev := range worst {
		v[sev]++
	}
	return v
}

// packageName drops the version from a CVE's "name@version" package.
func packageName(pkg string) string {
	if i := strings.LastIndex(pkg, "@"); i > 0 {
		return pkg[:i]
	}
	return pkg
}
