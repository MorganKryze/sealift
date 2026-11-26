package jobs

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/pip"
	"github.com/MorganKryze/sealift/rank"
)

// YankedReason is why a pip export carries a release its index yanked.
const YankedReason ReasonKind = "yanked"

// pipAsk is what one package of a pip set asks a reason for. A pip export
// carries the whole set, so every package asks for itself.
type pipAsk struct {
	pkg    PipPackage
	jump   bool     // a major jump since the previous crossing
	noFix  []string // ids of its CVEs that no version fixes
	yanked bool
}

func pipAsksOf(r PipResult) []pipAsk {
	out := make([]pipAsk, 0, len(r.Packages))
	for _, p := range r.Packages {
		a := pipAsk{pkg: p, jump: p.Previous != nil && p.Previous.MajorJump, yanked: p.Yanked != nil}
		for _, c := range p.CVEs {
			if pipWithoutFix(c) && !slices.Contains(a.noFix, c.ID) {
				a.noFix = append(a.noFix, c.ID)
			}
		}
		out = append(out, a)
	}
	return out
}

// pipWithoutFix is true for a CVE no version fixes, and for one whose
// fixing versions are all blank.
func pipWithoutFix(c PipFinding) bool {
	return !slices.ContainsFunc(c.FixedVersions, func(v string) bool { return strings.TrimSpace(v) != "" })
}

func (a pipAsk) needs(kind ReasonKind) bool {
	switch kind {
	case MajorJumpReason:
		return a.jump
	case CVEWithoutFixReason:
		return len(a.noFix) > 0
	case YankedReason:
		return a.yanked
	}
	return false
}

func (a pipAsk) jumpWords() string {
	return fmt.Sprintf("%s %s to %s is a major jump", a.pkg.Name, a.pkg.Previous.Version, a.pkg.Version)
}

func (a pipAsk) noFixWords() string {
	return fmt.Sprintf("%s %s keeps %s, which no version fixes", a.pkg.Name, a.pkg.Version, andList(a.noFix))
}

func (a pipAsk) yankedWords() string {
	return fmt.Sprintf("%s %s is yanked on the index", a.pkg.Name, a.pkg.Version)
}

// pipCover matches the reasons to the set's packages, by kind and
// normalized name, and words a problem for each reason that is
// unreadable, names other than one package of the set, repeats a reason
// or covers nothing. A problem names a package only once the set holds it.
func pipCover(asks []pipAsk, reasons []Reason) (map[ReasonKind]map[string]int, []string) {
	at := make(map[string]int, len(asks))
	for i, a := range asks {
		at[pip.Normalize(a.pkg.Name)] = i
	}
	covered := map[ReasonKind]map[string]int{MajorJumpReason: {}, CVEWithoutFixReason: {}, YankedReason: {}}
	var problems []string
	for i, reason := range reasons {
		if covered[reason.Kind] == nil {
			problems = append(problems, fmt.Sprintf("reason %d has an unknown kind", i+1))
			continue
		}
		label := fmt.Sprintf("reason %d (%s)", i+1, reason.Kind)
		if utf8.RuneCountInString(reason.Text) > maxReasonTextRunes {
			problems = append(problems, fmt.Sprintf("%s: the reason is longer than %d characters before trimming", label, maxReasonTextRunes))
		} else if err := archive.CheckReason(reason.Text); err != nil {
			problems = append(problems, label+": "+err.Error())
		}
		if n := len(reason.Dependencies); n != 1 {
			if n == 0 {
				problems = append(problems, label+" names no package")
			} else {
				problems = append(problems, fmt.Sprintf("%s names %d packages, and a pip reason covers one", label, n))
			}
			continue
		}
		key := pip.Normalize(reason.Dependencies[0])
		ai, ok := at[key]
		if !ok {
			// An unknown name is caller text: the problem leaves it out.
			problems = append(problems, label+" names a package the analysis does not hold")
			continue
		}
		name := asks[ai].pkg.Name
		switch _, done := covered[reason.Kind][key]; {
		case !asks[ai].needs(reason.Kind):
			problems = append(problems, fmt.Sprintf("%s covers nothing the set needs: %s needs no such reason", label, name))
		case done:
			problems = append(problems, fmt.Sprintf("%s repeats the reason for %s", label, name))
		default:
			covered[reason.Kind][key] = i
		}
	}
	return covered, problems
}

// CheckPipReasons returns one worded problem per reason a pip set needs
// and lacks, and per reason that is unreadable, repeated or covers
// nothing; empty when the export may go. It reads the set as the analysis
// recorded it, so an analysis that recorded no previous crossing and no
// yanked mark asks only for its CVEs without fix. pipRefusals applies the
// refuse rules.
func CheckPipReasons(r PipResult, reasons []Reason) []string {
	asks := pipAsksOf(r)
	covered, reasonProblems := pipCover(asks, reasons)
	var problems []string
	for _, a := range asks {
		key := pip.Normalize(a.pkg.Name)
		missing := func(kind ReasonKind) bool {
			_, ok := covered[kind][key]
			return a.needs(kind) && !ok
		}
		if missing(MajorJumpReason) {
			problems = append(problems, a.jumpWords()+" and needs a reason")
		}
		if missing(CVEWithoutFixReason) {
			problems = append(problems, a.noFixWords()+", and needs a reason")
		}
		if missing(YankedReason) {
			problems = append(problems, a.yankedWords()+" and needs a reason")
		}
	}
	return append(problems, reasonProblems...)
}

// pipRefusals words the refusal of a set under each refuse rule, nil when
// none applies. Each rule names at most shownProblems packages.
func pipRefusals(r PipResult, p policy.Review) error {
	asks := pipAsksOf(r)
	var parts []string
	for _, rule := range []struct {
		key   string
		rule  policy.Rule
		kind  ReasonKind
		words func(pipAsk) string
	}{
		{"review.majorJump", p.MajorJump, MajorJumpReason, func(a pipAsk) string { return a.jumpWords() + " and cannot cross" }},
		{"review.cveWithoutFix", p.CVEWithoutFix, CVEWithoutFixReason, func(a pipAsk) string { return a.noFixWords() + ", and cannot cross" }},
		{"review.yanked", p.Yanked, YankedReason, func(a pipAsk) string { return a.yankedWords() + " and cannot cross" }},
	} {
		if rule.rule != policy.Refuse {
			continue
		}
		var items []string
		for _, a := range asks {
			if a.needs(rule.kind) {
				items = append(items, rule.words(a))
			}
		}
		if len(items) == 0 {
			continue
		}
		if len(items) > shownProblems {
			items = append(items[:shownProblems], fmt.Sprintf("and %d more", len(items)-shownProblems))
		}
		parts = append(parts, rule.key+" is refuse: "+strings.Join(items, "; "))
	}
	if len(parts) == 0 {
		return nil
	}
	return &pipRefusal{text: "jobs: " + strings.Join(parts, "; "), class: ErrPipNotExportable}
}

// pipBlockedRefusal names the packages of a set the target cannot install
// from a wheel: those without a wheel and those the blocking list names,
// each once. Nil when there are none.
func pipBlockedRefusal(r PipResult) error {
	var names []string
	seen := map[string]bool{}
	add := func(name, version string) {
		if key := pip.Normalize(name); !seen[key] {
			seen[key] = true
			names = append(names, name+" "+version)
		}
	}
	for _, p := range r.Packages {
		if p.Wheel == nil {
			add(p.Name, p.Version)
		}
	}
	for _, b := range r.Blocking {
		add(b.Name, b.Version)
	}
	if len(names) == 0 {
		return nil
	}
	n := len(names)
	if n > shownProblems {
		names = append(names[:shownProblems], fmt.Sprintf("%d more", n-shownProblems))
	}
	return &pipRefusal{
		text:  fmt.Sprintf("jobs: %d %s no wheel for the target, so the set cannot cross: %s", n, plural(n, "package has", "packages have"), andList(names)),
		class: ErrPipNotExportable,
	}
}

// PipReviewOf is the review a pip export signs for reasons CheckPipReasons
// accepts. cves.before counts the previous crossing's set as this
// analysis scanned it, the packages that left included; with no previous
// crossing it equals cves.after. A pin that moved inside its major is an
// update and one that moved across it a jump; every CVE the set keeps is
// left. A package the previous crossing held at the same version is
// unchanged; with no previous crossing none is, since nothing was
// compared. Names are normalized, as the manifest's packages are.
func PipReviewOf(r PipResult, reasons []Reason) archive.Review {
	asks := pipAsksOf(r)
	covered, _ := pipCover(asks, reasons)
	reasonFor := func(kind ReasonKind, key string) string {
		if i, ok := covered[kind][key]; ok {
			return strings.TrimSpace(reasons[i].Text)
		}
		return ""
	}

	var before, after []CVE
	review := archive.Review{
		Updates: []archive.ReviewUpdate{},
		Kept:    []archive.ReviewKept{},
		Jumps:   []archive.ReviewJump{},
		Left:    []archive.ReviewCVE{},
	}
	for _, a := range asks {
		p := a.pkg
		name := pip.Normalize(p.Name)
		cves := pipCVEs(p.CVEs)
		after = append(after, cves...)
		switch prev := p.Previous; {
		case r.Previous == nil, prev == nil:
			// No comparison for this package: a first crossing, or a
			// package new since the previous one. No earlier CVEs, no move.
		default:
			earlier := pipCVEs(prev.CVEs)
			before = append(before, earlier...)
			switch {
			case prev.MajorJump:
				review.Jumps = append(review.Jumps, archive.ReviewJump{
					Packages: []archive.ReviewMove{{Name: name, From: prev.Version, To: p.Version}},
					Reason:   reasonFor(MajorJumpReason, name),
				})
			case pip.SameVersion(prev.Version, p.Version):
				review.Unchanged++
			default:
				review.Updates = append(review.Updates, archive.ReviewUpdate{
					Name: name, From: prev.Version, To: p.Version,
					Fixed: cveCounts(fixedBy(earlier, cves)), Left: cveCounts(cves),
				})
			}
		}

		text := reasonFor(CVEWithoutFixReason, name)
		for _, c := range p.CVEs {
			left := archive.ReviewCVE{
				Dependency: name, Version: p.Version, ID: c.ID,
				Severity: severityText(rank.ParseSeverity(c.Severity)),
				Package:  name, FixedIn: shortFixedIn(strings.Join(c.FixedVersions, ", ")),
			}
			if pipWithoutFix(c) {
				left.FixedIn, left.Reason = "", text
			}
			if !slices.Contains(review.Left, left) {
				review.Left = append(review.Left, left)
			}
		}
		if p.Yanked != nil {
			review.Yanked = append(review.Yanked, archive.ReviewYanked{
				Dependency: name, Version: p.Version, IndexReason: p.Yanked.Reason, Reason: reasonFor(YankedReason, name),
			})
		}
	}
	if r.Previous == nil {
		before = after
	} else {
		for _, gone := range r.Removed {
			before = append(before, pipCVEs(gone.CVEs)...)
		}
	}
	afterCounts := cveCounts(after)
	review.CVEs = archive.ReviewCVEs{Before: cveCounts(before), After: &afterCounts}
	return review
}

// pipCVEs gives a package's findings the shape the review's counts read.
func pipCVEs(findings []PipFinding) []CVE {
	out := make([]CVE, len(findings))
	for i, f := range findings {
		out[i] = CVE{ID: f.ID, Severity: f.Severity}
	}
	return out
}
