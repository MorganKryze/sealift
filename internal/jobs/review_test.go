package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// reviewResult is an analysis with a lone jump (express), a CVE no version
// fixes (html-minifier), a family (react 19) and a 0.x line (esbuild).
func reviewResult() Result {
	return Result{
		Before: Vector{0, 2, 1, 0, 0},
		Dependencies: []DependencyResult{
			{
				Name: "esbuild", Current: "0.18.0", Vector: Vector{}, CVEs: []CVE{}, Jump: "0.19.0",
				Candidates: []Candidate{{Version: "0.18.2", CVEs: []CVE{}}, {Version: "0.19.0", CVEs: []CVE{}}},
			},
			{
				Name: "express", Current: "4.17.1", Vector: Vector{0, 1, 1, 0, 0}, Jump: "5.1.0",
				CVEs: []CVE{
					{ID: "CVE-2024-0001", Severity: "HIGH", Package: "express@4.17.1", FixedIn: "4.20.0, 5.0.0"},
					{ID: "CVE-2024-0002", Severity: "MEDIUM", Package: "body-parser@1.19.0", FixedIn: "5.0.0"},
				},
				Candidates: []Candidate{
					{Version: "4.20.0", Vector: Vector{0, 0, 1, 1, 0}, CVEs: []CVE{
						{ID: "CVE-2024-0002", Severity: "MEDIUM", Package: "body-parser@1.20.3", FixedIn: "5.0.0"},
						{ID: "CVE-2024-0003", Severity: "LOW", Package: "cookie@0.4.0", FixedIn: "0.7.0"},
					}},
					{Version: "5.1.0", Vector: Vector{}, CVEs: []CVE{}},
				},
			},
			{
				Name: "html-minifier", Current: "4.0.0", Vector: Vector{0, 1, 0, 0, 0},
				CVEs:       []CVE{{ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier@4.0.0", FixedIn: ""}},
				Candidates: []Candidate{{Version: "4.0.1", Vector: Vector{}, CVEs: []CVE{}}},
			},
			{
				Name: "react", Current: "18.3.1", Vector: Vector{}, CVEs: []CVE{}, Jump: "19.2.0", Family: "react 19",
				Candidates: []Candidate{{Version: "19.2.0", CVEs: []CVE{}}},
			},
			{
				Name: "react-dom", Current: "18.3.1", Vector: Vector{}, CVEs: []CVE{}, Jump: "19.2.0", Family: "react 19",
				Candidates: []Candidate{{Version: "19.2.0", CVEs: []CVE{}}},
			},
		},
		Families: []Family{{Name: "react 19", Members: []string{"react", "react-dom"}}},
	}
}

// fixableResult is reviewResult with html-minifier's CVE fixed in 4.0.1, so
// a selection that leaves html-minifier out asks no reason for it.
func fixableResult() Result {
	r := reviewResult()
	r.Dependencies[2].CVEs[0].FixedIn = "4.0.1"
	return r
}

func askReasons() policy.Review { return policy.DefaultReview() }

func request(selection map[string][]string, reasons ...Reason) ExportRequest {
	return ExportRequest{Selection: selection, Reasons: reasons}
}

func jumpReason(text string, deps ...string) Reason {
	return Reason{Kind: MajorJumpReason, Dependencies: deps, Text: text}
}

func cveReason(text string, deps ...string) Reason {
	return Reason{Kind: CVEWithoutFixReason, Dependencies: deps, Text: text}
}

func assertProblems(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("problems:\n got %q\nwant %q", got, want)
	}
}

func TestCheckReasonsAsksForAJump(t *testing.T) {
	r := fixableResult()
	for _, tc := range []struct {
		name      string
		selection map[string][]string
		want      []string
	}{
		{"a major left", map[string][]string{"express": {"5.1.0"}}, []string{"express 4.17.1 to 5.1.0 leaves major 4 and needs a reason"}},
		{"a 0.x minor left", map[string][]string{"esbuild": {"0.19.0"}}, []string{"esbuild 0.18.0 to 0.19.0 leaves line 0.18 and needs a reason"}},
		{"every selected version counts", map[string][]string{"express": {"4.20.0", "5.1.0"}}, []string{"express 4.17.1 to 5.1.0 leaves major 4 and needs a reason"}},
		{"inside the line", map[string][]string{"express": {"4.20.0"}, "esbuild": {"0.18.2"}}, nil},
		{"the dependency not selected", map[string][]string{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertProblems(t, CheckReasons(r, request(tc.selection), askReasons()), tc.want)
		})
	}

	got := CheckReasons(r, request(map[string][]string{"express": {"5.1.0"}}, jumpReason("Our tests pass on 5.", "express")), askReasons())
	assertProblems(t, got, nil)

	// A jump selected beside a better version inside the line crosses too,
	// so it asks its reason though an install keeps the other version.
	worse := fixableResult()
	worse.Dependencies[1].Candidates[1].Vector = Vector{1, 0, 0, 0, 0}
	worse.Dependencies[1].Candidates[1].CVEs = []CVE{{ID: "CVE-2025-0005", Severity: "CRITICAL", Package: "express@5.1.0", FixedIn: "5.1.1"}}
	assertProblems(t, CheckReasons(worse, request(map[string][]string{"express": {"4.20.0", "5.1.0"}}), askReasons()),
		[]string{"express 4.17.1 to 5.1.0 leaves major 4 and needs a reason"})
}

func TestCheckReasonsAsksForACVEWithoutFix(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"html-minifier": {"4.0.0"}}
	assertProblems(t, CheckReasons(r, request(sel), askReasons()),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason"})

	// A jump reason is not a CVE reason.
	assertProblems(t, CheckReasons(r, request(sel, jumpReason("Templates are ours.", "html-minifier")), askReasons()), []string{
		"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason",
		"reason 1 (major-jump) covers nothing the selection takes",
	})
	assertProblems(t, CheckReasons(r, request(sel, cveReason("Templates are ours.", "html-minifier")), askReasons()), nil)

	// Every such CVE of one dependency asks one reason.
	r.Dependencies[2].CVEs = append(r.Dependencies[2].CVEs, CVE{ID: "CVE-2022-99999", Severity: "LOW", Package: "relateurl@0.2.7"})
	assertProblems(t, CheckReasons(r, request(sel), askReasons()),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620 and CVE-2022-99999, which no version fixes, and needs a reason"})
}

func TestCheckReasonsAsksForACVEWithoutFixOnADependencyLeftOut(t *testing.T) {
	r := reviewResult()
	// The project keeps html-minifier 4.0.0 when the selection leaves it out.
	want := []string{"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason"}
	assertProblems(t, CheckReasons(r, request(map[string][]string{"express": {"4.20.0"}}), askReasons()), want)
	assertProblems(t, CheckReasons(r, request(map[string][]string{}), askReasons()), want)
	assertProblems(t, CheckReasons(r, request(map[string][]string{"express": {"4.20.0"}}, cveReason("Templates are ours.", "html-minifier")), askReasons()), nil)
}

func TestCheckReasonsCountsAnUnknownFixAsNone(t *testing.T) {
	r := fixableResult()
	// The bytes an analysis of sealift 0.7.0 wrote for a CVE: no package,
	// no fixing version.
	var old []CVE
	if err := json.Unmarshal([]byte(`[{"id":"CVE-2021-23337","severity":"HIGH"}]`), &old); err != nil {
		t.Fatal(err)
	}
	r.Dependencies[1].CVEs = old
	assertProblems(t, CheckReasons(r, request(map[string][]string{"express": {"4.17.1"}}), askReasons()),
		[]string{"express 4.17.1 keeps CVE-2021-23337, which no version fixes, and needs a reason"})
}

func TestCheckReasonsAsksNothingForAFixInAnotherLine(t *testing.T) {
	r := fixableResult()
	// express 4.17.1 keeps CVE-2024-0002, fixed in 5.0.0 only.
	assertProblems(t, CheckReasons(r, request(map[string][]string{"express": {"4.17.1"}}), askReasons()), nil)
	assertProblems(t, CheckReasons(r, request(map[string][]string{"express": {"4.20.0"}}), askReasons()), nil)
}

func TestCheckReasonsAcceptsOneReasonForAFamily(t *testing.T) {
	r := fixableResult()
	sel := map[string][]string{"react": {"19.2.0"}, "react-dom": {"19.2.0"}}
	assertProblems(t, CheckReasons(r, request(sel), askReasons()), []string{
		"react 18.3.1 to 19.2.0 leaves major 18 and needs a reason",
		"react-dom 18.3.1 to 19.2.0 leaves major 18 and needs a reason",
	})
	assertProblems(t, CheckReasons(r, request(sel, jumpReason("The app moved to React 19.", "react", "react-dom")), askReasons()), nil)
	assertProblems(t, CheckReasons(r, request(sel, jumpReason("The app moved to React 19.", "react")), askReasons()),
		[]string{"react-dom 18.3.1 to 19.2.0 leaves major 18 and needs a reason"})
}

func TestCheckReasonsChecksEachVersionTheArchiveHolds(t *testing.T) {
	r := reviewResult()
	// 4.0.1 carries nothing, yet 4.0.0 crosses beside it with its CVE.
	assertProblems(t, CheckReasons(r, request(map[string][]string{"html-minifier": {"4.0.0", "4.0.1"}}), askReasons()),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason"})
	assertProblems(t, CheckReasons(r, request(map[string][]string{"html-minifier": {"4.0.1"}}), askReasons()), nil)

	// The other way round: the candidate carries a CVE without fix, the
	// current version none.
	r.Dependencies[2].CVEs, r.Dependencies[2].Vector = []CVE{}, Vector{}
	r.Dependencies[2].Candidates[0].CVEs = []CVE{{ID: "CVE-2025-0001", Severity: "LOW", Package: "html-minifier@4.0.1"}}
	r.Dependencies[2].Candidates[0].Vector = Vector{0, 0, 0, 1, 0}
	assertProblems(t, CheckReasons(r, request(map[string][]string{"html-minifier": {"4.0.0", "4.0.1"}}), askReasons()),
		[]string{"html-minifier 4.0.1 keeps CVE-2025-0001, which no version fixes, and needs a reason"})
}

func TestCheckReasonsCountsTheCurrentVersionBesideACleanOne(t *testing.T) {
	r := reviewResult()
	withTree := ExportRequest{Selection: map[string][]string{"html-minifier": {"4.0.1"}}, IncludeProject: true}
	refuseBoth := policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	assertProblems(t, CheckReasons(r, withTree, refuseBoth),
		[]string{"review.cveWithoutFix is refuse: html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and cannot cross"})
	assertProblems(t, CheckReasons(r, withTree, askReasons()),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason"})

	withTree.Reasons = []Reason{cveReason("Templates are ours.", "html-minifier")}
	assertProblems(t, CheckReasons(r, withTree, askReasons()), nil)
	var left []archive.ReviewCVE
	for _, c := range ReviewOf(r, withTree, nil).Left {
		if c.Dependency == "html-minifier" {
			left = append(left, c)
		}
	}
	want := []archive.ReviewCVE{{Dependency: "html-minifier", Version: "4.0.0", ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier", Reason: "Templates are ours."}}
	if !reflect.DeepEqual(left, want) {
		t.Errorf("html-minifier's left =\n %+v\nwant\n %+v", left, want)
	}
}

func TestCheckReasonsNeverRefusesADependencyTheArchiveLeavesOut(t *testing.T) {
	r := reviewResult()
	refuseBoth := policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	sel := map[string][]string{"esbuild": {"0.18.2"}}
	assertProblems(t, CheckReasons(r, request(sel), refuseBoth),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason"})
	assertProblems(t, CheckReasons(r, request(sel, cveReason("Templates are ours.", "html-minifier")), refuseBoth), nil)
}

func TestCheckReasonsLeavesOutAnEntryTheSelectionDoesNotHold(t *testing.T) {
	r := Result{Dependencies: []DependencyResult{
		{
			Name: "foo", Current: "1.0.0", Vector: Vector{0, 0, 0, 1, 0},
			CVEs:       []CVE{{ID: "CVE-X", Severity: "LOW", Package: "foo@1.0.0"}},
			Candidates: []Candidate{{Version: "1.0.1", Vector: Vector{0, 0, 0, 1, 0}, CVEs: []CVE{{ID: "CVE-X", Severity: "LOW", Package: "foo@1.0.1"}}}},
		},
		{Name: "foo", Current: "2.0.0", Vector: Vector{}, CVEs: []CVE{}, Candidates: []Candidate{{Version: "2.1.0", CVEs: []CVE{}}}},
	}}
	sel := map[string][]string{"foo": {"2.1.0"}}
	// 2.1.0 belongs to the second entry: the first keeps 1.0.0 in the
	// project, so its CVE asks a reason and the policy never refuses it.
	refuseCVEs := askReasons()
	refuseCVEs.CVEWithoutFix = policy.Refuse
	jump := jumpReason("Both lists move to 2.", "foo")
	assertProblems(t, CheckReasons(r, request(sel, jump), refuseCVEs),
		[]string{"foo 1.0.0 keeps CVE-X, which no version fixes, and needs a reason"})
	withReason := request(sel, jump, cveReason("Only tests load foo 1.", "foo"))
	assertProblems(t, CheckReasons(r, withReason, refuseCVEs), nil)
	got := ReviewOf(r, withReason, nil)
	want := []archive.ReviewCVE{{Dependency: "foo", Version: "1.0.0", ID: "CVE-X", Severity: "LOW", Package: "foo", Reason: "Only tests load foo 1."}}
	if !reflect.DeepEqual(got.Left, want) {
		t.Errorf("left =\n %+v\nwant\n %+v", got.Left, want)
	}
}

func TestCheckReasonsBoundsTheTextInCharacters(t *testing.T) {
	r := fixableResult()
	sel := map[string][]string{"express": {"5.1.0"}}
	for name, text := range map[string]string{
		"1200 characters":            strings.Repeat(" ", 1198) + "ok",
		"1200 multi-byte characters": strings.Repeat(" ", 1100) + strings.Repeat("é", 100),
	} {
		t.Run(name, func(t *testing.T) {
			assertProblems(t, CheckReasons(r, request(sel, jumpReason(text, "express")), askReasons()), nil)
		})
	}
	assertProblems(t, CheckReasons(r, request(sel, jumpReason(strings.Repeat(" ", 1199)+"ok", "express")), askReasons()),
		[]string{"reason 1 (major-jump): the reason is longer than 1200 characters before trimming"})
}

func TestCheckReasonsRefusesWhatThePolicyRefuses(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"express": {"5.1.0"}, "html-minifier": {"4.0.0"}}
	reasons := []Reason{jumpReason("Our tests pass on 5.", "express"), cveReason("Templates are ours.", "html-minifier")}

	refuseBoth := policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	assertProblems(t, CheckReasons(r, request(sel, reasons...), refuseBoth), []string{
		"review.majorJump is refuse: express 4.17.1 to 5.1.0 cannot cross",
		"review.cveWithoutFix is refuse: html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and cannot cross",
	})

	refuseJumps := policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.AskReason}
	assertProblems(t, CheckReasons(r, request(sel, reasons...), refuseJumps),
		[]string{"review.majorJump is refuse: express 4.17.1 to 5.1.0 cannot cross"})

	refuseCVEs := policy.Review{MajorJump: policy.AskReason, CVEWithoutFix: policy.Refuse}
	assertProblems(t, CheckReasons(r, request(sel, reasons...), refuseCVEs),
		[]string{"review.cveWithoutFix is refuse: html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and cannot cross"})
}

func TestCheckReasonsRefusesAReasonThatCoversNothing(t *testing.T) {
	r := fixableResult()
	for _, tc := range []struct {
		name      string
		selection map[string][]string
		reasons   []Reason
		want      []string
	}{
		{
			"a jump reason for a version inside the line",
			map[string][]string{"express": {"4.20.0"}},
			[]Reason{jumpReason("In case it helps.", "express")},
			[]string{"reason 1 (major-jump) covers nothing the selection takes"},
		},
		{
			"a CVE reason for a dependency whose CVEs have a fix",
			map[string][]string{"express": {"4.17.1"}},
			[]Reason{cveReason("In case it helps.", "express")},
			[]string{"reason 1 (cve-without-fix) covers nothing the selection takes"},
		},
		{
			"a reason for a dependency left out of the selection",
			map[string][]string{"express": {"5.1.0"}},
			[]Reason{jumpReason("Our tests pass on 5.", "express"), jumpReason("Moving on.", "react")},
			[]string{"reason 2 (major-jump) covers nothing the selection takes"},
		},
		{
			"a second reason for what the first covers",
			map[string][]string{"express": {"5.1.0"}},
			[]Reason{jumpReason("Our tests pass on 5.", "express"), jumpReason("Again.", "express")},
			[]string{"reason 2 (major-jump) covers nothing the selection takes"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertProblems(t, CheckReasons(r, request(tc.selection, tc.reasons...), askReasons()), tc.want)
		})
	}
}

func TestCheckReasonsRefusesAnUnknownDependency(t *testing.T) {
	r := fixableResult()
	sel := map[string][]string{"express": {"5.1.0"}}
	got := CheckReasons(r, request(sel, jumpReason("Our tests pass on 5.", "express", "evil\u202ename")), askReasons())
	assertProblems(t, got, []string{"reason 1 (major-jump) names a dependency the analysis does not hold"})

	got = CheckReasons(r, request(sel, jumpReason("Our tests pass on 5.", "express"), jumpReason("Nothing named.")), askReasons())
	assertProblems(t, got, []string{"reason 2 (major-jump) names no dependency"})

	got = CheckReasons(r, request(sel, jumpReason("Our tests pass on 5.", "express"), Reason{Kind: "<script>", Dependencies: []string{"express"}, Text: "x"}), askReasons())
	assertProblems(t, got, []string{"reason 2 has an unknown kind"})
}

// A package listed under two dependency kinds reaches the result twice under
// one name; what either entry asks, the name asks.
func TestCheckReasonsAsksForANameListedTwice(t *testing.T) {
	r := Result{Dependencies: []DependencyResult{
		{Name: "foo", Current: "1.0.0", Vector: Vector{}, CVEs: []CVE{}, Candidates: []Candidate{{Version: "2.1.0", CVEs: []CVE{}}}},
		{Name: "foo", Current: "2.0.0", Vector: Vector{}, CVEs: []CVE{}, Candidates: []Candidate{{Version: "2.1.0", CVEs: []CVE{}}}},
	}}
	sel := map[string][]string{"foo": {"2.1.0"}}
	assertProblems(t, CheckReasons(r, request(sel), askReasons()), []string{"foo 1.0.0 to 2.1.0 leaves major 1 and needs a reason"})
	assertProblems(t, CheckReasons(r, request(sel, jumpReason("Both lists move to 2.", "foo")), askReasons()), nil)

	r = Result{Dependencies: []DependencyResult{
		{Name: "foo", Current: "1.0.0", Vector: Vector{0, 0, 0, 1, 0}, CVEs: []CVE{{ID: "CVE-2025-0009", Severity: "LOW", Package: "foo@1.0.0"}}, Candidates: []Candidate{}},
		{Name: "foo", Current: "1.0.0", Vector: Vector{}, CVEs: []CVE{}, Candidates: []Candidate{}},
	}}
	sel = map[string][]string{"foo": {"1.0.0"}}
	assertProblems(t, CheckReasons(r, request(sel), askReasons()), []string{"foo 1.0.0 keeps CVE-2025-0009, which no version fixes, and needs a reason"})
	assertProblems(t, CheckReasons(r, request(sel, cveReason("Only our build calls foo.", "foo")), askReasons()), nil)
}

func TestExportChecksReasonsByTheImportsRule(t *testing.T) {
	r := fixableResult()
	sel := map[string][]string{"express": {"5.1.0"}}
	for _, tc := range []struct {
		name, text, want string
	}{
		{"a line separator", "tests pass\u2028on 5", "reason 1 (major-jump): the reason holds a control, line-separating, bidirectional or format character"},
		{"a bidirectional override", "tests pass \u202eon 5", "reason 1 (major-jump): the reason holds a control, line-separating, bidirectional or format character"},
		{"spaces only", "   ", "reason 1 (major-jump): the reason is empty"},
		{"301 characters", strings.Repeat("é", archive.MaxReasonRunes+1), "reason 1 (major-jump): the reason is longer than 300 characters"},
		{"1201 characters before trimming", strings.Repeat(" ", 1199) + "ok", "reason 1 (major-jump): the reason is longer than 1200 characters before trimming"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckReasons(r, request(sel, jumpReason(tc.text, "express")), askReasons())
			assertProblems(t, got, []string{tc.want})
		})
	}
}

// reviewSelection takes express inside its line, the react family out of
// its line, html-minifier with its CVE, and leaves esbuild alone.
func reviewSelection() (map[string][]string, []Reason) {
	return map[string][]string{
		"express":       {"4.20.0"},
		"html-minifier": {"4.0.0"},
		"react":         {"19.2.0"},
		"react-dom":     {"19.2.0"},
	}, []Reason{
		jumpReason("The app moved to React 19.", "react", "react-dom"),
		cveReason("Templates are ours.", "html-minifier"),
	}
}

func TestReviewOfCountsFixedAndLeft(t *testing.T) {
	r := reviewResult()
	sel, reasons := reviewSelection()
	if problems := CheckReasons(r, request(sel, reasons...), askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	projected := rank.Vector{0, 1, 1, 1, 0}
	got := ReviewOf(r, request(sel, reasons...), &projected)

	if got.CVEs.Before != [5]int{0, 2, 1, 0, 0} {
		t.Errorf("cves.before = %v, want the analysis' before", got.CVEs.Before)
	}
	if got.CVEs.After == nil || *got.CVEs.After != [5]int(projected) {
		t.Errorf("cves.after = %v, want the projected %v", got.CVEs.After, projected)
	}
	wantUpdates := []archive.ReviewUpdate{{Name: "express", From: "4.17.1", To: "4.20.0", Fixed: [5]int{0, 1, 0, 0, 0}, Left: [5]int{0, 0, 1, 1, 0}}}
	if !reflect.DeepEqual(got.Updates, wantUpdates) {
		t.Errorf("updates = %+v, want %+v", got.Updates, wantUpdates)
	}
	wantKept := []archive.ReviewKept{
		{Name: "esbuild", Version: "0.18.0", Jump: "0.19.0"},
		{Name: "express", Version: "4.20.0", Jump: "5.1.0"},
	}
	if !reflect.DeepEqual(got.Kept, wantKept) {
		t.Errorf("kept = %+v, want %+v", got.Kept, wantKept)
	}
	// html-minifier stays at its version with nothing to jump to.
	if got.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", got.Unchanged)
	}
	if err := archive.CheckReview(got, archive.NPM); err != nil {
		t.Errorf("the import would keep this review out: %v", err)
	}
}

func TestReviewOfListsTheKeptVersionsCVEs(t *testing.T) {
	r := reviewResult()
	sel, reasons := reviewSelection()
	got := ReviewOf(r, request(sel, reasons...), nil)
	want := []archive.ReviewCVE{
		{Dependency: "express", Version: "4.20.0", ID: "CVE-2024-0002", Severity: "MEDIUM", Package: "body-parser", FixedIn: "5.0.0"},
		{Dependency: "express", Version: "4.20.0", ID: "CVE-2024-0003", Severity: "LOW", Package: "cookie", FixedIn: "0.7.0"},
		{Dependency: "html-minifier", Version: "4.0.0", ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier", Reason: "Templates are ours."},
	}
	if !reflect.DeepEqual(got.Left, want) {
		t.Errorf("left =\n %+v\nwant\n %+v", got.Left, want)
	}

	// A dependency left out of the selection keeps its current version's
	// CVEs, with the reason given for those no version fixes. A 0.7.0 CVE
	// keeps an empty package and counts as one without fix.
	r.Dependencies[1].CVEs = []CVE{{ID: "CVE-2021-23337", Severity: "HIGH"}}
	sel = map[string][]string{"react": {"19.2.0"}, "react-dom": {"19.2.0"}}
	reasons = append(reasons, cveReason("Only our server parses bodies.", "express"))
	if problems := CheckReasons(r, request(sel, reasons...), askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	got = ReviewOf(r, request(sel, reasons...), nil)
	want = []archive.ReviewCVE{
		{Dependency: "express", Version: "4.17.1", ID: "CVE-2021-23337", Severity: "HIGH", Reason: "Only our server parses bodies."},
		{Dependency: "html-minifier", Version: "4.0.0", ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier", Reason: "Templates are ours."},
	}
	if !reflect.DeepEqual(got.Left, want) {
		t.Errorf("left without a selection =\n %+v\nwant\n %+v", got.Left, want)
	}
}

func TestReviewOfNamesTheFamilyOfAJump(t *testing.T) {
	r := reviewResult()
	sel, reasons := reviewSelection()
	sel["esbuild"] = []string{"0.19.0"}
	reasons = append(reasons, jumpReason("The bundle builds on 0.19.", "esbuild"))
	if problems := CheckReasons(r, request(sel, reasons...), askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	got := ReviewOf(r, request(sel, reasons...), nil)
	want := []archive.ReviewJump{
		{Packages: []archive.ReviewMove{{Name: "esbuild", From: "0.18.0", To: "0.19.0"}}, Reason: "The bundle builds on 0.19."},
		{
			Family: "react 19",
			Packages: []archive.ReviewMove{
				{Name: "react", From: "18.3.1", To: "19.2.0"},
				{Name: "react-dom", From: "18.3.1", To: "19.2.0"},
			},
			Reason: "The app moved to React 19.",
		},
	}
	if !reflect.DeepEqual(got.Jumps, want) {
		t.Errorf("jumps =\n %+v\nwant\n %+v", got.Jumps, want)
	}
	for _, k := range got.Kept {
		if k.Name == "esbuild" {
			t.Errorf("kept lists esbuild, which jumps")
		}
	}
	if err := archive.CheckReview(got, archive.NPM); err != nil {
		t.Errorf("the import would keep this review out: %v", err)
	}
}

func TestReviewOfKeepsEachReasonGivenForPartOfAFamily(t *testing.T) {
	r := reviewResult()
	// html-minifier takes its clean version, so the selection asks nothing
	// beyond the family.
	sel := map[string][]string{"react": {"19.2.0"}, "react-dom": {"19.2.0"}, "html-minifier": {"4.0.1"}}
	reasons := []Reason{
		jumpReason("The app moved to React 19.", "react"),
		jumpReason("The renderer follows React.", "react-dom"),
	}
	if problems := CheckReasons(r, request(sel, reasons...), askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	got := ReviewOf(r, request(sel, reasons...), nil)
	want := []archive.ReviewJump{
		{Family: "react 19", Packages: []archive.ReviewMove{{Name: "react", From: "18.3.1", To: "19.2.0"}}, Reason: "The app moved to React 19."},
		{Family: "react 19", Packages: []archive.ReviewMove{{Name: "react-dom", From: "18.3.1", To: "19.2.0"}}, Reason: "The renderer follows React."},
	}
	if !reflect.DeepEqual(got.Jumps, want) {
		t.Errorf("jumps =\n %+v\nwant\n %+v", got.Jumps, want)
	}
}

func TestReviewOfSignsTheTrimmedReason(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"react": {"19.2.0"}, "react-dom": {"19.2.0"}, "html-minifier": {"4.0.1"}}
	reasons := []Reason{jumpReason("  The app moved to React 19.  ", "react", "react-dom")}
	if problems := CheckReasons(r, request(sel, reasons...), askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	got := ReviewOf(r, request(sel, reasons...), nil)
	if len(got.Jumps) != 1 || got.Jumps[0].Reason != "The app moved to React 19." {
		t.Errorf("jumps = %+v, want one with the trimmed reason", got.Jumps)
	}
}

func TestReviewOfLeavesAfterOutWithoutAProjectScan(t *testing.T) {
	sel, reasons := reviewSelection()
	got := ReviewOf(reviewResult(), request(sel, reasons...), nil)
	if got.CVEs.After != nil {
		t.Errorf("cves.after = %v, want none without a project scan", *got.CVEs.After)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"after"`) {
		t.Errorf("the review holds an after key: %s", data)
	}
}

// A Trivy fixedIn past the import's 256-byte bound would make the import
// keep the review out: the signed one stops at the last whole version.
func TestReviewOfShortensALongFixedInAtAVersion(t *testing.T) {
	var versions []string
	for i := 0; len(strings.Join(versions, ", ")) < 300; i++ {
		versions = append(versions, fmt.Sprintf("4.%d.%d", i, 100+i))
	}
	long := strings.Join(versions, ", ")
	r := reviewResult()
	r.Dependencies[1].Candidates[0].CVEs[0].FixedIn = long
	sel, reasons := reviewSelection()
	got := ReviewOf(r, request(sel, reasons...), nil)
	fixedIn := got.Left[0].FixedIn
	if len(fixedIn) > 256 || len(fixedIn) == 0 {
		t.Fatalf("fixedIn is %d bytes, want 1 to 256 (from %d)", len(fixedIn), len(long))
	}
	if !strings.HasPrefix(long, fixedIn) || !strings.HasPrefix(long[len(fixedIn):], ", ") {
		t.Errorf("fixedIn %q does not stop at a version boundary of %q", fixedIn, long)
	}
	if err := archive.CheckReview(got, archive.NPM); err != nil {
		t.Errorf("the import would keep this review out: %v", err)
	}
}

func TestShortFixedInCutsALoneLongVersionOnARune(t *testing.T) {
	long := strings.Repeat("é", 200)
	got := shortFixedIn(long)
	if len(got) > 256 || !utf8.ValidString(got) || !strings.HasPrefix(long, got) {
		t.Errorf("shortFixedIn = %d bytes, valid %v, want a valid prefix of at most 256 bytes", len(got), utf8.ValidString(got))
	}
	if short := "4.0.1, 5.0.0"; shortFixedIn(short) != short {
		t.Errorf("shortFixedIn changed %q", short)
	}
}

// A name listed under two dependency kinds at the same version has two
// entries: review.left lists each of its CVEs once.
func TestReviewOfListsACVEOfANameListedTwiceOnce(t *testing.T) {
	r := reviewResult()
	r.Dependencies = append(r.Dependencies, r.Dependencies[2])
	sel, reasons := reviewSelection()
	got := ReviewOf(r, request(sel, reasons...), nil)
	n := 0
	for _, c := range got.Left {
		if c.ID == "CVE-2022-37620" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("review.left lists CVE-2022-37620 %d times, want once: %+v", n, got.Left)
	}
}

// A reason answers only for the CVEs no version fixes: a fixable CVE of
// the same version carries none.
func TestReviewOfPutsTheReasonOnlyOnCVEsWithoutFix(t *testing.T) {
	r := reviewResult()
	minifier := &r.Dependencies[2]
	minifier.CVEs = append(minifier.CVEs, CVE{ID: "CVE-2023-0004", Severity: "LOW", Package: "html-minifier@4.0.0", FixedIn: "4.0.1"})
	sel, reasons := reviewSelection()
	if problems := CheckReasons(r, request(sel, reasons...), askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	got := ReviewOf(r, request(sel, reasons...), nil)
	seen := 0
	for _, c := range got.Left {
		switch c.ID {
		case "CVE-2022-37620":
			seen++
			if c.Reason != "Templates are ours." {
				t.Errorf("the CVE without fix has reason %q, want the one given", c.Reason)
			}
		case "CVE-2023-0004":
			seen++
			if c.Reason != "" {
				t.Errorf("the fixable CVE has reason %q, want none", c.Reason)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("review.left = %+v, want both html-minifier CVEs", got.Left)
	}
}

// withProject is req shipping the project tree, whose lockfile scan holds
// findings.
func withProject(req ExportRequest, findings ...rank.Finding) ExportRequest {
	req.IncludeProject = true
	req.ProjectFindings = findings
	return req
}

func TestCheckReasonsReadsTheProjectScansCVEsWithoutFix(t *testing.T) {
	r := reviewResult()
	// react's own scan found nothing; the lockfile's scan finds one.
	reactCVE := rank.Finding{ID: "CVE-2025-0100", Package: "react", Version: "18.3.1", Severity: rank.High}
	// body-parser sits under express, which the analysis already knows.
	transitive := rank.Finding{ID: "CVE-2025-0200", Package: "body-parser", Version: "1.19.0", Severity: rank.Low}
	minifier := cveReason("Templates are ours.", "html-minifier")
	req := withProject(request(map[string][]string{}, minifier), reactCVE, transitive)

	assertProblems(t, CheckReasons(r, req, askReasons()), []string{
		"express 4.17.1 keeps CVE-2025-0200, which no version fixes, and needs a reason",
		"react 18.3.1 keeps CVE-2025-0100, which no version fixes, and needs a reason",
	})

	refuse := askReasons()
	refuse.CVEWithoutFix = policy.Refuse
	got := CheckReasons(r, req, refuse)
	for _, want := range []string{
		"review.cveWithoutFix is refuse: express 4.17.1 keeps CVE-2025-0200, which no version fixes, and cannot cross",
		"review.cveWithoutFix is refuse: react 18.3.1 keeps CVE-2025-0100, which no version fixes, and cannot cross",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("under refuse, problems = %q, want %q", got, want)
		}
	}

	req.Reasons = append(req.Reasons, cveReason("Only the admin page renders it.", "react"), cveReason("Bodies come from us.", "express"))
	if problems := CheckReasons(r, req, askReasons()); len(problems) > 0 {
		t.Fatalf("with every reason, problems = %q", problems)
	}
	left := ReviewOf(r, req, nil).Left
	if !slices.ContainsFunc(left, func(c archive.ReviewCVE) bool {
		return c.Dependency == "react" && c.ID == "CVE-2025-0100" && c.Reason == "Only the admin page renders it."
	}) {
		t.Errorf("review.left = %+v, want react's project CVE with its reason", left)
	}
}

// A package of the lockfile no dependency's scan names still holds a CVE
// that ships: refuse refuses it.
func TestCheckReasonsRefusesAProjectCVENoDependencyNames(t *testing.T) {
	r := reviewResult()
	refuse := askReasons()
	refuse.CVEWithoutFix = policy.Refuse
	req := withProject(request(map[string][]string{}), rank.Finding{ID: "CVE-2025-0300", Package: "qs", Version: "6.0.0", Severity: rank.High})
	want := "the project tree keeps qs 6.0.0 with CVE-2025-0300, which no version fixes, and no direct dependency's tree in the lockfile holds it, so it cannot cross"
	for _, p := range []policy.Review{refuse, askReasons()} {
		if got := CheckReasons(r, req, p); !slices.Contains(got, want) {
			t.Errorf("under %s, problems = %q, want %q", p.CVEWithoutFix, got, want)
		}
	}
}

// qs sits in the lockfile under express only, and express's own scan never
// names it: its CVE without a fix asks express a reason, and review.left
// lists it under express with qs named.
func TestCheckReasonsPlacesAnUnnamedLockfileCVEUnderItsDirectDependency(t *testing.T) {
	r := reviewResult()
	noFix := rank.Finding{ID: "CVE-2025-0300", Package: "qs", Version: "6.0.0", Severity: rank.High}
	fixed := rank.Finding{ID: "CVE-2025-0301", Package: "qs", Version: "6.0.0", Severity: rank.Medium, FixedVersion: "6.2.0"}
	req := withProject(request(map[string][]string{}), noFix, fixed)
	req.ProjectHolders = map[string][]string{"qs@6.0.0": {"express"}}

	req.Reasons = []Reason{cveReason("Templates are ours.", "html-minifier")}
	assertProblems(t, CheckReasons(r, req, askReasons()), []string{
		"express 4.17.1 keeps CVE-2025-0300, which no version fixes, and needs a reason",
	})
	refuse := askReasons()
	refuse.CVEWithoutFix = policy.Refuse
	if got := CheckReasons(r, req, refuse); !slices.ContainsFunc(got, func(p string) bool {
		return strings.HasPrefix(p, "review.cveWithoutFix is refuse: express 4.17.1 keeps") && strings.Contains(p, "CVE-2025-0300")
	}) {
		t.Errorf("under refuse, problems = %q, want express refused for CVE-2025-0300", got)
	}

	req.Reasons = append(req.Reasons, cveReason("Bodies come from us.", "express"))
	if problems := CheckReasons(r, req, askReasons()); len(problems) > 0 {
		t.Fatalf("with the reason, problems = %q", problems)
	}
	after := projectedFor(r, req, req.ProjectFindings)
	review := ReviewOf(r, req, &after)
	if !slices.ContainsFunc(review.Left, func(c archive.ReviewCVE) bool {
		return c.Dependency == "express" && c.Version == "4.17.1" && c.ID == "CVE-2025-0300" && c.Package == "qs" && c.Reason == "Bodies come from us."
	}) {
		t.Errorf("review.left = %+v, want CVE-2025-0300 under express, package qs, with the reason", review.Left)
	}
	ids := map[string]bool{}
	for _, c := range review.Left {
		ids[c.ID] = true
	}
	total := 0
	for _, n := range *review.CVEs.After {
		total += n
	}
	if total != len(ids) {
		t.Errorf("cves.after counts %d, review.left lists %d ids: %+v", total, len(ids), review.Left)
	}
	if err := archive.CheckReview(review, archive.NPM); err != nil {
		t.Errorf("the import would keep this review out: %v", err)
	}
}

// A package two direct dependencies reach asks both a reason.
func TestCheckReasonsAsksEveryDirectDependencyThatReachesALockfileCVE(t *testing.T) {
	r := reviewResult()
	req := withProject(request(map[string][]string{}), rank.Finding{ID: "CVE-2025-0300", Package: "qs", Version: "6.0.0", Severity: rank.High})
	req.ProjectHolders = map[string][]string{"qs@6.0.0": {"express", "react"}}
	req.Reasons = []Reason{cveReason("Bodies come from us.", "express"), cveReason("Templates are ours.", "html-minifier")}
	assertProblems(t, CheckReasons(r, req, askReasons()), []string{
		"react 18.3.1 keeps CVE-2025-0300, which no version fixes, and needs a reason",
	})
	req.Reasons = append(req.Reasons, cveReason("Only the admin page renders it.", "react"))
	left := ReviewOf(r, req, nil).Left
	for _, dep := range []string{"express", "react"} {
		if !slices.ContainsFunc(left, func(c archive.ReviewCVE) bool { return c.Dependency == dep && c.ID == "CVE-2025-0300" }) {
			t.Errorf("review.left = %+v, want CVE-2025-0300 under %s", left, dep)
		}
	}
}

// With the project tree, cves.after counts what the lockfile keeps, so it
// agrees with review.left.
func TestProjectedWithTheProjectCountsWhatReviewLeftLists(t *testing.T) {
	r := fixableResult()
	sel := map[string][]string{"express": {"4.20.0"}}
	var findings []rank.Finding
	for _, d := range r.Dependencies {
		for _, c := range d.CVEs {
			findings = append(findings, rank.Finding{ID: c.ID, Package: packageName(c.Package), Version: d.Current, Severity: rank.ParseSeverity(c.Severity), FixedVersion: c.FixedIn})
		}
	}
	req := withProject(request(sel), findings...)
	after := projectedFor(r, req, findings)
	ids := map[string]bool{}
	for _, c := range ReviewOf(r, req, &after).Left {
		ids[c.ID] = true
	}
	total := 0
	for _, n := range after {
		total += n
	}
	if total != len(ids) || total == 0 {
		t.Errorf("cves.after counts %d (%v), review.left lists %d ids", total, after, len(ids))
	}
}

func TestReviewOfKeepsAFixedInOfExactly256BytesWhole(t *testing.T) {
	exact := "4.0.1, " + strings.Repeat("9", 256-len("4.0.1, "))
	r := reviewResult()
	r.Dependencies[1].Candidates[0].CVEs[0].FixedIn = exact
	sel, reasons := reviewSelection()
	got := ReviewOf(r, request(sel, reasons...), nil)
	if got.Left[0].FixedIn != exact {
		t.Errorf("fixedIn = %d bytes, want the 256 bytes kept whole", len(got.Left[0].FixedIn))
	}
}

// A separator right after byte 256 means the versions before it fit
// whole: all 256 bytes stay.
func TestShortFixedInKeepsEveryVersionBeforeASeparatorAtTheBound(t *testing.T) {
	head := strings.Repeat("1", 200) + ", " + strings.Repeat("2", 256-202)
	long := head + ", 3.0.0"
	if got := shortFixedIn(long); got != head {
		t.Errorf("shortFixedIn = %d bytes, want the %d bytes before the separator", len(got), len(head))
	}
}

func TestShortFixedInCutsAFixedInOf257Bytes(t *testing.T) {
	long := strings.Repeat("1", 200) + ", " + strings.Repeat("2", 55)
	if got := shortFixedIn(long); got != long[:200] {
		t.Errorf("shortFixedIn = %d bytes, want 200", len(got))
	}
}

// A lockfile copy of a direct dependency at another version is not the
// dependency the project selects from: it asks that dependency nothing.
func TestCheckReasonsPlacesAProjectFindingOnADependencyOnlyAtItsCurrentVersion(t *testing.T) {
	r := reviewResult()
	req := withProject(request(map[string][]string{}), rank.Finding{ID: "CVE-2025-0400", Package: "react", Version: "17.0.2", Severity: rank.High})
	req.ProjectHolders = map[string][]string{"react@17.0.2": {"express"}}
	for _, p := range CheckReasons(r, req, askReasons()) {
		if strings.Contains(p, "react 18.3.1") {
			t.Errorf("problem %q places react 17.0.2 on react 18.3.1", p)
		}
	}
}

// Every lockfile CVE no dependency's scan places needs the lockfile
// walked, with a fix or without; the walk starts from its package alone.
func TestLockKeysToPlaceNamesEveryUnplacedFinding(t *testing.T) {
	r := reviewResult()
	findings := []rank.Finding{
		{ID: "CVE-2025-0300", Package: "qs", Version: "6.0.0"},
		{ID: "CVE-2025-0302", Package: "qs", Version: "6.0.0"},
		{ID: "CVE-2025-0301", Package: "ms", Version: "2.0.0", FixedVersion: "2.1.0"},
		{ID: "CVE-2025-0100", Package: "react", Version: "18.3.1"},
	}
	if got, want := lockKeysToPlace(r, findings), []string{"qs@6.0.0", "ms@2.0.0"}; !slices.Equal(got, want) {
		t.Errorf("lockKeysToPlace = %q, want %q", got, want)
	}
	if got := lockKeysToPlace(r, findings[3:]); len(got) != 0 {
		t.Errorf("with every finding placed, lockKeysToPlace = %q, want none", got)
	}
}

const expressQsLock = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express:
        specifier: 4.17.1
        version: 4.17.1
snapshots:
  express@4.17.1:
    dependencies:
      qs: 6.0.0
  qs@6.0.0: {}
`

// A fixable lockfile CVE that no dependency's scan places is counted in
// cves.after, so review.left must list it under the direct dependency the
// lockfile places it under, with its fix, and ask no reason for it.
func TestReviewLeftListsEveryCVEAfterCountsWithTheProject(t *testing.T) {
	r := reviewResult()
	fixed := rank.Finding{ID: "CVE-2025-0301", Package: "qs", Version: "6.0.0", Severity: rank.Medium, FixedVersion: "6.2.0"}
	req := withProject(request(map[string][]string{}), fixed)
	holders, err := npm.LockHolders(strings.NewReader(expressQsLock), lockKeysToPlace(r, req.ProjectFindings))
	if err != nil {
		t.Fatal(err)
	}
	req.ProjectHolders = holders
	req.Reasons = []Reason{cveReason("Templates are ours.", "html-minifier")}
	if problems := CheckReasons(r, req, askReasons()); len(problems) > 0 {
		t.Fatalf("a fixable CVE asked for a reason: %q", problems)
	}
	after := projectedFor(r, req, req.ProjectFindings)
	review := ReviewOf(r, req, &after)
	if !slices.ContainsFunc(review.Left, func(c archive.ReviewCVE) bool {
		return c.Dependency == "express" && c.ID == "CVE-2025-0301" && c.Package == "qs" && c.FixedIn == "6.2.0"
	}) {
		t.Errorf("review.left = %+v, want CVE-2025-0301 under express with fixedIn 6.2.0", review.Left)
	}
	ids := map[string]bool{}
	for _, c := range review.Left {
		ids[c.ID] = true
	}
	total := 0
	for _, n := range *review.CVEs.After {
		total += n
	}
	if total != len(ids) {
		t.Errorf("cves.after counts %d, review.left lists %d ids: %+v", total, len(ids), review.Left)
	}
}

// A holder the analysis does not know, such as a dev dependency it never
// ranked, places nothing: the CVE stays unplaced and cannot cross.
func TestCheckReasonsIgnoresALockfileHolderOutsideTheAnalysis(t *testing.T) {
	r := reviewResult()
	req := withProject(request(map[string][]string{}, cveReason("Templates are ours.", "html-minifier")), rank.Finding{ID: "CVE-2025-0300", Package: "qs", Version: "6.0.0", Severity: rank.High})
	req.ProjectHolders = map[string][]string{"qs@6.0.0": {"ghost"}}
	assertProblems(t, CheckReasons(r, req, askReasons()), []string{
		"the project tree keeps qs 6.0.0 with CVE-2025-0300, which no version fixes, and no direct dependency's tree in the lockfile holds it, so it cannot cross",
	})
}

// A CVE some dependency's own scan places is asked of that dependency
// only, whatever other holders the lockfile names.
func TestCheckReasonsAsksAScanPlacedCVEOfItsDependencyOnly(t *testing.T) {
	r := reviewResult()
	transitive := rank.Finding{ID: "CVE-2025-0200", Package: "body-parser", Version: "1.19.0", Severity: rank.Low}
	req := withProject(request(map[string][]string{}, cveReason("Templates are ours.", "html-minifier")), transitive)
	req.ProjectHolders = map[string][]string{"body-parser@1.19.0": {"express", "react"}}
	assertProblems(t, CheckReasons(r, req, askReasons()), []string{
		"express 4.17.1 keeps CVE-2025-0200, which no version fixes, and needs a reason",
	})
}

// A lockfile CVE with a fix is never counted as unplaced.
func TestCheckReasonsLeavesAFixedUnplacedCVEOut(t *testing.T) {
	r := reviewResult()
	fixed := rank.Finding{ID: "CVE-2025-0301", Package: "qs", Version: "6.0.0", Severity: rank.Medium, FixedVersion: "6.2.0"}
	req := withProject(request(map[string][]string{}, cveReason("Templates are ours.", "html-minifier")), fixed)
	assertProblems(t, CheckReasons(r, req, askReasons()), nil)
}

func TestSignsTheProjectsNameInTheReview(t *testing.T) {
	for name, tc := range map[string]struct{ project, read string }{
		"a name the import reads": {"pdf-renderer", "pdf-renderer"},
		"a name the import drops": {"pdf\u202erenderer", ""},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness(t)
			analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
			h.buildAnalysis(analysisDir)
			exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
			exp := reviewedExport(t, h, analysisDir, exportDir, "Only our own build calls the gadget.")
			exp.Project.Name = tc.project
			if err := exp.Run(context.Background(), noopEmit); err != nil {
				t.Fatalf("Run: %v", err)
			}
			assertSigned(t, exportDir, h.store.SigningKey())
			data, err := os.ReadFile(filepath.Join(exportDir, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var written struct {
				Review struct {
					Project *string `json:"project"`
				} `json:"review"`
			}
			if err := json.Unmarshal(data, &written); err != nil {
				t.Fatal(err)
			}
			if written.Review.Project == nil || *written.Review.Project != tc.project {
				t.Errorf("review.project = %v, want the store's name %q", written.Review.Project, tc.project)
			}
			m, err := archive.ParseManifest(data)
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if m.Review == nil || m.ReviewProblem != "" || m.Review.Project != tc.read {
				t.Errorf("the import read %+v, %q, want the project %q", m.Review, m.ReviewProblem, tc.read)
			}
		})
	}
}
