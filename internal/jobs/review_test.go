package jobs

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/policy"
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

func askReasons() policy.Review { return policy.DefaultReview() }

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
	r := reviewResult()
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
			assertProblems(t, CheckReasons(r, tc.selection, nil, askReasons()), tc.want)
		})
	}

	got := CheckReasons(r, map[string][]string{"express": {"5.1.0"}}, []Reason{jumpReason("Our tests pass on 5.", "express")}, askReasons())
	assertProblems(t, got, nil)

	// A jump selected beside a better version inside the line crosses too,
	// so it asks its reason though an install keeps the other version.
	worse := reviewResult()
	worse.Dependencies[1].Candidates[1].Vector = Vector{1, 0, 0, 0, 0}
	worse.Dependencies[1].Candidates[1].CVEs = []CVE{{ID: "CVE-2025-0005", Severity: "CRITICAL", Package: "express@5.1.0", FixedIn: "5.1.1"}}
	assertProblems(t, CheckReasons(worse, map[string][]string{"express": {"4.20.0", "5.1.0"}}, nil, askReasons()),
		[]string{"express 4.17.1 to 5.1.0 leaves major 4 and needs a reason"})
}

func TestCheckReasonsAsksForACVEWithoutFix(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"html-minifier": {"4.0.0"}}
	assertProblems(t, CheckReasons(r, sel, nil, askReasons()),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason"})

	// A jump reason is not a CVE reason.
	assertProblems(t, CheckReasons(r, sel, []Reason{jumpReason("Templates are ours.", "html-minifier")}, askReasons()), []string{
		"html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason",
		"reason 1 (major-jump) covers nothing the selection takes",
	})
	assertProblems(t, CheckReasons(r, sel, []Reason{cveReason("Templates are ours.", "html-minifier")}, askReasons()), nil)

	// Every such CVE of one dependency asks one reason.
	r.Dependencies[2].CVEs = append(r.Dependencies[2].CVEs, CVE{ID: "CVE-2022-99999", Severity: "LOW", Package: "relateurl@0.2.7"})
	assertProblems(t, CheckReasons(r, sel, nil, askReasons()),
		[]string{"html-minifier 4.0.0 keeps CVE-2022-37620 and CVE-2022-99999, which no version fixes, and needs a reason"})
}

func TestCheckReasonsCountsAnUnknownFixAsNone(t *testing.T) {
	r := reviewResult()
	// The bytes an analysis of sealift 0.7.0 wrote for a CVE: no package,
	// no fixing version.
	var old []CVE
	if err := json.Unmarshal([]byte(`[{"id":"CVE-2021-23337","severity":"HIGH"}]`), &old); err != nil {
		t.Fatal(err)
	}
	r.Dependencies[1].CVEs = old
	assertProblems(t, CheckReasons(r, map[string][]string{"express": {"4.17.1"}}, nil, askReasons()),
		[]string{"express 4.17.1 keeps CVE-2021-23337, which no version fixes, and needs a reason"})
}

func TestCheckReasonsAsksNothingForAFixInAnotherLine(t *testing.T) {
	r := reviewResult()
	// express 4.17.1 keeps CVE-2024-0002, fixed in 5.0.0 only.
	assertProblems(t, CheckReasons(r, map[string][]string{"express": {"4.17.1"}}, nil, askReasons()), nil)
	assertProblems(t, CheckReasons(r, map[string][]string{"express": {"4.20.0"}}, nil, askReasons()), nil)
}

func TestCheckReasonsAcceptsOneReasonForAFamily(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"react": {"19.2.0"}, "react-dom": {"19.2.0"}}
	assertProblems(t, CheckReasons(r, sel, nil, askReasons()), []string{
		"react 18.3.1 to 19.2.0 leaves major 18 and needs a reason",
		"react-dom 18.3.1 to 19.2.0 leaves major 18 and needs a reason",
	})
	assertProblems(t, CheckReasons(r, sel, []Reason{jumpReason("The app moved to React 19.", "react", "react-dom")}, askReasons()), nil)
	assertProblems(t, CheckReasons(r, sel, []Reason{jumpReason("The app moved to React 19.", "react")}, askReasons()),
		[]string{"react-dom 18.3.1 to 19.2.0 leaves major 18 and needs a reason"})
}

func TestCheckReasonsUsesTheVersionAnInstallKeeps(t *testing.T) {
	r := reviewResult()
	// 4.0.1 carries nothing, so an install keeps it over 4.0.0.
	assertProblems(t, CheckReasons(r, map[string][]string{"html-minifier": {"4.0.0", "4.0.1"}}, nil, askReasons()), nil)

	// The other way round: the candidate carries a CVE without fix, the
	// current version none, and the install keeps the current one.
	r.Dependencies[2].CVEs, r.Dependencies[2].Vector = []CVE{}, Vector{}
	r.Dependencies[2].Candidates[0].CVEs = []CVE{{ID: "CVE-2025-0001", Severity: "LOW", Package: "html-minifier@4.0.1"}}
	r.Dependencies[2].Candidates[0].Vector = Vector{0, 0, 0, 1, 0}
	assertProblems(t, CheckReasons(r, map[string][]string{"html-minifier": {"4.0.0", "4.0.1"}}, nil, askReasons()), nil)
	assertProblems(t, CheckReasons(r, map[string][]string{"html-minifier": {"4.0.1"}}, nil, askReasons()),
		[]string{"html-minifier 4.0.1 keeps CVE-2025-0001, which no version fixes, and needs a reason"})
}

func TestCheckReasonsRefusesWhatThePolicyRefuses(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"express": {"5.1.0"}, "html-minifier": {"4.0.0"}}
	reasons := []Reason{jumpReason("Our tests pass on 5.", "express"), cveReason("Templates are ours.", "html-minifier")}

	refuseBoth := policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	assertProblems(t, CheckReasons(r, sel, reasons, refuseBoth), []string{
		"review.majorJump is refuse: express 4.17.1 to 5.1.0 cannot cross",
		"review.cveWithoutFix is refuse: html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and cannot cross",
	})

	refuseJumps := policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.AskReason}
	assertProblems(t, CheckReasons(r, sel, reasons, refuseJumps),
		[]string{"review.majorJump is refuse: express 4.17.1 to 5.1.0 cannot cross"})

	refuseCVEs := policy.Review{MajorJump: policy.AskReason, CVEWithoutFix: policy.Refuse}
	assertProblems(t, CheckReasons(r, sel, reasons, refuseCVEs),
		[]string{"review.cveWithoutFix is refuse: html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and cannot cross"})
}

func TestCheckReasonsRefusesAReasonThatCoversNothing(t *testing.T) {
	r := reviewResult()
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
			assertProblems(t, CheckReasons(r, tc.selection, tc.reasons, askReasons()), tc.want)
		})
	}
}

func TestCheckReasonsRefusesAnUnknownDependency(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"express": {"5.1.0"}}
	got := CheckReasons(r, sel, []Reason{jumpReason("Our tests pass on 5.", "express", "evil\u202ename")}, askReasons())
	assertProblems(t, got, []string{"reason 1 (major-jump) names a dependency the analysis does not hold"})

	got = CheckReasons(r, sel, []Reason{jumpReason("Our tests pass on 5.", "express"), jumpReason("Nothing named.")}, askReasons())
	assertProblems(t, got, []string{"reason 2 (major-jump) names no dependency"})

	got = CheckReasons(r, sel, []Reason{jumpReason("Our tests pass on 5.", "express"), {Kind: "<script>", Dependencies: []string{"express"}, Text: "x"}}, askReasons())
	assertProblems(t, got, []string{"reason 2 has an unknown kind"})
}

func TestExportChecksReasonsByTheImportsRule(t *testing.T) {
	r := reviewResult()
	sel := map[string][]string{"express": {"5.1.0"}}
	for _, tc := range []struct {
		name, text, want string
	}{
		{"a line separator", "tests pass\u2028on 5", "reason 1 (major-jump): the reason holds a control, line-separating, bidirectional or format character"},
		{"a bidirectional override", "tests pass \u202eon 5", "reason 1 (major-jump): the reason holds a control, line-separating, bidirectional or format character"},
		{"spaces only", "   ", "reason 1 (major-jump): the reason is empty"},
		{"301 characters", strings.Repeat("é", archive.MaxReasonRunes+1), "reason 1 (major-jump): the reason is longer than 300 characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckReasons(r, sel, []Reason{jumpReason(tc.text, "express")}, askReasons())
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
	if problems := CheckReasons(r, sel, reasons, askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	projected := rank.Vector{0, 1, 1, 1, 0}
	got := ReviewOf(r, sel, reasons, &projected)

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
	got := ReviewOf(r, sel, reasons, nil)
	want := []archive.ReviewCVE{
		{Dependency: "express", Version: "4.20.0", ID: "CVE-2024-0002", Severity: "MEDIUM", Package: "body-parser", FixedIn: "5.0.0"},
		{Dependency: "express", Version: "4.20.0", ID: "CVE-2024-0003", Severity: "LOW", Package: "cookie", FixedIn: "0.7.0"},
		{Dependency: "html-minifier", Version: "4.0.0", ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier", Reason: "Templates are ours."},
	}
	if !reflect.DeepEqual(got.Left, want) {
		t.Errorf("left =\n %+v\nwant\n %+v", got.Left, want)
	}

	// A dependency left out of the selection keeps its current version's
	// CVEs, and a 0.7.0 CVE keeps an empty package.
	r.Dependencies[1].CVEs = []CVE{{ID: "CVE-2021-23337", Severity: "HIGH"}}
	got = ReviewOf(r, map[string][]string{"react": {"19.2.0"}, "react-dom": {"19.2.0"}}, reasons[:1], nil)
	want = []archive.ReviewCVE{
		{Dependency: "express", Version: "4.17.1", ID: "CVE-2021-23337", Severity: "HIGH"},
		{Dependency: "html-minifier", Version: "4.0.0", ID: "CVE-2022-37620", Severity: "HIGH", Package: "html-minifier"},
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
	if problems := CheckReasons(r, sel, reasons, askReasons()); len(problems) > 0 {
		t.Fatalf("the selection should pass: %q", problems)
	}
	got := ReviewOf(r, sel, reasons, nil)
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

func TestReviewOfLeavesAfterOutWithoutAProjectScan(t *testing.T) {
	sel, reasons := reviewSelection()
	got := ReviewOf(reviewResult(), sel, reasons, nil)
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
