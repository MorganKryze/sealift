package jobs

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/store"
)

// pipReviewResult is a pip analysis compared with a previous crossing:
// django takes a major jump, idna is new and yanked, requests moves inside
// its major, urllib3 keeps a CVE no version fixes, certifi stays, and six
// left the set.
func pipReviewResult() PipResult {
	sealed := time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)
	return PipResult{
		Target:   store.DefaultPipTarget,
		Files:    []string{"requirements.txt"},
		Blocking: []PipBlocking{},
		Warnings: []string{},
		Previous: &PipPreviousCrossing{ProjectID: "data-tools", ProjectName: "Data tools", ExportID: "20261001T090000Z", AnalysisID: "20261001T080000Z", SealedAt: sealed},
		Packages: []PipPackage{
			{Name: "certifi", Version: "2024.8.30", CVEs: []PipFinding{}, Previous: &PipPrevious{Version: "2024.8.30", CVEs: []PipFinding{}}},
			{
				Name: "django", Version: "5.1.4", CVEs: []PipFinding{},
				Previous: &PipPrevious{Version: "4.2.16", MajorJump: true, CVEs: []PipFinding{{ID: "CVE-2024-0001", Severity: "HIGH", FixedVersions: []string{"4.2.17"}}}},
			},
			{Name: "idna", Version: "3.10", CVEs: []PipFinding{}, Yanked: &PipYanked{Reason: "broken metadata"}},
			{
				Name: "requests", Version: "2.32.3",
				CVEs: []PipFinding{{ID: "CVE-2024-47081", Severity: "MEDIUM", FixedVersions: []string{"2.32.4"}}},
				Previous: &PipPrevious{Version: "2.31.0", CVEs: []PipFinding{
					{ID: "CVE-2024-35195", Severity: "MEDIUM", FixedVersions: []string{"2.32.0"}},
					{ID: "CVE-2024-47081", Severity: "MEDIUM", FixedVersions: []string{"2.32.4"}},
				}},
			},
			{
				Name: "urllib3", Version: "1.26.0",
				CVEs:     []PipFinding{{ID: "CVE-2099-0001", Severity: "HIGH", FixedVersions: []string{}}},
				Previous: &PipPrevious{Version: "1.26.0", CVEs: []PipFinding{{ID: "CVE-2099-0001", Severity: "HIGH", FixedVersions: []string{}}}},
			},
		},
		Removed: []PipRemoved{{Name: "six", Version: "1.16.0", CVEs: []PipFinding{{ID: "CVE-2099-0002", Severity: "LOW", FixedVersions: []string{}}}}},
	}
}

func pipReason(kind ReasonKind, text string, names ...string) Reason {
	return Reason{Kind: kind, Dependencies: names, Text: text}
}

// pipReviewReasons are the three reasons pipReviewResult needs.
func pipReviewReasons() []Reason {
	return []Reason{
		pipReason(MajorJumpReason, "Our tests pass on Django 5.", "django"),
		pipReason(YankedReason, "Only the metadata was wrong.", "idna"),
		pipReason(CVEWithoutFixReason, "The proxy never reaches it.", "urllib3"),
	}
}

// without returns reasons without the one of kind.
func without(reasons []Reason, kind ReasonKind) []Reason {
	var out []Reason
	for _, r := range reasons {
		if r.Kind != kind {
			out = append(out, r)
		}
	}
	return out
}

func TestPipExportAsksAReasonForEachMajorJump(t *testing.T) {
	r := pipReviewResult()
	assertProblems(t, CheckPipReasons(r, pipReviewReasons()), nil)
	assertProblems(t, CheckPipReasons(r, without(pipReviewReasons(), MajorJumpReason)),
		[]string{"django 4.2.16 to 5.1.4 is a major jump and needs a reason"})

	// A move inside the major asks nothing.
	r.Packages[1].Previous.MajorJump = false
	assertProblems(t, CheckPipReasons(r, without(pipReviewReasons(), MajorJumpReason)), nil)
}

func TestPipExportAsksAReasonForEachCVEWithoutFix(t *testing.T) {
	r := pipReviewResult()
	r.Packages[4].CVEs = append(r.Packages[4].CVEs,
		PipFinding{ID: "CVE-2099-0003", Severity: "LOW", FixedVersions: []string{" "}},
		PipFinding{ID: "CVE-2099-0004", Severity: "LOW", FixedVersions: []string{"2.0.0"}},
	)
	assertProblems(t, CheckPipReasons(r, without(pipReviewReasons(), CVEWithoutFixReason)),
		[]string{"urllib3 1.26.0 keeps CVE-2099-0001 and CVE-2099-0003, which no version fixes, and needs a reason"})
	assertProblems(t, CheckPipReasons(r, pipReviewReasons()), nil)

	// A CVE with a fix asks nothing.
	r.Packages[4].CVEs = r.Packages[4].CVEs[2:]
	assertProblems(t, CheckPipReasons(r, without(pipReviewReasons(), CVEWithoutFixReason)), nil)
}

func TestPipExportAsksAReasonForEachYankedRelease(t *testing.T) {
	r := pipReviewResult()
	assertProblems(t, CheckPipReasons(r, without(pipReviewReasons(), YankedReason)),
		[]string{"idna 3.10 is yanked on the index and needs a reason"})

	// A yanked release with no reason from the index asks one all the same.
	r.Packages[0].Yanked = &PipYanked{}
	assertProblems(t, CheckPipReasons(r, pipReviewReasons()),
		[]string{"certifi 2024.8.30 is yanked on the index and needs a reason"})
	both := append(without(pipReviewReasons(), YankedReason), pipReason(YankedReason, "Both were fine.", "certifi", "idna"))
	assertProblems(t, CheckPipReasons(r, both), []string{
		"certifi 2024.8.30 is yanked on the index and needs a reason",
		"idna 3.10 is yanked on the index and needs a reason",
		"reason 3 (yanked) names 2 packages, and a pip reason covers one",
	})
	two := append(pipReviewReasons(), pipReason(YankedReason, "The index kept it once.", "certifi"))
	assertProblems(t, CheckPipReasons(r, two), nil)
}

func TestPipExportRefusesAReasonThatCoversNothingOrRepeats(t *testing.T) {
	r := pipReviewResult()
	for _, tc := range []struct {
		name  string
		extra Reason
		want  string
	}{
		{"a yanked reason for a release the index keeps", pipReason(YankedReason, "In case.", "certifi"), "reason 4 (yanked) covers nothing the set needs: certifi needs no such reason"},
		{"a jump reason for a move inside the major", pipReason(MajorJumpReason, "In case.", "requests"), "reason 4 (major-jump) covers nothing the set needs: requests needs no such reason"},
		{"a CVE reason for a CVE with a fix", pipReason(CVEWithoutFixReason, "In case.", "requests"), "reason 4 (cve-without-fix) covers nothing the set needs: requests needs no such reason"},
		{"a second reason for one package", pipReason(YankedReason, "Again.", "idna"), "reason 4 (yanked) repeats the reason for idna"},
		{"a second reason under another spelling", pipReason(MajorJumpReason, "Again.", "Django"), "reason 4 (major-jump) repeats the reason for django"},
		{"a package the set does not hold", pipReason(YankedReason, "In case.", "evil\u202ename"), "reason 4 (yanked) names a package the analysis does not hold"},
		{"no package", pipReason(YankedReason, "In case."), "reason 4 (yanked) names no package"},
		{"an unknown kind", pipReason("family", "In case.", "idna"), "reason 4 has an unknown kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertProblems(t, CheckPipReasons(r, append(pipReviewReasons(), tc.extra)), []string{tc.want})
		})
	}
}

func TestPipExportChecksEachReasonText(t *testing.T) {
	r := pipReviewResult()
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
			reasons := pipReviewReasons()
			reasons[0].Text = tc.text
			assertProblems(t, CheckPipReasons(r, reasons), []string{tc.want})
		})
	}
}

func TestPipExportRefusesUnderEachRefuseRuleWhateverTheReasons(t *testing.T) {
	r := pipReviewResult()
	const (
		jump = "review.majorJump is refuse: django 4.2.16 to 5.1.4 is a major jump and cannot cross"
		cve  = "review.cveWithoutFix is refuse: urllib3 1.26.0 keeps CVE-2099-0001, which no version fixes, and cannot cross"
		yank = "review.yanked is refuse: idna 3.10 is yanked on the index and cannot cross"
	)
	reason := policy.AskReason
	for _, tc := range []struct {
		name   string
		policy policy.Review
		want   string
	}{
		{"major jumps", policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: reason, Yanked: reason}, jump},
		{"CVEs without fix", policy.Review{MajorJump: reason, CVEWithoutFix: policy.Refuse, Yanked: reason}, cve},
		{"yanked releases", policy.Review{MajorJump: reason, CVEWithoutFix: reason, Yanked: policy.Refuse}, yank},
		{"all three", policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse, Yanked: policy.Refuse}, jump + "; " + cve + "; " + yank},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := pipRefusals(r, tc.policy)
			if !errors.Is(err, ErrPipNotExportable) || err.Error() != "jobs: "+tc.want {
				t.Fatalf("pipRefusals = %v, want ErrPipNotExportable saying %q", err, "jobs: "+tc.want)
			}
		})
	}
	if err := pipRefusals(r, policy.DefaultReview()); err != nil {
		t.Errorf("pipRefusals under the default rules = %v, want nil", err)
	}

	t.Run("names at most three packages per rule", func(t *testing.T) {
		r := pipReviewResult()
		for i := range r.Packages {
			r.Packages[i].Yanked = &PipYanked{}
		}
		err := pipRefusals(r, policy.Review{MajorJump: reason, CVEWithoutFix: reason, Yanked: policy.Refuse})
		want := "jobs: review.yanked is refuse: certifi 2024.8.30 is yanked on the index and cannot cross; " +
			"django 5.1.4 is yanked on the index and cannot cross; idna 3.10 is yanked on the index and cannot cross; and 2 more"
		if err == nil || err.Error() != want {
			t.Errorf("pipRefusals = %v, want %q", err, want)
		}
	})

	t.Run("at the queue, with every reason given", func(t *testing.T) {
		f := donePipAnalysis(t, piptest.NewIndex(t))
		res := f.ref.Result
		res.Packages = clonePipPackages(res.Packages)
		res.Packages[1].Yanked = &PipYanked{Reason: "broken"}
		if err := f.st.WriteJSON(filepath.Join(f.ref.Dir, "pip-result.json"), res); err != nil {
			t.Fatal(err)
		}
		f.svc.Review = policy.Review{MajorJump: reason, CVEWithoutFix: reason, Yanked: policy.Refuse}
		reasons := []Reason{pipReason(YankedReason, "We need it.", "idna")}
		_, err := f.svc.QueueExport(f.project.ID, f.ref.ID, ExportRequest{Reasons: reasons})
		if want := "review.yanked is refuse: idna 3.10 is yanked on the index and cannot cross"; !errors.Is(err, ErrPipNotExportable) || !strings.Contains(err.Error(), want) {
			t.Fatalf("QueueExport = %v, want a 409 saying %q", err, want)
		}
		if strings.Contains(err.Error(), "We need it.") {
			t.Errorf("the refusal %q repeats the reason's text", err)
		}
		noExportReserved(t, f.project)
	})
}

// A pip analysis from sealift 0.7.0 recorded no previous crossing and no
// yanked mark, so only its CVEs without fix ask a reason.
func TestPipExportOfA070AnalysisAsksNoJumpOrYankedReason(t *testing.T) {
	r := pipReviewResult()
	r.Previous, r.Removed = nil, nil
	for i := range r.Packages {
		r.Packages[i].Previous, r.Packages[i].Yanked = nil, nil
	}
	assertProblems(t, CheckPipReasons(r, nil),
		[]string{"urllib3 1.26.0 keeps CVE-2099-0001, which no version fixes, and needs a reason"})
	assertProblems(t, CheckPipReasons(r, pipReviewReasons()), []string{
		"reason 1 (major-jump) covers nothing the set needs: django needs no such reason",
		"reason 2 (yanked) covers nothing the set needs: idna needs no such reason",
	})
	if err := pipRefusals(r, policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.AskReason, Yanked: policy.Refuse}); err != nil {
		t.Errorf("pipRefusals = %v, want nil: the analysis records no jump and no yanked release", err)
	}
}

func TestNpmExportRefusesAYankedReason(t *testing.T) {
	r := fixableResult()
	sel := map[string][]string{"express": {"5.1.0"}}
	reasons := []Reason{jumpReason("Our tests pass on 5.", "express"), {Kind: YankedReason, Dependencies: []string{"express"}, Text: "In case."}}
	assertProblems(t, CheckReasons(r, request(sel, reasons...), askReasons()), []string{"reason 2 has an unknown kind"})
}

func TestPipReviewOfCountsBeforeAndAfter(t *testing.T) {
	r := pipReviewResult()
	after := [5]int{0, 1, 1, 0, 0}
	want := archive.Review{
		// django's and requests' earlier CVEs, urllib3's, and six's, which left.
		CVEs: archive.ReviewCVEs{Before: [5]int{0, 2, 2, 1, 0}, After: &after},
		Updates: []archive.ReviewUpdate{
			{Name: "requests", From: "2.31.0", To: "2.32.3", Fixed: [5]int{0, 0, 1, 0, 0}, Left: [5]int{0, 0, 1, 0, 0}},
		},
		Kept: []archive.ReviewKept{},
		Jumps: []archive.ReviewJump{
			{Packages: []archive.ReviewMove{{Name: "django", From: "4.2.16", To: "5.1.4"}}, Reason: "Our tests pass on Django 5."},
		},
		Left: []archive.ReviewCVE{
			{Dependency: "requests", Version: "2.32.3", ID: "CVE-2024-47081", Severity: "MEDIUM", Package: "requests", FixedIn: "2.32.4"},
			{Dependency: "urllib3", Version: "1.26.0", ID: "CVE-2099-0001", Severity: "HIGH", Package: "urllib3", Reason: "The proxy never reaches it."},
		},
		Unchanged: 2,
		Yanked:    []archive.ReviewYanked{{Dependency: "idna", Version: "3.10", IndexReason: "broken metadata", Reason: "Only the metadata was wrong."}},
	}
	reasons := pipReviewReasons()
	reasons[0].Text = "  " + reasons[0].Text + " "
	got := PipReviewOf(r, reasons)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PipReviewOf =\n%+v\nwant\n%+v", got, want)
	}
	if err := archive.CheckReview(got, archive.Pip); err != nil {
		t.Errorf("CheckReview: %v", err)
	}

	t.Run("with no previous crossing", func(t *testing.T) {
		r := pipReviewResult()
		r.Previous, r.Removed = nil, nil
		for i := range r.Packages {
			r.Packages[i].Previous = nil
		}
		got := PipReviewOf(r, pipReviewReasons()[1:])
		if got.CVEs.After == nil || got.CVEs.Before != *got.CVEs.After || got.CVEs.Before != after {
			t.Errorf("cves = %+v, want before equal to after, %v", got.CVEs, after)
		}
		// No comparison ran, so no package counts as unchanged.
		if len(got.Updates) != 0 || len(got.Jumps) != 0 || got.Unchanged != 0 {
			t.Errorf("updates %v, jumps %v, unchanged %d; want none of each", got.Updates, got.Jumps, got.Unchanged)
		}
	})

	t.Run("with no yanked release", func(t *testing.T) {
		r := pipReviewResult()
		r.Packages[2].Yanked = nil
		if got := PipReviewOf(r, without(pipReviewReasons(), YankedReason)); got.Yanked != nil {
			t.Errorf("yanked = %v, want the list left out", got.Yanked)
		}
	})
}

// A long index reason reaches the review whole: it is the analysis that
// bounds it, and CheckReview that refuses one past the bound.
func TestPipReviewOfKeepsTheIndexReason(t *testing.T) {
	r := pipReviewResult()
	r.Packages[2].Yanked.Reason = strings.Repeat("x", 201)
	got := PipReviewOf(r, pipReviewReasons())
	if len(got.Yanked) != 1 || got.Yanked[0].IndexReason != r.Packages[2].Yanked.Reason {
		t.Fatalf("yanked = %+v, want the index reason as recorded", got.Yanked)
	}
	if err := archive.CheckReview(got, archive.Pip); err == nil || !strings.Contains(err.Error(), "review.yanked[0].indexReason") {
		t.Errorf("CheckReview = %v, want the index reason refused by name", err)
	}
}

func TestPipBlockedRefusalNamesAtMostThreePackages(t *testing.T) {
	r := pipReviewResult()
	r.Packages = nil
	r.Blocking = []PipBlocking{{Name: "a", Version: "1.0"}, {Name: "b", Version: "1.0"}, {Name: "c", Version: "1.0"}, {Name: "d", Version: "1.0"}, {Name: "e", Version: "1.0"}}
	err := pipBlockedRefusal(r)
	if err == nil || !strings.HasSuffix(err.Error(), "c 1.0 and 2 more") || strings.Contains(err.Error(), "d 1.0") {
		t.Errorf("pipBlockedRefusal = %v, want three packages and the 2 more", err)
	}
}

func TestPipReviewOfCountsTwoSpellingsOfAVersionAsUnchanged(t *testing.T) {
	r := pipReviewResult()
	r.Packages[0].Version, r.Packages[0].Previous.Version = "1.0", "1.0.0"
	got := PipReviewOf(r, pipReviewReasons())
	if got.Unchanged != 2 || len(got.Updates) != 1 {
		t.Errorf("unchanged %d, updates %v; want 1.0 and 1.0.0 counted as unchanged", got.Unchanged, got.Updates)
	}
}

func TestPipReviewOfClearsBlankFixingVersions(t *testing.T) {
	r := pipReviewResult()
	r.Packages[4].CVEs[0].FixedVersions = []string{" ", ""}
	got := PipReviewOf(r, pipReviewReasons())
	want := archive.ReviewCVE{Dependency: "urllib3", Version: "1.26.0", ID: "CVE-2099-0001", Severity: "HIGH", Package: "urllib3", Reason: "The proxy never reaches it."}
	if !slices.Contains(got.Left, want) {
		t.Errorf("left = %+v, want %+v", got.Left, want)
	}
}
