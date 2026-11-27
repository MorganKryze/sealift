package archive

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCheckReasonRefuses(t *testing.T) {
	const empty, long, unsafe = "is empty", "is longer than 300 characters", "holds a control, line-separating, bidirectional or format character"
	tests := []struct {
		name, text, rule string
	}{
		{"empty", "", empty},
		{"spaces only", "    ", empty},
		{"301 runes", strings.Repeat("é", MaxReasonRunes+1), long},
		{"newline", "owned\nsecond line", unsafe},
		{"tab", "owned\tcolumn", unsafe},
		{"line separator", "owned\u2028second line", unsafe},
		{"paragraph separator", "owned\u2029second line", unsafe},
		{"bidi override", "owned\u202eevil", unsafe},
		{"zero width space", "owned\u200bb", unsafe},
		{"escape sequence", "owned\x1b[2J", unsafe},
		{"invalid UTF-8", "owned\xff", unsafe},
		{"4801 bytes of spaces around a word", strings.Repeat(" ", maxReasonBytes) + "x", "is longer than 4800 bytes"},
		{"ogham space mark", "owned\u1680b", unsafe},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckReason(tt.text)
			if err == nil {
				t.Fatalf("CheckReason accepted %q", tt.text)
			}
			if !strings.Contains(err.Error(), tt.rule) {
				t.Errorf("error = %q, want it to name the rule %q", err, tt.rule)
			}
			assertRepeatsNoValue(t, err)
			if strings.Contains(err.Error(), "éé") {
				t.Errorf("the error repeats the reason's text: %q", err)
			}
		})
	}
}

func TestCheckReasonAcceptsFrenchSpaces(t *testing.T) {
	for _, text := range []string{
		"Mise à jour\u00a0: rien ne casse",
		"Mise à jour\u202f: rien ne casse",
		"東京\u3000リアクト",
		strings.Repeat(" ", maxReasonBytes-1) + "x",
	} {
		if err := CheckReason(text); err != nil {
			t.Errorf("CheckReason(%q): %v", text[:min(len(text), 40)], err)
		}
	}
}

func TestCheckReasonAcceptsAtTheBound(t *testing.T) {
	name := "東京リアクト"
	text := name + " needs React 19: " + strings.Repeat("é", MaxReasonRunes-utf8.RuneCountInString(name)-len(" needs React 19: "))
	if n := utf8.RuneCountInString(text); n != MaxReasonRunes {
		t.Fatalf("the test text holds %d runes, want %d", n, MaxReasonRunes)
	}
	for _, s := range []string{text, "  " + text + "  ", "x"} {
		if err := CheckReason(s); err != nil {
			t.Errorf("CheckReason(%d runes): %v", utf8.RuneCountInString(s), err)
		}
	}
}

// TestCheckReviewReadsAsTheImportDoes holds the writer's check to the
// import's reader: each review it refuses, the import keeps out with the same
// problem, and each one it accepts, the import reads back whole.
func TestCheckReviewReadsAsTheImportDoes(t *testing.T) {
	fixedIn := strings.TrimSuffix(strings.Repeat("4.17.3, ", 35), ", ")
	if len(fixedIn) <= maxTextBytes {
		t.Fatalf("the fixing versions hold %d bytes, want more than %d", len(fixedIn), maxTextBytes)
	}
	tests := []struct {
		name, value, problem string
		edit                 func(r *Review)
	}{
		{"a valid review", "", "", func(*Review) {}},
		{"a long list of fixing versions", fixedIn, "review.left[1].fixedIn is longer than 256 bytes", func(r *Review) { r.Left[1].FixedIn = fixedIn }},
		{"a lowercase severity", "high", "review.left[0].severity is not one of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN", func(r *Review) { r.Left[0].Severity = "high" }},
		{"a range for a version", "^5.0.0-owned", "review.updates[0].to is not an exact version", func(r *Review) { r.Updates[0].To = "^5.0.0-owned" }},
		{"an invalid name", "../owned", "review.kept[0].name is not a valid package name", func(r *Review) { r.Kept[0].Name = "../owned" }},
		{"a reason over two lines", "owned\u2028second line", "review.jumps[0].reason holds a control, line-separating, bidirectional or format character", func(r *Review) { r.Jumps[0].Reason = "owned\u2028second line" }},
		{"a jump without packages", "", "review.jumps[1].packages is empty", func(r *Review) { r.Jumps[1].Packages = nil }},
		{"a negative count", "", "review.updates[0].fixed holds a negative count", func(r *Review) { r.Updates[0].Fixed[2] = -1 }},
		{"a negative unchanged count", "", "review.unchanged is negative", func(r *Review) { r.Unchanged = -1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := wantReview("express", "4.17.1", "5.1.0")
			tt.edit(r)
			err := CheckReview(*r, NPM)
			doc := manifestDoc()
			doc["review"] = r
			m, perr := ParseManifest(encode(t, doc))
			if perr != nil {
				t.Fatalf("ParseManifest: %v", perr)
			}
			if tt.problem == "" {
				if err != nil {
					t.Errorf("CheckReview refused a review the import reads: %v", err)
				}
				if m.ReviewProblem != "" || !reflect.DeepEqual(m.Review, r) {
					t.Errorf("the import read %+v, %q, want %+v", m.Review, m.ReviewProblem, r)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckReview accepted a review the import keeps out with %q", m.ReviewProblem)
			}
			if err.Error() != tt.problem || m.ReviewProblem != tt.problem {
				t.Errorf("CheckReview = %q, the import's problem = %q, want both %q", err, m.ReviewProblem, tt.problem)
			}
			assertRepeatsNoValue(t, err)
			if tt.value != "" && strings.Contains(err.Error(), tt.value) {
				t.Errorf("CheckReview repeats the value: %q", err)
			}
		})
	}
}

func TestCheckReviewReadsNamesByTheEcosystem(t *testing.T) {
	r := *wantReview("@types/node", "20.1.0", "22.0.0")
	if err := CheckReview(r, NPM); err != nil {
		t.Errorf("CheckReview(npm) refused a scoped npm name: %v", err)
	}
	const problem = "review.updates[0].name is not a valid package name"
	if err := CheckReview(r, Pip); err == nil || err.Error() != problem {
		t.Errorf("CheckReview(pip) = %v, want %q", err, problem)
	}
	doc := pipManifestDoc()
	doc["review"] = r
	if m, err := ParsePipManifest(encode(t, doc)); err != nil || m.ReviewProblem != problem {
		t.Errorf("the pip import read %q, %v, want %q", m.ReviewProblem, err, problem)
	}
	if err := CheckReview(*wantReview("jinja2", "3.1.4", "3.1.6"), Pip); err != nil {
		t.Errorf("CheckReview(pip) refused a pip review: %v", err)
	}
	if err := CheckReview(r, Ecosystem("cargo")); err == nil {
		t.Error("CheckReview accepted an ecosystem it has no rules for")
	}
}

// reviewDoc returns a valid review as a generic document a case can edit. It
// names one dependency, moved from one exact version to another.
func reviewDoc(name, from, to string) map[string]any {
	return map[string]any{
		"cves": map[string]any{"before": []any{1, 2, 3, 0, 1}, "after": []any{0, 1, 2, 0, 1}},
		"updates": []any{
			map[string]any{"name": name, "from": from, "to": to, "fixed": []any{1, 1, 1, 0, 0}, "left": []any{0, 1, 2, 0, 1}},
		},
		"kept": []any{
			map[string]any{"name": name, "version": from, "jump": to},
		},
		"jumps": []any{
			map[string]any{
				"family":   "react 19",
				"packages": []any{map[string]any{"name": name, "from": from, "to": to}},
				"reason":   "The team moved to the next line on 2026-11-20, tests pass.",
			},
			map[string]any{
				"packages": []any{map[string]any{"name": name, "from": from, "to": to}},
				"reason":   "東京 needs this line; é and ü are fine.",
			},
		},
		"left": []any{
			map[string]any{
				"dependency": name, "version": to, "id": "CVE-2024-0001", "severity": "HIGH",
				"package": name, "fixedIn": "", "reason": "No release fixes it; the route is disabled.",
			},
			map[string]any{
				"dependency": name, "version": to, "id": "GHSA-abcd-efgh-ijkl", "severity": "LOW",
				"package": name, "fixedIn": "4.17.3, 5.0.0",
			},
		},
		"unchanged":   4,
		"futureField": true,
	}
}

// wantReview is what the reader makes of reviewDoc.
func wantReview(name, from, to string) *Review {
	after := [5]int{0, 1, 2, 0, 1}
	return &Review{
		CVEs:    ReviewCVEs{Before: [5]int{1, 2, 3, 0, 1}, After: &after},
		Updates: []ReviewUpdate{{Name: name, From: from, To: to, Fixed: [5]int{1, 1, 1, 0, 0}, Left: [5]int{0, 1, 2, 0, 1}}},
		Kept:    []ReviewKept{{Name: name, Version: from, Jump: to}},
		Jumps: []ReviewJump{
			{Family: "react 19", Packages: []ReviewMove{{Name: name, From: from, To: to}}, Reason: "The team moved to the next line on 2026-11-20, tests pass."},
			{Packages: []ReviewMove{{Name: name, From: from, To: to}}, Reason: "東京 needs this line; é and ü are fine."},
		},
		Left: []ReviewCVE{
			{Dependency: name, Version: to, ID: "CVE-2024-0001", Severity: "HIGH", Package: name, Reason: "No release fixes it; the route is disabled."},
			{Dependency: name, Version: to, ID: "GHSA-abcd-efgh-ijkl", Severity: "LOW", Package: name, FixedIn: "4.17.3, 5.0.0"},
		},
		Unchanged: 4,
	}
}

func reviewOf(doc map[string]any) map[string]any { return doc["review"].(map[string]any) }

func entryOf(review map[string]any, list string, i int) map[string]any {
	return review[list].([]any)[i].(map[string]any)
}

func TestParseManifestReadsTheReviewExample(t *testing.T) {
	page, err := os.ReadFile("../docs/dev/archive-format.md")
	if err != nil {
		t.Fatal(err)
	}
	const heading = "## The review\n"
	_, section, ok := strings.Cut(string(page), heading)
	if !ok {
		t.Fatalf("the format page has no %q section", heading)
	}
	_, block, ok := strings.Cut(section, "```json\n")
	example, _, closed := strings.Cut(block, "\n```")
	if !ok || !closed {
		t.Fatal("the review section holds no JSON example")
	}
	doc := manifestDoc()
	doc["review"] = json.RawMessage(example)
	m, err := ParseManifest(encode(t, doc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.ReviewProblem != "" || m.Review == nil {
		t.Fatalf("Review = %+v, ReviewProblem = %q", m.Review, m.ReviewProblem)
	}
	if len(m.Review.Jumps) != 1 || len(m.Review.Jumps[0].Packages) != 2 || len(m.Review.Left) != 2 || m.Review.Unchanged != 12 {
		t.Errorf("Review = %+v", m.Review)
	}
}

// parseBoth reads review through an npm and a pip manifest, named by
// ecosystem, with names valid in both.
func parseBoth(t *testing.T, review map[string]any) map[string]struct {
	review  *Review
	problem string
} {
	t.Helper()
	npmDoc, pipDoc := manifestDoc(), pipManifestDoc()
	npmDoc["review"], pipDoc["review"] = review, review
	m, err := ParseManifest(encode(t, npmDoc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	p, err := ParsePipManifest(encode(t, pipDoc))
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	return map[string]struct {
		review  *Review
		problem string
	}{"npm": {m.Review, m.ReviewProblem}, "pip": {p.Review, p.ReviewProblem}}
}

func TestReadsTheProjectAReviewCarries(t *testing.T) {
	for name, project := range map[string]string{
		"a plain name":            "pdf-renderer",
		"a scoped npm name":       "@acme/pdf-renderer",
		"100 characters":          strings.Repeat("p", 100),
		"spaces around 100":       "  " + strings.Repeat("p", 100) + "  ",
		"214 bytes":               strings.Repeat("東", 71) + "a",
		"a name with a no-break":  "Rendu\u00a0PDF",
		"letters of other script": "東京リアクト",
		"spaces around a name":    "  pdf-renderer  ",
	} {
		t.Run(name, func(t *testing.T) {
			doc := reviewDoc("jinja2", "3.1.4", "3.1.6")
			doc["project"] = project
			want := wantReview("jinja2", "3.1.4", "3.1.6")
			want.Project = strings.TrimSpace(project)
			for eco, got := range parseBoth(t, doc) {
				if got.problem != "" || !reflect.DeepEqual(got.review, want) {
					t.Errorf("%s: read %+v, %q, want the project %q", eco, got.review, got.problem, want.Project)
				}
			}
			if err := CheckReview(*want, NPM); err != nil {
				t.Errorf("CheckReview refused a review with a project: %v", err)
			}
		})
	}
}

// yankedDoc is a pip review that carries two yanked releases, one with the
// index's reason and one without.
func yankedDoc() map[string]any {
	review := reviewDoc("jinja2", "3.1.4", "3.1.6")
	review["yanked"] = []any{
		map[string]any{"dependency": "redis", "version": "5.0.8", "indexReason": "broken connection pool", "reason": "The pool is unused; 5.0.9 drops Python 3.11."},
		map[string]any{"dependency": "urllib3", "version": "2.2.0", "reason": "Pinned by the vendor until 2027."},
	}
	doc := pipManifestDoc()
	doc["review"] = review
	return doc
}

var wantYanked = []ReviewYanked{
	{Dependency: "redis", Version: "5.0.8", IndexReason: "broken connection pool", Reason: "The pool is unused; 5.0.9 drops Python 3.11."},
	{Dependency: "urllib3", Version: "2.2.0", Reason: "Pinned by the vendor until 2027."},
}

func TestReadReviewKeepsYankedReleases(t *testing.T) {
	m, err := ParsePipManifest(encode(t, yankedDoc()))
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	if m.Review == nil {
		t.Fatalf("the review was kept out: %s", m.ReviewProblem)
	}
	if !reflect.DeepEqual(m.Review.Yanked, wantYanked) {
		t.Errorf("yanked = %+v, want %+v", m.Review.Yanked, wantYanked)
	}
	if err := CheckReview(*m.Review, Pip); err != nil {
		t.Errorf("CheckReview refused the review the import kept: %v", err)
	}
}

func TestAnUnreadableYankedListKeepsTheReviewOut(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(review map[string]any)
		problem string
	}{
		{"a list of the wrong type", func(r map[string]any) { r["yanked"] = "owned" }, "review.yanked has the wrong type"},
		{"a bad pip name", func(r map[string]any) { entryOf(r, "yanked", 0)["dependency"] = "../owned" }, "review.yanked[0].dependency is not a valid package name"},
		{"no name", func(r map[string]any) { delete(entryOf(r, "yanked", 1), "dependency") }, "review.yanked[1].dependency is missing"},
		{"an inexact version", func(r map[string]any) { entryOf(r, "yanked", 1)["version"] = ">=5.0-owned" }, "review.yanked[1].version is not an exact version"},
		{"a reason with a line separator", func(r map[string]any) { entryOf(r, "yanked", 0)["reason"] = "owned second line" },
			"review.yanked[0].reason holds a control, line-separating, bidirectional or format character"},
		{"no reason", func(r map[string]any) { delete(entryOf(r, "yanked", 1), "reason") }, "review.yanked[1].reason is empty"},
		{"an index reason of 201 characters", func(r map[string]any) { entryOf(r, "yanked", 0)["indexReason"] = "owned" + strings.Repeat("a", 196) },
			"review.yanked[0].indexReason is longer than 200 characters"},
		{"an index reason with a control character", func(r map[string]any) { entryOf(r, "yanked", 0)["indexReason"] = "owned\x1b[31m" },
			"review.yanked[0].indexReason holds a control, line-separating, bidirectional or format character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := yankedDoc()
			tt.edit(reviewOf(doc))
			m, err := ParsePipManifest(encode(t, doc))
			if err != nil {
				t.Fatalf("ParsePipManifest refused the manifest: %v", err)
			}
			if m.Review != nil || m.ReviewProblem != tt.problem {
				t.Errorf("review = %+v, problem = %q, want it kept out with %q", m.Review, m.ReviewProblem, tt.problem)
			}
			if strings.Contains(m.ReviewProblem, "owned") {
				t.Errorf("problem %q repeats the value", m.ReviewProblem)
			}
		})
	}
}

func TestReadsAReviewWithNoProject(t *testing.T) {
	for eco, got := range parseBoth(t, reviewDoc("jinja2", "3.1.4", "3.1.6")) {
		if got.problem != "" || got.review == nil || got.review.Project != "" {
			t.Fatalf("%s: read %+v, %q, want a review with no project", eco, got.review, got.problem)
		}
		if !reflect.DeepEqual(got.review, wantReview("jinja2", "3.1.4", "3.1.6")) {
			t.Errorf("%s: read %+v", eco, got.review)
		}
	}
	data, err := json.Marshal(*wantReview("jinja2", "3.1.4", "3.1.6"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"project"`) {
		t.Errorf("a review with no project writes the key: %s", data)
	}
}

func TestDropsAnUnreadableProjectAndKeepsTheReview(t *testing.T) {
	for name, project := range map[string]any{
		"a bidirectional override, 215 bytes": "pdf\u202e" + strings.Repeat("r", 215-len("pdf\u202e")),
		"a bidirectional override":            "pdf\u202erenderer",
		"215 bytes":                           strings.Repeat("東", 71) + "ab",
		"101 characters":                      strings.Repeat("p", 101),
		"a newline":                           "pdf\nrenderer",
		"a line separator":                    "pdf\u2028renderer",
		"an escape sequence":                  "pdf\x1b[2Jrenderer",
		"empty":                               "",
		"spaces only":                         "   ",
		"a number":                            42,
		"an object":                           map[string]any{"name": "pdf-renderer"},
		"null":                                nil,
	} {
		t.Run(name, func(t *testing.T) {
			if s, ok := project.(string); ok && name == "a bidirectional override, 215 bytes" && len(s) != 215 {
				t.Fatalf("the test name holds %d bytes, want 215", len(s))
			}
			doc := reviewDoc("jinja2", "3.1.4", "3.1.6")
			doc["project"] = project
			for eco, got := range parseBoth(t, doc) {
				if got.problem != "" || !reflect.DeepEqual(got.review, wantReview("jinja2", "3.1.4", "3.1.6")) {
					t.Errorf("%s: read %+v, %q, want the whole review with no project", eco, got.review, got.problem)
				}
			}
			if s, ok := project.(string); ok {
				r := wantReview("jinja2", "3.1.4", "3.1.6")
				r.Project = s
				if err := CheckReview(*r, NPM); err != nil {
					t.Errorf("CheckReview refused the review over its project: %v", err)
				}
			}
		})
	}
}

// The list's bound holds within the manifest's own cap, and the reader
// stops on it in bounded time.
func TestAYankedListPastTheBoundKeepsTheReviewOut(t *testing.T) {
	doc := yankedDoc()
	review := reviewOf(doc)
	review["yanked"] = repeated(map[string]any{"dependency": "a", "version": "1", "reason": "r"}, maxReviewEntries+1)
	data := encode(t, doc)
	if len(data) > MaxManifestSize {
		t.Fatalf("the manifest holds %d bytes, past the cap of %d", len(data), MaxManifestSize)
	}
	start := time.Now()
	m, err := ParsePipManifest(data)
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("reading 100,001 yanked releases took %v, want under 10s", took)
	}
	if err != nil {
		t.Fatalf("ParsePipManifest refused the manifest: %v", err)
	}
	if want := "review.yanked holds more than 100000 entries"; m.Review != nil || m.ReviewProblem != want {
		t.Errorf("review kept = %v, problem = %q, want it kept out with %q", m.Review != nil, m.ReviewProblem, want)
	}
}

// A review with no yanked release, npm's included, keeps the bytes it had
// before the list existed.
func TestAReviewWithoutYankedKeepsItsBytes(t *testing.T) {
	for _, r := range []*Review{wantReview("express", "4.17.1", "5.1.0"), {Yanked: []ReviewYanked{}}} {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"yanked"`) {
			t.Errorf("review = %s, holds a yanked key", data)
		}
	}
	data, err := json.Marshal(wantReview("express", "4.17.1", "5.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"cves":{"before":[1,2,3,0,1],"after":[0,1,2,0,1]},"updates":[{"name":"express","from":"4.17.1","to":"5.1.0","fixed":[1,1,1,0,0],"left":[0,1,2,0,1]}],"kept":[{"name":"express","version":"4.17.1","jump":"5.1.0"}],"jumps":[{"family":"react 19","packages":[{"name":"express","from":"4.17.1","to":"5.1.0"}],"reason":"The team moved to the next line on 2026-11-20, tests pass."},{"packages":[{"name":"express","from":"4.17.1","to":"5.1.0"}],"reason":"東京 needs this line; é and ü are fine."}],"left":[{"dependency":"express","version":"5.1.0","id":"CVE-2024-0001","severity":"HIGH","package":"express","fixedIn":"","reason":"No release fixes it; the route is disabled."},{"dependency":"express","version":"5.1.0","id":"GHSA-abcd-efgh-ijkl","severity":"LOW","package":"express","fixedIn":"4.17.3, 5.0.0"}],"unchanged":4}`
	if string(data) != want {
		t.Errorf("review = %s\nwant      %s", data, want)
	}
}

func TestCheckReviewReadsTheYankedList(t *testing.T) {
	base := func() Review {
		r := *wantReview("jinja2", "3.1.4", "3.1.6")
		r.Yanked = slices.Clone(wantYanked)
		return r
	}
	if err := CheckReview(base(), Pip); err != nil {
		t.Fatalf("CheckReview refused a review with yanked releases: %v", err)
	}
	tests := []struct {
		name, problem string
		edit          func(r *Review)
	}{
		{"a bad pip name", "review.yanked[0].dependency is not a valid package name", func(r *Review) { r.Yanked[0].Dependency = "../owned" }},
		{"an inexact version", "review.yanked[1].version is not an exact version", func(r *Review) { r.Yanked[1].Version = "^2.2.0-owned" }},
		{"an empty reason", "review.yanked[1].reason is empty", func(r *Review) { r.Yanked[1].Reason = " " }},
		{"an index reason over two lines", "review.yanked[0].indexReason holds a control, line-separating, bidirectional or format character",
			func(r *Review) { r.Yanked[0].IndexReason = "owned second line" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base()
			tt.edit(&r)
			err := CheckReview(r, Pip)
			if err == nil || err.Error() != tt.problem {
				t.Errorf("CheckReview = %v, want %q", err, tt.problem)
			}
			assertRepeatsNoValue(t, err)
		})
	}
}
