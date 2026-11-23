package archive

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
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
