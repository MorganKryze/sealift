package jobs

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/rank"
)

// Real Trivy 0.76.2 descriptions for axios, as the database words them.
const (
	axiosCredentialLeak = "axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if \u2060baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2."
	axiosDataURI        = "Axios is a promise based HTTP client for the browser and Node.js. When Axios starting in version 0.28.0 and prior to versions 0.30.2 and 1.12.0 runs on Node.js and is given a URL with the `data:` scheme, it does not perform HTTP. Instead, its Node http adapter decodes the entire payload into memory (`Buffer`/`Blob`) and returns a synthetic 200 response. This path ignores `maxContentLength` / `maxBodyLength` (which only protect HTTP responses), so an attacker can supply a very large `data:` URI and cause the process to allocate unbounded memory and crash (DoS), even if the caller requested `responseType: 'stream'`. Versions 0.30.2 and 1.12.0 contain a patch for the issue."
)

func TestAdvisoryTitleCutsAtAWordPastTwoHundred(t *testing.T) {
	title := strings.TrimSpace(strings.Repeat("dépassement ", 22)) + " fin"
	if n := utf8.RuneCountInString(title); n != 267 {
		t.Fatalf("the input holds %d code points, want 267", n)
	}
	want := strings.TrimSpace(strings.Repeat("dépassement ", 16)) + "..."
	got := advisoryTitle("", title)
	if got != want {
		t.Errorf("advisoryTitle = %q, want %q", got, want)
	}
	if n := utf8.RuneCountInString(got); n > advisoryTitleLimit {
		t.Errorf("title holds %d code points, want at most %d", n, advisoryTitleLimit)
	}
	if short := "axios: Axios DoS via lack of data size check"; advisoryTitle("", short) != short {
		t.Errorf("a short title must stay whole, got %q", advisoryTitle("", short))
	}
}

func TestAdvisorySummaryKeepsAShortDescriptionWhole(t *testing.T) {
	want := strings.Replace(axiosCredentialLeak, "\u2060", "", 1)
	if got := advisorySummary("", axiosCredentialLeak); got != want {
		t.Errorf("advisorySummary = %q, want %q", got, want)
	}
	// Wrapped and indented, the paragraph holds more than 500 code points
	// until its whitespace folds.
	wrapped := strings.ReplaceAll(axiosCredentialLeak, " ", " \n  ")
	if n := utf8.RuneCountInString(wrapped); n <= advisorySummaryLimit {
		t.Fatalf("the wrapped input holds %d code points, want more than %d", n, advisorySummaryLimit)
	}
	if got := advisorySummary("", wrapped); got != want {
		t.Errorf("advisorySummary(wrapped) = %q, want %q", got, want)
	}
}

func TestAdvisorySummaryCutsAfterTheLastWholeSentence(t *testing.T) {
	if n := utf8.RuneCountInString(axiosDataURI); n != 679 {
		t.Fatalf("the input holds %d code points, want 679", n)
	}
	end := "returns a synthetic 200 response."
	want := axiosDataURI[:strings.Index(axiosDataURI, end)+len(end)]
	if got := advisorySummary("", axiosDataURI); got != want {
		t.Errorf("advisorySummary = %q, want %q", got, want)
	}
}

func TestAdvisorySummaryCutsAtAWordWhenNoSentenceEndFits(t *testing.T) {
	// The full stop before the 200th code point is the only sentence end:
	// a cut there would keep too little.
	description := "Short. " + strings.TrimSpace(strings.Repeat("overflow ", 57))
	if n := utf8.RuneCountInString(description); n != 519 {
		t.Fatalf("the input holds %d code points, want 519", n)
	}
	want := "Short. " + strings.TrimSpace(strings.Repeat("overflow ", 54)) + "..."
	got := advisorySummary("", description)
	if got != want {
		t.Errorf("advisorySummary = %q, want %q", got, want)
	}
	if n := utf8.RuneCountInString(got); n > advisorySummaryLimit {
		t.Errorf("summary holds %d code points, want at most %d", n, advisorySummaryLimit)
	}
}

func TestAdvisorySummarySkipsMarkdownHeadings(t *testing.T) {
	for _, description := range []string{
		"### Impact\n\nThe parser reads a\nwhole line.\n\n### Patches\n\nFixed in 2.0.",
		"### Impact\r\nThe parser reads a\r\nwhole line.\r\n### Patches\r\nFixed in 2.0.",
		"\n\n  # Impact\n\n\tThe parser reads a   whole line.\n\nFixed in 2.0.",
	} {
		if got := advisorySummary("", description); got != "The parser reads a whole line." {
			t.Errorf("advisorySummary(%q) = %q, want the first paragraph that is not a heading", description, got)
		}
	}
	if got := advisorySummary("", "#hashtag is not a heading"); got != "#hashtag is not a heading" {
		t.Errorf("a # without a space after it starts no heading, got %q", got)
	}
}

func TestAdvisoryTextDropsControlCredentialsAndDataPaths(t *testing.T) {
	root := t.TempDir()
	text := "\x1b[31mred\x1b[0m text \u202Eevil\u2060 fetched https://user:secret@registry.example/x into " +
		filepath.Join(root, "projects", "p", "x") + "\x00."
	want := "[31mred[0m text evil fetched https://registry.example/x into " + filepath.Join("projects", "p", "x") + "."
	if got := advisoryTitle(root, text); got != want {
		t.Errorf("advisoryTitle = %q, want %q", got, want)
	}
	if got := advisorySummary(root, text); got != want {
		t.Errorf("advisorySummary = %q, want %q", got, want)
	}
}

func TestAdvisoryTextKeepsMarkupAsPlainCharacters(t *testing.T) {
	text := "A title such as <img src=x onerror=alert(1)> runs `eval(input)`; see [link](https://example.org) & <script>."
	if got := advisoryTitle(t.TempDir(), text); got != text {
		t.Errorf("advisoryTitle = %q, want it as written", got)
	}
	if got := advisorySummary(t.TempDir(), text); got != text {
		t.Errorf("advisorySummary = %q, want it as written", got)
	}
}

func TestAdvisoryOfLeavesOutWhatTheReportDoesNotGive(t *testing.T) {
	published := time.Date(2026, 2, 9, 21, 15, 49, 10_000_000, time.UTC)
	paris := time.FixedZone("CET", 3600)
	for _, c := range []struct {
		name    string
		finding rank.Finding
		want    Advisory
		ok      bool
	}{
		{"title only", rank.Finding{ID: "CVE-1", Title: "a: one"}, Advisory{Title: "a: one"}, true},
		{"description only", rank.Finding{ID: "CVE-1", Description: "Does a thing."}, Advisory{Summary: "Does a thing."}, true},
		{"date only", rank.Finding{ID: "CVE-1", Published: published}, Advisory{Published: "2026-02-09T21:15:49Z"}, true},
		{"date in another zone", rank.Finding{ID: "CVE-1", Published: published.In(paris)}, Advisory{Published: "2026-02-09T21:15:49Z"}, true},
		{"none", rank.Finding{ID: "CVE-1"}, Advisory{}, false},
		{"text that cleans to nothing", rank.Finding{ID: "CVE-1", Title: "\x1b\u200B", Description: " \t\n"}, Advisory{}, false},
	} {
		got, ok := advisoryOf("", c.finding)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: advisoryOf = %+v, %v, want %+v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestAdvisorySummaryBoundsAOneMebibyteDescription(t *testing.T) {
	var b strings.Builder
	for b.Len() < 1<<20 {
		b.WriteString("flood ")
	}
	description := b.String()
	root := t.TempDir()

	got := advisorySummary(root, description)
	if n := utf8.RuneCountInString(got); n == 0 || n > advisorySummaryLimit {
		t.Errorf("summary holds %d code points, want between 1 and %d", n, advisorySummaryLimit)
	}
	// A step that copied the text once per word would allocate about
	// 175,000 times here.
	const allocBound = 100
	if allocs := testing.AllocsPerRun(3, func() { advisorySummary(root, description) }); allocs > allocBound {
		t.Errorf("advisorySummary allocates %.0f times on 1 MiB, want at most %d", allocs, allocBound)
	}
}
