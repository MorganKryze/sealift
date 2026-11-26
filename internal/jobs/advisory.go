package jobs

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/rank"
)

// Trivy's titles and descriptions come from a vulnerability database
// sealift downloads and does not control. Each one is cleaned and bounded
// here before it is stored, and stays plain text: markup is neither parsed
// nor stripped, since real advisories quote tags such as <script>.
const (
	advisoryTitleLimit    = 200 // code points
	advisorySummaryLimit  = 500 // code points
	advisorySentenceFloor = 200 // a cut at a sentence end keeps at least this many code points
)

// dropControl drops Unicode control (Cc) and format (Cf) characters. A
// control character that is whitespace becomes a space, so the words it
// parted stay apart.
func dropControl(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r) && unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
}

// advisoryText cleans s as a failure cause is cleaned, drops its control
// and format characters, and folds its whitespace to single spaces.
func advisoryText(root, s string) string {
	return strings.Join(strings.Fields(dropControl(causeText(root, s))), " ")
}

// advisoryTitle is Trivy's title, cleaned and cut at a word to
// advisoryTitleLimit code points.
func advisoryTitle(root, s string) string {
	return cutAtWord(advisoryText(root, s), advisoryTitleLimit)
}

// advisorySummary is the first paragraph of Trivy's description that is
// not a Markdown heading, cleaned, and cut after its last sentence end
// between advisorySentenceFloor and advisorySummaryLimit code points, or
// at a word when no sentence end falls there.
func advisorySummary(root, s string) string {
	text := advisoryText(root, firstParagraph(s))
	if _, long := runePrefix(text, advisorySummaryLimit); !long {
		return text
	}
	if end := sentenceEnd(text); end > 0 {
		return text[:end]
	}
	return cutAtWord(text, advisorySummaryLimit)
}

// sentenceEnd returns the byte offset just past the last full stop that a
// space follows and that ends between advisorySentenceFloor and
// advisorySummaryLimit code points, or 0 when none does. text must be
// longer than advisorySummaryLimit code points, so a space can follow
// the last full stop it looks at.
func sentenceEnd(text string) int {
	end, n := 0, 0
	for i, r := range text {
		n++
		if n > advisorySummaryLimit {
			break
		}
		if r == '.' && n >= advisorySentenceFloor && strings.HasPrefix(text[i+1:], " ") {
			end = i + 1
		}
	}
	return end
}

// cutAtWord cuts s, whose spaces are single, to at most limit code points:
// the words that fit, then "...". A first word longer than that is cut
// inside.
func cutAtWord(s string, limit int) string {
	if _, long := runePrefix(s, limit); !long {
		return s
	}
	head, _ := runePrefix(s, limit-len("..."))
	if s[len(head)] != ' ' {
		if i := strings.LastIndexByte(head, ' '); i > 0 {
			head = head[:i]
		}
	}
	return strings.TrimRight(head, " ") + "..."
}

// runePrefix returns the first n code points of s, and whether s holds
// more than that.
func runePrefix(s string, n int) (string, bool) {
	count := 0
	for i := range s {
		if count == n {
			return s[:i], true
		}
		count++
	}
	return s, false
}

// firstParagraph returns the first run of non-blank lines in s that is not
// a Markdown heading. A heading line also ends the paragraph before it.
func firstParagraph(s string) string {
	start := -1
	for off := 0; off <= len(s); {
		end := strings.IndexByte(s[off:], '\n')
		if end < 0 {
			end = len(s)
		} else {
			end += off
		}
		line := s[off:end]
		if strings.TrimSpace(line) == "" || isHeading(line) {
			if start >= 0 {
				return s[start:off]
			}
		} else if start < 0 {
			start = off
		}
		off = end + 1
	}
	if start < 0 {
		return ""
	}
	return s[start:]
}

// isHeading reports whether line is an ATX heading: at most three spaces,
// one to six "#", then whitespace or the line's end.
func isHeading(line string) bool {
	t := strings.TrimLeft(line, " ")
	if len(line)-len(t) > 3 {
		return false
	}
	n := len(t) - len(strings.TrimLeft(t, "#"))
	if n < 1 || n > 6 {
		return false
	}
	if n == len(t) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(t[n:])
	return unicode.IsSpace(r)
}

// advisoryOf is what f says its CVE does, cleaned and bounded, and false
// when the report gives no title, description or published date for it.
func advisoryOf(root string, f rank.Finding) (Advisory, bool) {
	a := Advisory{Title: advisoryTitle(root, f.Title), Summary: advisorySummary(root, f.Description)}
	if !f.Published.IsZero() {
		a.Published = f.Published.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	return a, a != Advisory{}
}

// addAdvisory adds f's advisory to table unless the table already holds
// one for its id: the first wording stays.
func addAdvisory(table map[string]Advisory, root string, f rank.Finding) {
	if _, ok := table[f.ID]; ok {
		return
	}
	if a, ok := advisoryOf(root, f); ok {
		table[f.ID] = a
	}
}
