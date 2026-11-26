package jobs

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzAdvisoryText(f *testing.F) {
	for _, seed := range []string{
		axiosCredentialLeak, axiosDataURI,
		"### Impact\n\nThe parser.", "\u2060\n\nReal text.", "\x1b\n\nReal text.",
		"https:\u2060//user:secret@host.example/x", "https:/\u200B/user:secret@host.example/x",
		"https://user@host.example/x", "\xff\xfe broken", "\u202Eevil",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, c := range []struct {
			name  string
			got   string
			limit int
		}{
			{"title", advisoryTitle("", s), advisoryTitleLimit},
			{"summary", advisorySummary("", s), advisorySummaryLimit},
		} {
			if !utf8.ValidString(c.got) {
				t.Fatalf("%s %q is not valid UTF-8", c.name, c.got)
			}
			if n := utf8.RuneCountInString(c.got); n > c.limit {
				t.Fatalf("%s holds %d code points, want at most %d", c.name, n, c.limit)
			}
			if i := strings.IndexFunc(c.got, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }); i >= 0 {
				t.Fatalf("%s %q holds a control or format character at %d", c.name, c.got, i)
			}
			if strings.Contains(c.got, "://user@") {
				t.Fatalf("%s %q keeps a URL's user", c.name, c.got)
			}
		}
	})
}
