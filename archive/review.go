package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/pip"
)

// MaxReasonRunes is the longest reason, in characters once trimmed.
const MaxReasonRunes = 300

// maxReviewEntries bounds each list of a review: 100,000 entries.
const maxReviewEntries = 100_000

// Review is what an export decided and why, signed with its manifest under
// the key review. Count vectors hold critical, high, medium, low and unknown,
// in that order.
type Review struct {
	CVEs      ReviewCVEs     `json:"cves"`
	Updates   []ReviewUpdate `json:"updates"`
	Kept      []ReviewKept   `json:"kept"`
	Jumps     []ReviewJump   `json:"jumps"`
	Left      []ReviewCVE    `json:"left"`
	Unchanged int            `json:"unchanged"`
}

// ReviewCVEs counts the project's CVEs before the selection and once it
// applies; After is nil when the project scan could not be read.
type ReviewCVEs struct {
	Before [5]int  `json:"before"`
	After  *[5]int `json:"after,omitempty"`
}

// ReviewUpdate is a dependency the selection moves within its line, with the
// CVEs the move fixes and those it leaves.
type ReviewUpdate struct {
	Name  string `json:"name"`
	From  string `json:"from"`
	To    string `json:"to"`
	Fixed [5]int `json:"fixed"`
	Left  [5]int `json:"left"`
}

// ReviewKept is a dependency kept on its line, with the version outside the
// line it could take.
type ReviewKept struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Jump    string `json:"jump"`
}

// ReviewJump is a family, or a lone dependency, the selection takes out of
// its line, with the reason given for it.
type ReviewJump struct {
	Family   string       `json:"family,omitempty"`
	Packages []ReviewMove `json:"packages"`
	Reason   string       `json:"reason"`
}

// ReviewMove is one dependency of a jump.
type ReviewMove struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// ReviewCVE is a CVE the project keeps, with the versions that fix it or the
// reason given when none does.
type ReviewCVE struct {
	Dependency string `json:"dependency"`
	Version    string `json:"version"`
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Package    string `json:"package"`
	FixedIn    string `json:"fixedIn"`
	Reason     string `json:"reason,omitempty"`
}

// CheckReason is the one rule a reason's text follows, at export and at
// import: 1 to MaxReasonRunes characters once trimmed, printable characters
// only. The error repeats none of the text.
func CheckReason(text string) error {
	if rule := reasonRule(text); rule != "" {
		return errors.New("the reason " + rule)
	}
	return nil
}

// reasonRule names the rule text breaks, or returns "". Line and paragraph
// separators, bidirectional and other format characters are not printable,
// so a reason printed into a table or a terminal stays one plain line.
func reasonRule(text string) string {
	if !utf8.ValidString(text) || strings.IndexFunc(text, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return "holds a control, line-separating, bidirectional or format character"
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "is empty"
	}
	if utf8.RuneCountInString(trimmed) > MaxReasonRunes {
		return fmt.Sprintf("is longer than %d characters", MaxReasonRunes)
	}
	return ""
}

// nameRules reads names and versions as a manifest of one ecosystem does.
type nameRules struct {
	name, version func(string) bool
}

var (
	npmNames = nameRules{name: npm.ValidName, version: npm.IsExactVersion}
	pipNames = nameRules{name: pip.ValidName, version: pip.IsExactVersion}
)

var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// rawReview keeps a missing vector apart from a zero one, and a vector of
// the wrong length apart from a short one Go would pad with zeros.
type rawReview struct {
	CVEs *struct {
		Before []int `json:"before"`
		After  []int `json:"after"`
	} `json:"cves"`
	Updates []struct {
		Name  string `json:"name"`
		From  string `json:"from"`
		To    string `json:"to"`
		Fixed []int  `json:"fixed"`
		Left  []int  `json:"left"`
	} `json:"updates"`
	Kept  []ReviewKept `json:"kept"`
	Jumps []ReviewJump `json:"jumps"`
	Left  []ReviewCVE  `json:"left"`
	// Unchanged is a pointer so a negative count is told apart from none.
	Unchanged *int `json:"unchanged"`
}

// readReview reads the review a manifest carries. An absent or null review
// is not carried: nil and "". A review that does not decode or check is kept
// out: nil and the problem, which names the field and repeats no value. It
// never refuses the manifest.
func readReview(data json.RawMessage, rules nameRules) (*Review, string) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil, ""
	}
	if data[0] != '{' {
		return nil, "review is not an object"
	}
	var raw rawReview
	if err := json.Unmarshal(data, &raw); err != nil {
		var typ *json.UnmarshalTypeError
		if errors.As(err, &typ) && typ.Field != "" {
			return nil, fmt.Sprintf("review.%s has the wrong type", typ.Field)
		}
		return nil, "review is unreadable"
	}
	r, problem := checkReview(raw, rules)
	if problem != "" {
		return nil, problem
	}
	return r, ""
}

func checkReview(raw rawReview, rules nameRules) (*Review, string) {
	for _, l := range []struct {
		name string
		n    int
	}{{"updates", len(raw.Updates)}, {"kept", len(raw.Kept)}, {"jumps", len(raw.Jumps)}, {"left", len(raw.Left)}} {
		if l.n > maxReviewEntries {
			return nil, fmt.Sprintf("review.%s holds more than %d entries", l.name, maxReviewEntries)
		}
	}
	r := &Review{}
	if raw.CVEs == nil || raw.CVEs.Before == nil {
		return nil, "review.cves.before is missing"
	}
	var problem string
	if r.CVEs.Before, problem = vector("review.cves.before", raw.CVEs.Before); problem != "" {
		return nil, problem
	}
	if raw.CVEs.After != nil {
		after, problem := vector("review.cves.after", raw.CVEs.After)
		if problem != "" {
			return nil, problem
		}
		r.CVEs.After = &after
	}
	if raw.Unchanged != nil {
		if *raw.Unchanged < 0 {
			return nil, "review.unchanged is negative"
		}
		r.Unchanged = *raw.Unchanged
	}
	if raw.Updates != nil {
		r.Updates = make([]ReviewUpdate, len(raw.Updates))
	}
	for i, u := range raw.Updates {
		at := fmt.Sprintf("review.updates[%d]", i)
		if problem := rules.move(at, ReviewMove{Name: u.Name, From: u.From, To: u.To}); problem != "" {
			return nil, problem
		}
		fixed, problem := vector(at+".fixed", u.Fixed)
		if problem != "" {
			return nil, problem
		}
		left, problem := vector(at+".left", u.Left)
		if problem != "" {
			return nil, problem
		}
		r.Updates[i] = ReviewUpdate{Name: u.Name, From: u.From, To: u.To, Fixed: fixed, Left: left}
	}
	for i, k := range raw.Kept {
		at := fmt.Sprintf("review.kept[%d]", i)
		problem := firstProblem(rules.packageName(at+".name", k.Name), rules.exactVersion(at+".version", k.Version))
		if problem == "" && k.Jump != "" {
			problem = rules.exactVersion(at+".jump", k.Jump)
		}
		if problem != "" {
			return nil, problem
		}
	}
	r.Kept = raw.Kept
	for i, j := range raw.Jumps {
		if problem := rules.jump(fmt.Sprintf("review.jumps[%d]", i), j); problem != "" {
			return nil, problem
		}
	}
	r.Jumps = raw.Jumps
	for i, c := range raw.Left {
		if problem := rules.cve(fmt.Sprintf("review.left[%d]", i), c); problem != "" {
			return nil, problem
		}
	}
	r.Left = raw.Left
	return r, ""
}

func (rules nameRules) jump(at string, j ReviewJump) string {
	if j.Family != "" {
		if err := checkText(at+".family", j.Family); err != nil {
			return err.Error()
		}
	}
	if len(j.Packages) == 0 {
		return at + ".packages is empty"
	}
	if len(j.Packages) > maxReviewEntries {
		return fmt.Sprintf("%s.packages holds more than %d entries", at, maxReviewEntries)
	}
	for i, m := range j.Packages {
		if problem := rules.move(fmt.Sprintf("%s.packages[%d]", at, i), m); problem != "" {
			return problem
		}
	}
	if rule := reasonRule(j.Reason); rule != "" {
		return at + ".reason " + rule
	}
	return ""
}

func (rules nameRules) cve(at string, c ReviewCVE) string {
	problem := firstProblem(rules.packageName(at+".dependency", c.Dependency), rules.exactVersion(at+".version", c.Version))
	if problem != "" {
		return problem
	}
	if c.ID == "" {
		return at + ".id is missing"
	}
	if err := checkText(at+".id", c.ID); err != nil {
		return err.Error()
	}
	if !slices.Contains(severities, c.Severity) {
		return at + ".severity is not one of " + strings.Join(severities, ", ")
	}
	// A CVE recorded before the package was kept with it has none.
	if c.Package != "" {
		if problem := rules.packageName(at+".package", c.Package); problem != "" {
			return problem
		}
	}
	if err := checkText(at+".fixedIn", c.FixedIn); err != nil {
		return err.Error()
	}
	if c.Reason != "" {
		if rule := reasonRule(c.Reason); rule != "" {
			return at + ".reason " + rule
		}
	}
	return ""
}

func (rules nameRules) move(at string, m ReviewMove) string {
	return firstProblem(
		rules.packageName(at+".name", m.Name),
		rules.exactVersion(at+".from", m.From),
		rules.exactVersion(at+".to", m.To),
	)
}

func (rules nameRules) packageName(field, value string) string {
	switch {
	case value == "":
		return field + " is missing"
	case len(value) > maxTextBytes:
		return fmt.Sprintf("%s is longer than %d bytes", field, maxTextBytes)
	case !rules.name(value):
		return field + " is not a valid package name"
	}
	return ""
}

func (rules nameRules) exactVersion(field, value string) string {
	switch {
	case value == "":
		return field + " is missing"
	case len(value) > maxVersionBytes:
		return fmt.Sprintf("%s is longer than %d bytes", field, maxVersionBytes)
	case !rules.version(value):
		return field + " is not an exact version"
	}
	return ""
}

func vector(field string, counts []int) ([5]int, string) {
	var v [5]int
	if len(counts) != len(v) {
		return v, field + " does not hold 5 counts"
	}
	for i, n := range counts {
		if n < 0 {
			return v, field + " holds a negative count"
		}
		v[i] = n
	}
	return v, ""
}

func firstProblem(problems ...string) string {
	for _, p := range problems {
		if p != "" {
			return p
		}
	}
	return ""
}
