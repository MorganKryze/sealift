package pip

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MarkerHolds reports whether an environment marker is true for CPython
// p.Python on Linux p.CPU, as uv decides it with --python-version and
// --python-platform: platform_release and platform_version are empty there,
// and no extra is requested.
//
// A part it cannot decide the way uv does, such as an ordering of strings,
// a version with more than a release number, or ===, leaves the marker
// undecided unless the rest settles it, as a false part settles an and. An
// undecided or malformed marker is an error.
func MarkerHolds(marker string, p Platform) (bool, error) {
	if len(marker) > maxMarkerBytes {
		return false, fmt.Errorf("pip: marker is longer than %d bytes", maxMarkerBytes)
	}
	env, err := markerEnvOf(p)
	if err != nil {
		return false, err
	}
	toks, err := lexMarker(marker)
	if err != nil {
		return false, err
	}
	m := &markerParser{toks: toks, env: env}
	t, err := m.or()
	switch {
	case err != nil:
		return false, err
	case m.pos < len(toks):
		return false, fmt.Errorf("pip: marker has %q where and, or or the end is expected", toks[m.pos].text)
	case t == undecided:
		return false, fmt.Errorf("pip: cannot decide the marker part %s the way uv does", m.why)
	}
	return t == holds, nil
}

// markerEnv holds the value of every marker variable on one target.
type markerEnv struct {
	versions map[string][]int
	strings  map[string]string
}

func markerEnvOf(p Platform) (markerEnv, error) {
	full, ok := releaseOf(p.Python)
	switch {
	case !ok || len(full) != 3:
		return markerEnv{}, fmt.Errorf("pip: python %q is not a major.minor.patch version", p.Python)
	case p.OS != "linux":
		return markerEnv{}, fmt.Errorf("pip: os %q is not supported, only linux", p.OS)
	case p.CPU == "":
		return markerEnv{}, errors.New("pip: the target names no cpu")
	}
	return markerEnv{
		versions: map[string][]int{
			"python_version":         full[:2],
			"python_full_version":    full,
			"implementation_version": full,
		},
		strings: map[string]string{
			"os_name":                        "posix",
			"sys_platform":                   "linux",
			"platform_system":                "Linux",
			"platform_machine":               p.CPU,
			"platform_python_implementation": "CPython",
			"implementation_name":            "cpython",
			"platform_release":               "",
			"platform_version":               "",
		},
	}, nil
}

// legacyMarkerNames are the older spellings uv still reads.
var legacyMarkerNames = map[string]string{
	"os.name":                        "os_name",
	"sys.platform":                   "sys_platform",
	"platform.version":               "platform_version",
	"platform.machine":               "platform_machine",
	"platform.python_implementation": "platform_python_implementation",
	"python_implementation":          "platform_python_implementation",
}

type markerToken struct {
	kind byte // 'w' for a word, 's' for a quoted string, 'o' for an operator, '(' or ')'
	text string
}

func lexMarker(s string) ([]markerToken, error) {
	var toks []markerToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			toks = append(toks, markerToken{kind: c, text: string(c)})
			i++
		case c == '"' || c == '\'':
			end := strings.IndexByte(s[i+1:], c)
			if end < 0 {
				return nil, errors.New("pip: marker has a string that is not closed")
			}
			toks = append(toks, markerToken{kind: 's', text: s[i+1 : i+1+end]})
			i += end + 2
		case isOperatorByte(c):
			j := i
			for j < len(s) && isOperatorByte(s[j]) {
				j++
			}
			if !slices.Contains(operators, s[i:j]) {
				return nil, fmt.Errorf("pip: marker has %q, which is not an operator", s[i:j])
			}
			toks = append(toks, markerToken{kind: 'o', text: s[i:j]})
			i = j
		case isMarkerWordByte(c):
			j := i
			for j < len(s) && isMarkerWordByte(s[j]) {
				j++
			}
			toks = append(toks, markerToken{kind: 'w', text: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("pip: marker has %q, which no marker holds", c)
		}
	}
	return toks, nil
}

func isOperatorByte(c byte) bool { return strings.IndexByte("<>=!~", c) >= 0 }

func isMarkerWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}

// truth is a three-valued result: a part sealift cannot decide may still
// let the whole marker be decided.
type truth int8

const (
	undecided truth = iota
	fails
	holds
)

func truthOf(b bool) truth {
	if b {
		return holds
	}
	return fails
}

func both(a, b truth) truth {
	switch {
	case a == fails || b == fails:
		return fails
	case a == undecided || b == undecided:
		return undecided
	}
	return holds
}

func either(a, b truth) truth {
	switch {
	case a == holds || b == holds:
		return holds
	case a == undecided || b == undecided:
		return undecided
	}
	return fails
}

type markerParser struct {
	toks []markerToken
	pos  int
	env  markerEnv
	why  string // the first part left undecided
}

func (m *markerParser) at(kind byte, text string) bool {
	return m.pos < len(m.toks) && m.toks[m.pos].kind == kind && (text == "" || m.toks[m.pos].text == text)
}

func (m *markerParser) or() (truth, error) {
	t, err := m.and()
	for err == nil && m.at('w', "or") {
		m.pos++
		var u truth
		u, err = m.and()
		t = either(t, u)
	}
	return t, err
}

func (m *markerParser) and() (truth, error) {
	t, err := m.expr()
	for err == nil && m.at('w', "and") {
		m.pos++
		var u truth
		u, err = m.expr()
		t = both(t, u)
	}
	return t, err
}

func (m *markerParser) expr() (truth, error) {
	if m.at('(', "") {
		m.pos++
		t, err := m.or()
		if err != nil {
			return undecided, err
		}
		if !m.at(')', "") {
			return undecided, errors.New("pip: marker has a ( that is not closed")
		}
		m.pos++
		return t, nil
	}
	left, err := m.operand()
	if err != nil {
		return undecided, err
	}
	op, err := m.operator()
	if err != nil {
		return undecided, err
	}
	right, err := m.operand()
	if err != nil {
		return undecided, err
	}
	return m.compare(left, op, right)
}

// markerOperand is a variable or a quoted value.
type markerOperand struct{ variable, value string }

func (m *markerParser) operand() (markerOperand, error) {
	if m.pos >= len(m.toks) {
		return markerOperand{}, errors.New("pip: marker ends where a value is expected")
	}
	tok := m.toks[m.pos]
	m.pos++
	switch tok.kind {
	case 's':
		return markerOperand{value: tok.text}, nil
	case 'w':
		name := tok.text
		if modern, ok := legacyMarkerNames[name]; ok {
			name = modern
		}
		_, isVersion := m.env.versions[name]
		_, isString := m.env.strings[name]
		if isVersion || isString || name == "extra" {
			return markerOperand{variable: name}, nil
		}
		return markerOperand{}, fmt.Errorf("pip: marker names %q, which is not a marker variable", tok.text)
	}
	return markerOperand{}, fmt.Errorf("pip: marker has %q where a value is expected", tok.text)
}

func (m *markerParser) operator() (string, error) {
	switch {
	case m.at('o', ""), m.at('w', "in"):
		m.pos++
		return m.toks[m.pos-1].text, nil
	case m.at('w', "not") && m.pos+1 < len(m.toks) && m.toks[m.pos+1].kind == 'w' && m.toks[m.pos+1].text == "in":
		m.pos += 2
		return "not in", nil
	}
	return "", errors.New("pip: marker misses an operator")
}

func (m *markerParser) compare(left markerOperand, op string, right markerOperand) (truth, error) {
	if (left.variable == "") == (right.variable == "") {
		return undecided, errors.New("pip: marker compares two values or two variables; one of each is expected")
	}
	name, value, flipped := left.variable, right.value, false
	if name == "" {
		name, value, flipped = right.variable, left.value, true
	}
	var t truth
	if target, isVersion := m.env.versions[name]; isVersion {
		t = versionTruth(name, target, op, value, flipped)
	} else if name == "extra" {
		t = extraTruth(op, value)
	} else {
		t = stringTruth(m.env.strings[name], op, value, flipped)
	}
	if t == undecided && m.why == "" {
		m.why = fmt.Sprintf("%s %s %q", name, op, value)
		if flipped {
			m.why = fmt.Sprintf("%q %s %s", value, op, name)
		}
	}
	return t, nil
}

// flippedOps rewrites "3.11" <= python_version as python_version >= "3.11".
var flippedOps = map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}

func versionTruth(name string, target []int, op, value string, flipped bool) truth {
	if op == "in" || op == "not in" {
		listed := strings.Fields(value)
		if flipped || len(listed) == 0 {
			return undecided
		}
		found := false
		for _, s := range listed {
			v, ok := releaseOf(s)
			// uv answers false to a python_version list holding a version
			// such as 3.11.2, whatever the rest of the list.
			if !ok || name == "python_version" && len(v) > 2 {
				return undecided
			}
			found = found || compareRelease(target, v) == 0
		}
		return truthOf(found == (op == "in"))
	}
	if flipped {
		if op = flippedOps[op]; op == "" {
			return undecided
		}
	}
	if _, ok := releaseOf(value); !ok {
		return undecided
	}
	allowed, valid := clauseAllows(op+value, target)
	if !valid {
		return undecided
	}
	return truthOf(allowed)
}

// extraTruth decides extra for a requirement of the files, which requests
// no extra.
func extraTruth(op, value string) truth {
	if !ValidName(value) {
		return undecided
	}
	switch op {
	case "==":
		return fails
	case "!=":
		return holds
	}
	return undecided
}

func stringTruth(actual, op, value string, flipped bool) truth {
	switch op {
	case "==":
		return truthOf(actual == value)
	case "!=":
		return truthOf(actual != value)
	case "in", "not in":
		in := strings.Contains(value, actual)
		if flipped {
			in = strings.Contains(actual, value)
		}
		return truthOf(in == (op == "in"))
	}
	// uv's answers to an ordering of strings, or to ~=, differ from
	// lexical order.
	return undecided
}
