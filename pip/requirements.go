package pip

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds on what a project's requirements files may hold.
const (
	MaxFiles     = 32
	MaxFileBytes = 1 << 20
	MaxLines     = 10000
	MaxLineBytes = 16 << 10
	MaxPins      = 5000

	maxIncludeDepth = 8
	maxMarkerBytes  = 512
	maxTextRunes    = 200
)

var (
	commentRE     = regexp.MustCompile(`(^|\s)#.*$`)
	optionStartRE = regexp.MustCompile(`\s--?[A-Za-z]`)
	schemeRE      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	pathStartRE   = regexp.MustCompile(`^(?:[./~]|[^\s=<>!~;\[@]*[/\\])`)
	leadingNameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`)
	markerCharsRE = regexp.MustCompile(`^[A-Za-z0-9_.<>=!~"' ()-]*$`)
	hashHexRE     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	userinfoRE    = regexp.MustCompile(`(://)[^/\s@]*@`)
)

// File is one uploaded requirements file.
type File struct {
	Name string
	Data []byte
}

// Pin is one exact requirement.
type Pin struct {
	Name       string   // as written
	Key        string   // Normalize(Name)
	Extras     []string // sorted, normalized
	Version    string
	Marker     string   // empty when the line has none
	Hashes     []string // lower-case hex sha256
	File       string
	Line       int
	Constraint bool // reached only through -c
}

// Problem is one refusal, with the place it came from.
type Problem struct {
	File, Text, Reason string // Text: the line, cut to 200 runes, control characters removed
	Line               int    // 0 for a file-level problem
}

// Set is the content of a project's requirements files.
type Set struct {
	Requirements []Pin // sorted by Key
	Constraints  []Pin // sorted by Key; none repeats a requirement
	files        map[string][]string
}

type include struct {
	target     string
	constraint bool
	line       int
	text       string
}

type parsedFile struct {
	pins     []Pin
	includes []include
}

type problems struct {
	list []Problem
	seen map[Problem]bool
}

func (p *problems) add(file string, line int, text, reason string) {
	pr := Problem{File: file, Line: line, Text: cleanText(text), Reason: reason}
	if p.seen[pr] {
		return
	}
	if p.seen == nil {
		p.seen = map[Problem]bool{}
	}
	p.seen[pr] = true
	p.list = append(p.list, pr)
}

// ParseFiles reads every file, follows includes between them and checks the
// pins against each other. It reports every problem, never only the first,
// and returns an empty Set when there is one.
func ParseFiles(files []File) (Set, []Problem) {
	var probs problems
	names := map[string]bool{}
	var accepted []File
	for _, f := range files {
		switch {
		case names[f.Name]:
			probs.add(f.Name, 0, "", "file name given twice")
		case len(accepted) >= MaxFiles:
			probs.add(f.Name, 0, "", fmt.Sprintf("a project takes at most %d files", MaxFiles))
		default:
			names[f.Name] = true
			accepted = append(accepted, f)
		}
	}
	parsed := map[string]*parsedFile{}
	for _, f := range accepted {
		parsed[f.Name] = parseFile(f, names, &probs)
	}

	w := walker{parsed: parsed, seen: map[walkKey]bool{}, probs: &probs}
	// A file reached through -c, and whatever it includes, holds constraints.
	// Every other uploaded file is a top-level requirements file.
	inConstraints := map[string]bool{}
	var queue []string
	for _, pf := range parsed {
		for _, inc := range pf.includes {
			if inc.constraint {
				queue = append(queue, inc.target)
			}
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if inConstraints[name] {
			continue
		}
		inConstraints[name] = true
		for _, inc := range parsed[name].includes {
			queue = append(queue, inc.target)
		}
	}
	for _, f := range accepted {
		if !inConstraints[f.Name] {
			w.walk(f.Name, false, []string{f.Name})
		}
	}
	for _, f := range accepted {
		if !w.seen[walkKey{f.Name, false}] && !w.seen[walkKey{f.Name, true}] {
			w.walk(f.Name, true, []string{f.Name})
		}
	}

	set, ok := w.assemble()
	if !ok || len(probs.list) > 0 {
		return Set{}, probs.list
	}
	return set, nil
}

type walkKey struct {
	file       string
	constraint bool
}

type walker struct {
	parsed map[string]*parsedFile
	seen   map[walkKey]bool
	probs  *problems
	reqs   []Pin
	cons   []Pin
}

func (w *walker) walk(name string, constraint bool, stack []string) {
	key := walkKey{name, constraint}
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	pf := w.parsed[name]
	for _, p := range pf.pins {
		p.Constraint = constraint
		if constraint {
			w.cons = append(w.cons, p)
		} else {
			w.reqs = append(w.reqs, p)
		}
	}
	for _, inc := range pf.includes {
		switch {
		case slices.Contains(stack, inc.target):
			path := append(slices.Clone(stack), inc.target)
			w.probs.add(name, inc.line, inc.text, "include cycle: "+strings.Join(path, " -> "))
		case len(stack) > maxIncludeDepth:
			w.probs.add(name, inc.line, inc.text, fmt.Sprintf("includes nest deeper than %d files", maxIncludeDepth))
		default:
			w.walk(inc.target, constraint || inc.constraint, append(slices.Clone(stack), inc.target))
		}
	}
}

func comparePins(a, b Pin) int {
	if c := strings.Compare(a.Key, b.Key); c != 0 {
		return c
	}
	if c := strings.Compare(a.File, b.File); c != 0 {
		return c
	}
	return a.Line - b.Line
}

// assemble checks the pins across files and builds the Set. A file reached
// both through -r and -c counts as requirements.
func (w *walker) assemble() (Set, bool) {
	type place struct {
		file string
		line int
	}
	isReq := map[place]bool{}
	for _, p := range w.reqs {
		isReq[place{p.File, p.Line}] = true
	}
	var cons []Pin
	for _, p := range w.cons {
		if !isReq[place{p.File, p.Line}] {
			cons = append(cons, p)
		}
	}
	reqs := slices.Clone(w.reqs)
	if len(reqs)+len(cons) > MaxPins {
		all := append(slices.Clone(reqs), cons...)
		slices.SortFunc(all, comparePins)
		over := all[MaxPins]
		w.probs.add(over.File, over.Line, "", fmt.Sprintf("a project takes at most %d pins", MaxPins))
		return Set{}, false
	}
	slices.SortFunc(reqs, comparePins)
	slices.SortFunc(cons, comparePins)

	all := append(slices.Clone(reqs), cons...)
	slices.SortStableFunc(all, comparePins)
	files := map[string][]string{}
	first := map[string]Pin{}
	for _, p := range all {
		if !slices.Contains(files[p.Key], p.File) {
			files[p.Key] = append(files[p.Key], p.File)
		}
		f, ok := first[p.Key]
		if !ok {
			first[p.Key] = p
			continue
		}
		if !SameVersion(f.Version, p.Version) {
			w.probs.add(p.File, p.Line, p.Name+"=="+p.Version, fmt.Sprintf("conflicting pins for %s: %s:%d pins %s, %s:%d pins %s",
				p.Key, f.File, f.Line, f.Version, p.File, p.Line, p.Version))
		}
	}
	for _, list := range files {
		slices.Sort(list)
	}

	var set Set
	set.files = files
	for _, p := range reqs {
		n := len(set.Requirements)
		if n > 0 {
			prev := &set.Requirements[n-1]
			if prev.Key == p.Key && SameVersion(prev.Version, p.Version) && prev.Marker == p.Marker && slices.Equal(prev.Extras, p.Extras) {
				for _, h := range p.Hashes {
					if !slices.Contains(prev.Hashes, h) {
						prev.Hashes = append(prev.Hashes, h)
					}
				}
				continue
			}
		}
		set.Requirements = append(set.Requirements, p)
	}
	for _, p := range cons {
		if _, isReq := slices.BinarySearchFunc(set.Requirements, p.Key, func(r Pin, k string) int { return strings.Compare(r.Key, k) }); isReq {
			continue
		}
		if n := len(set.Constraints); n > 0 && set.Constraints[n-1].Key == p.Key {
			continue
		}
		set.Constraints = append(set.Constraints, p)
	}
	return set, true
}

// RequirementsIn is uv's input: name[extras]==version ; marker.
func (s Set) RequirementsIn() []byte { return renderPins(s.Requirements, true) }

// ConstraintsTxt is the constraints uv reads with -c.
func (s Set) ConstraintsTxt() []byte { return renderPins(s.Constraints, false) }

func renderPins(pins []Pin, extras bool) []byte {
	var b bytes.Buffer
	for _, p := range pins {
		b.WriteString(p.Key)
		if extras && len(p.Extras) > 0 {
			b.WriteString("[" + strings.Join(p.Extras, ",") + "]")
		}
		b.WriteString("==" + p.Version)
		if p.Marker != "" {
			b.WriteString(" ; " + p.Marker)
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// FilesOf returns the files that pin key, sorted.
func (s Set) FilesOf(key string) []string { return slices.Clone(s.files[key]) }

func parseFile(f File, names map[string]bool, probs *problems) *parsedFile {
	pf := &parsedFile{}
	if len(f.Data) > MaxFileBytes {
		probs.add(f.Name, 0, "", fmt.Sprintf("file is larger than %d bytes", MaxFileBytes))
		return pf
	}
	if !utf8.Valid(f.Data) {
		probs.add(f.Name, 0, "", "file is not valid UTF-8")
		return pf
	}
	data := strings.TrimPrefix(string(f.Data), "\xef\xbb\xbf")
	data = strings.ReplaceAll(data, "\r", "")
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if data == "" {
		return pf
	}
	if len(lines) > MaxLines {
		probs.add(f.Name, 0, "", fmt.Sprintf("file has more than %d lines", MaxLines))
		return pf
	}

	for i := 0; i < len(lines); i++ {
		start := i + 1
		var joined strings.Builder
		raw := 0
		for ; i < len(lines); i++ {
			raw += len(lines[i])
			part := strings.TrimRight(commentRE.ReplaceAllString(lines[i], ""), " \t")
			if cont := strings.HasSuffix(part, `\`); cont && i+1 < len(lines) {
				joined.WriteString(strings.TrimSuffix(part, `\`))
				continue
			}
			joined.WriteString(strings.TrimSuffix(part, `\`))
			break
		}
		line := strings.TrimSpace(joined.String())
		if line == "" {
			continue
		}
		if raw > MaxLineBytes {
			probs.add(f.Name, start, line, fmt.Sprintf("line is longer than %d bytes", MaxLineBytes))
			continue
		}
		if strings.HasPrefix(line, "-") {
			parseOption(f.Name, start, line, names, pf, probs)
			continue
		}
		pin, reason := parseRequirement(line)
		if reason != "" {
			probs.add(f.Name, start, line, reason)
			continue
		}
		pin.File, pin.Line = f.Name, start
		pf.pins = append(pf.pins, pin)
	}
	return pf
}

func parseOption(file string, lineNo int, line string, names map[string]bool, pf *parsedFile, probs *problems) {
	fields := strings.Fields(line)
	tok := fields[0]
	opt, value, hasValue := strings.Cut(tok, "=")
	constraint := false
	switch {
	case opt == "-e" || opt == "--editable":
		probs.add(file, lineNo, line, "editable installs are not accepted")
		return
	case opt == "--requirement":
	case opt == "--constraint":
		constraint = true
	case len(tok) >= 2 && (tok[:2] == "-r" || tok[:2] == "-c") && !strings.HasPrefix(tok, "--"):
		constraint = tok[1] == 'c'
		value, hasValue = strings.TrimPrefix(tok[2:], "="), len(tok) > 2
		opt = tok[:2]
	default:
		probs.add(file, lineNo, line, fmt.Sprintf("option %s is not accepted", opt))
		return
	}
	rest := fields[1:]
	if !hasValue && len(rest) > 0 {
		value, rest = rest[0], rest[1:]
	}
	if value == "" {
		probs.add(file, lineNo, line, fmt.Sprintf("option %s needs a file name", opt))
		return
	}
	if len(rest) > 0 {
		probs.add(file, lineNo, line, fmt.Sprintf("option %s takes one file name", opt))
		return
	}
	target := strings.TrimPrefix(value, "./")
	switch {
	case slices.Contains(strings.FieldsFunc(target, func(r rune) bool { return r == '/' || r == '\\' }), ".."):
		probs.add(file, lineNo, line, "the included file leaves the project")
	case strings.ContainsAny(target, `/\`):
		probs.add(file, lineNo, line, "an include names an uploaded file by its plain file name, not a path")
	case !names[target]:
		probs.add(file, lineNo, line, fmt.Sprintf("%q is not one of the uploaded files", target))
	default:
		pf.includes = append(pf.includes, include{target: target, constraint: constraint, line: lineNo, text: line})
	}
}

// parseRequirement reads one name==version line. The reason is empty on
// success.
func parseRequirement(line string) (Pin, string) {
	if strings.Contains(line, "${") {
		return Pin{}, "variables are not expanded"
	}
	body, optionPart := line, ""
	if loc := optionStartRE.FindStringIndex(line); loc != nil {
		body, optionPart = line[:loc[0]], line[loc[0]:]
	}
	body = strings.TrimSpace(body)
	switch {
	case schemeRE.MatchString(body) || hasVCSPrefix(body):
		return Pin{}, "URLs are not accepted"
	case pathStartRE.MatchString(body):
		return Pin{}, "local paths are not accepted"
	}

	spec, marker, hasMarker := strings.Cut(body, ";")
	pin := Pin{}
	if hasMarker {
		marker = strings.TrimSpace(marker)
		switch {
		case marker == "":
			return Pin{}, "marker is empty"
		case strings.Contains(marker, ";"):
			return Pin{}, "marker contains ;"
		case len(marker) > maxMarkerBytes:
			return Pin{}, fmt.Sprintf("marker is longer than %d bytes", maxMarkerBytes)
		case !markerCharsRE.MatchString(marker):
			return Pin{}, "marker has characters outside letters, digits, spaces and _.<>=!~\"'()-"
		}
		pin.Marker = marker
	}

	spec = strings.TrimSpace(spec)
	pin.Name = leadingNameRE.FindString(spec)
	if pin.Name == "" {
		return Pin{}, "not a requirement: write name==version"
	}
	pin.Key = Normalize(pin.Name)
	rest := strings.TrimSpace(spec[len(pin.Name):])
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return Pin{}, "invalid extra list: missing ]"
		}
		seen := map[string]bool{}
		for _, e := range strings.Split(rest[1:end], ",") {
			e = strings.TrimSpace(e)
			if !ValidName(e) {
				return Pin{}, fmt.Sprintf("invalid extra %q", e)
			}
			if k := Normalize(e); !seen[k] {
				seen[k] = true
				pin.Extras = append(pin.Extras, k)
			}
		}
		slices.Sort(pin.Extras)
		rest = strings.TrimSpace(rest[end+1:])
	}
	switch {
	case strings.HasPrefix(rest, "@"):
		return Pin{}, "direct references are not accepted"
	case strings.HasPrefix(rest, "==="):
		return Pin{}, "arbitrary equality === is not accepted"
	case !strings.HasPrefix(rest, "=="):
		return Pin{}, "pin with ==: write name==version"
	}
	version := strings.TrimSpace(rest[2:])
	switch {
	case strings.Contains(version, ","):
		return Pin{}, "write one == specifier and nothing else"
	case strings.Contains(version, "*"):
		return Pin{}, "wildcard versions are not accepted"
	case strings.Contains(version, "+"):
		return Pin{}, "local versions are not accepted"
	case !IsExactVersion(version):
		return Pin{}, fmt.Sprintf("%q is not a PEP 440 version", version)
	}
	pin.Version = version

	hashes, reason := parseHashes(strings.Fields(optionPart))
	if reason != "" {
		return Pin{}, reason
	}
	pin.Hashes = hashes
	return pin, ""
}

func hasVCSPrefix(s string) bool {
	for _, p := range []string{"git+", "hg+", "svn+", "bzr+"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			return true
		}
	}
	return false
}

func parseHashes(tokens []string) ([]string, string) {
	var hashes []string
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		opt, value, hasValue := strings.Cut(tok, "=")
		if opt != "--hash" {
			return nil, fmt.Sprintf("option %s is not accepted after a requirement", opt)
		}
		if !hasValue {
			if i+1 >= len(tokens) {
				return nil, "option --hash needs a value"
			}
			i++
			value = tokens[i]
		}
		algo, digest, _ := strings.Cut(value, ":")
		switch {
		case !strings.EqualFold(algo, "sha256"):
			return nil, "only sha256 hashes are accepted"
		case !hashHexRE.MatchString(digest):
			return nil, "a sha256 hash is 64 hexadecimal digits"
		}
		digest = strings.ToLower(digest)
		if !slices.Contains(hashes, digest) {
			hashes = append(hashes, digest)
		}
	}
	return hashes, ""
}

// cleanText makes a requirements line safe to show: no control or format
// characters, no URL credentials, at most 200 runes.
func cleanText(s string) string {
	s = userinfoRE.ReplaceAllString(s, "$1")
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	runes := []rune(strings.Join(strings.Fields(s), " "))
	if len(runes) > maxTextRunes {
		runes = runes[:maxTextRunes]
	}
	return string(runes)
}
