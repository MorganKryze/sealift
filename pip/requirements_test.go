package pip

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func one(data string) []File { return []File{{Name: "r.txt", Data: []byte(data)}} }

func TestParseFilesRefusals(t *testing.T) {
	long := "name==1.0 " + strings.Repeat("x", MaxLineBytes-len("name==1.0 ")+1)
	cycle := []File{
		{Name: "a.txt", Data: []byte("-r b.txt\n")},
		{Name: "b.txt", Data: []byte("x==1.0\n-r a.txt\n")},
	}
	many := make([]File, 0, MaxFiles+1)
	for i := 0; i <= MaxFiles; i++ {
		many = append(many, File{Name: fmt.Sprintf("f%02d.txt", i), Data: []byte("")})
	}
	tests := []struct {
		name  string
		files []File
		file  string
		line  int
		words string
	}{
		{"index url short", one("x==1.0\n-i https://x/simple\n"), "r.txt", 2, "option -i is not accepted"},
		{"index url", one("--index-url https://x/simple\n"), "r.txt", 1, "option --index-url is not accepted"},
		{"extra index url", one("--extra-index-url=https://x/simple\n"), "r.txt", 1, "option --extra-index-url is not accepted"},
		{"no index", one("--no-index\n"), "r.txt", 1, "option --no-index is not accepted"},
		{"find links short", one("-f /tmp\n"), "r.txt", 1, "option -f is not accepted"},
		{"find links", one("--find-links /tmp\n"), "r.txt", 1, "option --find-links is not accepted"},
		{"trusted host", one("--trusted-host x\n"), "r.txt", 1, "option --trusted-host is not accepted"},
		{"pre", one("--pre\n"), "r.txt", 1, "option --pre is not accepted"},
		{"require hashes", one("--require-hashes\n"), "r.txt", 1, "option --require-hashes is not accepted"},
		{"editable", one("-e .\n"), "r.txt", 1, "editable installs are not accepted"},
		{"option after pin", one("x==1.0 --no-binary :all:\n"), "r.txt", 1, "option --no-binary is not accepted after a requirement"},
		{"relative path", one("./local\n"), "r.txt", 1, "local paths are not accepted"},
		{"absolute path", one("/abs/path\n"), "r.txt", 1, "local paths are not accepted"},
		{"wheel url", one("https://host/x.whl\n"), "r.txt", 1, "URLs are not accepted"},
		{"direct reference", one("name @ https://host/x.whl\n"), "r.txt", 1, "direct references are not accepted"},
		{"vcs", one("git+https://host/repo\n"), "r.txt", 1, "URLs are not accepted"},
		{"range", one("\nname>=1.0\n"), "r.txt", 2, "pin with =="},
		{"compatible", one("name~=1.0\n"), "r.txt", 1, "pin with =="},
		{"bare name", one("name\n"), "r.txt", 1, "pin with =="},
		{"arbitrary equality", one("name===1.0\n"), "r.txt", 1, "=== is not accepted"},
		{"wildcard", one("name==1.*\n"), "r.txt", 1, "wildcard versions are not accepted"},
		{"local version", one("name==1.0+local\n"), "r.txt", 1, "local versions are not accepted"},
		{"two specifiers", one("name==1.0,<2\n"), "r.txt", 1, "one == specifier"},
		{"variable", one("name==${VERSION}\n"), "r.txt", 1, "variables are not expanded"},
		{"bad version", one("name==one\n"), "r.txt", 1, "not a PEP 440 version"},
		{"bad name", one("na me==1.0\n"), "r.txt", 1, "pin with =="},
		{"bad extras", one("name[a b]==1.0\n"), "r.txt", 1, "invalid extra"},
		{"sha512", one("name==1.0 --hash=sha512:" + hexA + "\n"), "r.txt", 1, "only sha256 hashes are accepted"},
		{"short hash", one("name==1.0 --hash=sha256:abc\n"), "r.txt", 1, "64 hexadecimal digits"},
		{"marker semicolon", one("name==1.0 ; python_version > '3' ; os_name == 'nt'\n"), "r.txt", 1, "marker contains ;"},
		{"marker characters", one("name==1.0 ; os_name == `x`\n"), "r.txt", 1, "marker has characters"},
		{"empty marker", one("name==1.0 ;\n"), "r.txt", 1, "marker is empty"},
		{"marker too long", one("name==1.0 ; " + strings.Repeat("a", 513) + "\n"), "r.txt", 1, "marker is longer than 512 bytes"},
		{"missing include", one("x==1.0\n-r missing.txt\n"), "r.txt", 2, "not one of the uploaded files"},
		{"include up", one("-r ../up.txt\n"), "r.txt", 1, "leaves the project"},
		{"include subdirectory", one("-r sub/dir.txt\n"), "r.txt", 1, "plain file name"},
		{"include without name", one("-r\n"), "r.txt", 1, "needs a file name"},
		{"include with two names", one("-r a.txt b.txt\n"), "r.txt", 1, "one file name"},
		{"include cycle", cycle, "b.txt", 2, "include cycle"},
		{"too many files", many, "f32.txt", 0, "at most 32 files"},
		{"long line", one("x==1.0\n" + long + "\n"), "r.txt", 2, "line is longer than 16384 bytes"},
		{"big file", one(strings.Repeat("#\n", MaxFileBytes/2+1)), "r.txt", 0, "file is larger than 1048576 bytes"},
		{"many lines", one(strings.Repeat("\n", MaxLines+1)), "r.txt", 0, "more than 10000 lines"},
		{"not utf-8", one("x==1.0\n\xff\n"), "r.txt", 0, "not valid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, probs := ParseFiles(tt.files)
			var found *Problem
			for i := range probs {
				if probs[i].File == tt.file && probs[i].Line == tt.line {
					found = &probs[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no problem at %s:%d, got %+v", tt.file, tt.line, probs)
			}
			if !strings.Contains(found.Reason, tt.words) {
				t.Errorf("reason %q lacks %q", found.Reason, tt.words)
			}
		})
	}
}

func TestParseFilesReportsEveryProblem(t *testing.T) {
	_, probs := ParseFiles(one("--pre\nx==1.0\nname>=1\n--no-index\n"))
	var lines []int
	for _, p := range probs {
		lines = append(lines, p.Line)
	}
	if !reflect.DeepEqual(lines, []int{1, 3, 4}) {
		t.Fatalf("problem lines = %v, want [1 3 4]", lines)
	}
}

func TestParseFilesCleansProblemText(t *testing.T) {
	line := "name>=1.0 \x1b[31m" + string(rune(0x202e)) + strings.Repeat("y", 300)
	_, probs := ParseFiles(one(line + "\n"))
	if len(probs) != 1 {
		t.Fatalf("problems = %+v", probs)
	}
	text := probs[0].Text
	if n := len([]rune(text)); n != 200 {
		t.Errorf("text has %d runes, want 200", n)
	}
	if strings.ContainsAny(text, "\x1b\u202e") {
		t.Errorf("text keeps a control or format character: %q", text)
	}
	_, probs = ParseFiles(one("name>=1 https://user:secret@host/x\n"))
	if len(probs) != 1 || strings.Contains(probs[0].Text, "secret") {
		t.Errorf("text leaks a credential: %+v", probs)
	}
}

func TestParseFilesRefusesConflictingPins(t *testing.T) {
	files := []File{
		{Name: "a.txt", Data: []byte("x==1\nMypy_Extensions==1.0.0\n")},
		{Name: "b.txt", Data: []byte("\nmypy-extensions==1.1.0\n")},
	}
	_, probs := ParseFiles(files)
	if len(probs) != 1 {
		t.Fatalf("problems = %+v, want one", probs)
	}
	r := probs[0].Reason
	for _, want := range []string{"a.txt:2", "b.txt:2", "1.0.0", "1.1.0", "mypy-extensions"} {
		if !strings.Contains(r, want) {
			t.Errorf("reason %q lacks %q", r, want)
		}
	}

	same := []File{
		{Name: "a.txt", Data: []byte("x==1.0\n")},
		{Name: "b.txt", Data: []byte("x==1.0.0\n")},
	}
	s, probs := ParseFiles(same)
	if len(probs) != 0 {
		t.Fatalf("equal versions are a problem: %+v", probs)
	}
	if len(s.Requirements) != 1 {
		t.Errorf("requirements = %+v, want one", s.Requirements)
	}
	if got := s.FilesOf("x"); !reflect.DeepEqual(got, []string{"a.txt", "b.txt"}) {
		t.Errorf("FilesOf = %v", got)
	}
}

func TestParseFilesRefusesConstraintConflictingWithRequirement(t *testing.T) {
	files := []File{
		{Name: "r.txt", Data: []byte("-c c.txt\nx==1.0\n")},
		{Name: "c.txt", Data: []byte("x==2.0\n")},
	}
	_, probs := ParseFiles(files)
	if len(probs) != 1 || !strings.Contains(probs[0].Reason, "c.txt:1") {
		t.Fatalf("problems = %+v", probs)
	}
}

func TestParseFilesJoinsContinuationLines(t *testing.T) {
	data := "a==1\n\nb==2\n\nname==1.0 \\\n    --hash=sha256:" + hexA + "\nz==3\n"
	s, probs := ParseFiles(one(data))
	if len(probs) != 0 {
		t.Fatalf("problems = %+v", probs)
	}
	var pin *Pin
	for i := range s.Requirements {
		if s.Requirements[i].Key == "name" {
			pin = &s.Requirements[i]
		}
	}
	if pin == nil {
		t.Fatalf("no pin for name in %+v", s.Requirements)
	}
	if pin.Line != 5 {
		t.Errorf("line = %d, want 5", pin.Line)
	}
	if !reflect.DeepEqual(pin.Hashes, []string{hexA}) {
		t.Errorf("hashes = %v", pin.Hashes)
	}
	if pin.Version != "1.0" {
		t.Errorf("version = %q", pin.Version)
	}
}

func TestParseFilesReportsProblemOnContinuedLineAtItsFirstLine(t *testing.T) {
	_, probs := ParseFiles(one("a==1\nname>=1.0 \\\n --hash=sha256:" + hexA + "\n"))
	if len(probs) != 1 || probs[0].Line != 2 {
		t.Fatalf("problems = %+v", probs)
	}
}

func TestParseFilesReadsHashes(t *testing.T) {
	data := "name[Extra_One,b]==1.0 ; python_version >= \"3.9\" --hash=sha256:" + hexA + " --hash sha256:" + strings.ToUpper(hexB) +
		" --hash=sha256:" + hexA + " # c\n"
	s, probs := ParseFiles(one(data))
	if len(probs) != 0 {
		t.Fatalf("problems = %+v", probs)
	}
	want := Pin{
		Name: "name", Key: "name", Extras: []string{"b", "extra-one"}, Version: "1.0",
		Marker: `python_version >= "3.9"`, Hashes: []string{hexA, hexB}, File: "r.txt", Line: 1,
	}
	if len(s.Requirements) != 1 || !reflect.DeepEqual(s.Requirements[0], want) {
		t.Fatalf("pin = %+v, want %+v", s.Requirements, want)
	}
}

func TestParseFilesIncludesAndConstraints(t *testing.T) {
	files := []File{
		{Name: "requirements.txt", Data: []byte("-r ./base.txt\n--constraint=constraints.txt\nweb==3\n")},
		{Name: "base.txt", Data: []byte("-rlower.txt\nbase==1\n")},
		{Name: "lower.txt", Data: []byte("lower==2\n")},
		{Name: "constraints.txt", Data: []byte("sub==9\nweb==3.0\nbase==1\n-r deep.txt\n")},
		{Name: "deep.txt", Data: []byte("deep==4\n")},
	}
	s, probs := ParseFiles(files)
	if len(probs) != 0 {
		t.Fatalf("problems = %+v", probs)
	}
	var reqs, cons []string
	for _, p := range s.Requirements {
		if p.Constraint {
			t.Errorf("requirement %s marked as constraint", p.Key)
		}
		reqs = append(reqs, p.Key+"=="+p.Version)
	}
	for _, p := range s.Constraints {
		if !p.Constraint {
			t.Errorf("constraint %s not marked", p.Key)
		}
		cons = append(cons, p.Key+"=="+p.Version)
	}
	if want := []string{"base==1", "lower==2", "web==3"}; !reflect.DeepEqual(reqs, want) {
		t.Errorf("requirements = %v, want %v", reqs, want)
	}
	if want := []string{"deep==4", "sub==9"}; !reflect.DeepEqual(cons, want) {
		t.Errorf("constraints = %v, want %v", cons, want)
	}
	if got := s.FilesOf("web"); !reflect.DeepEqual(got, []string{"constraints.txt", "requirements.txt"}) {
		t.Errorf("FilesOf(web) = %v", got)
	}
}

func TestParseFilesRefusesIncludesNestedTooDeep(t *testing.T) {
	var files []File
	for i := 0; i < 10; i++ {
		files = append(files, File{Name: fmt.Sprintf("f%d.txt", i), Data: []byte(fmt.Sprintf("-r f%d.txt\n", i+1))})
	}
	files = append(files, File{Name: "f10.txt", Data: []byte("x==1\n")})
	_, probs := ParseFiles(files)
	if len(probs) == 0 || !strings.Contains(probs[0].Reason, "deeper than 8") {
		t.Fatalf("problems = %+v", probs)
	}
}

func TestParseFilesAcceptsBOMAndCRLF(t *testing.T) {
	data := "\xef\xbb\xbf# header\r\nb==2 \\\r\n  --hash=sha256:" + hexA + "\r\n\r\na==1\r\n"
	s, probs := ParseFiles(one(data))
	if len(probs) != 0 {
		t.Fatalf("problems = %+v", probs)
	}
	if len(s.Requirements) != 2 || s.Requirements[0].Key != "a" || s.Requirements[1].Line != 2 {
		t.Errorf("requirements = %+v", s.Requirements)
	}
	if !reflect.DeepEqual(s.Requirements[1].Hashes, []string{hexA}) {
		t.Errorf("hashes = %v", s.Requirements[1].Hashes)
	}
}

func TestParseFilesRefusesMoreThanMaxPins(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxPins; i++ {
		fmt.Fprintf(&b, "p%d==1\n", i)
	}
	_, probs := ParseFiles(one(b.String()))
	if len(probs) != 1 || !strings.Contains(probs[0].Reason, "at most 5000 pins") {
		t.Fatalf("problems = %+v", probs)
	}
}

func TestParseFilesRefusesDuplicateFileName(t *testing.T) {
	_, probs := ParseFiles([]File{{Name: "a.txt"}, {Name: "a.txt"}})
	if len(probs) != 1 || !strings.Contains(probs[0].Reason, "twice") {
		t.Fatalf("problems = %+v", probs)
	}
}

func TestRequirementsIn(t *testing.T) {
	files := []File{
		{Name: "r.txt", Data: []byte("--constraint c.txt\nZed[b,a]==2 --hash=sha256:" + hexA +
			"\nalpha==1.0 ; python_version >= \"3.9\"\nMid_dle==3\n")},
		{Name: "c.txt", Data: []byte("alpha==1.0.0\nother==5 ; os_name == 'nt'\n")},
	}
	s, probs := ParseFiles(files)
	if len(probs) != 0 {
		t.Fatalf("problems = %+v", probs)
	}
	want := "alpha==1.0 ; python_version >= \"3.9\"\nmid-dle==3\nzed[a,b]==2\n"
	if got := string(s.RequirementsIn()); got != want {
		t.Errorf("RequirementsIn = %q, want %q", got, want)
	}
	if got, want := string(s.ConstraintsTxt()), "other==5 ; os_name == 'nt'\n"; got != want {
		t.Errorf("ConstraintsTxt = %q, want %q", got, want)
	}
	if got := (Set{}).RequirementsIn(); len(got) != 0 {
		t.Errorf("empty set gives %q", got)
	}
}
