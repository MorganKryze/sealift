package pip

import (
	"slices"
	"strings"
	"testing"
)

var host = Platform{Python: "3.11.2", OS: "linux", CPU: "x86_64", Glibc: "2.28"}

func tagString(t Tag) string { return t.Interpreter + "-" + t.ABI + "-" + t.Platform }

func indexOfTag(tags []Tag, s string) int {
	return slices.IndexFunc(tags, func(t Tag) bool { return tagString(t) == s })
}

func TestTagsOrder(t *testing.T) {
	tags, err := Tags(host)
	if err != nil {
		t.Fatal(err)
	}
	var first []string
	for _, tg := range tags[:3] {
		first = append(first, tagString(tg))
	}
	want := []string{
		"cp311-cp311-manylinux_2_28_x86_64",
		"cp311-cp311-manylinux_2_27_x86_64",
		"cp311-cp311-manylinux_2_26_x86_64",
	}
	if !slices.Equal(first, want) {
		t.Fatalf("first tags = %v, want %v", first, want)
	}
	before := [][2]string{
		{"cp311-cp311-manylinux_2_17_x86_64", "cp311-cp311-manylinux2014_x86_64"},
		{"cp311-cp311-manylinux2014_x86_64", "cp311-cp311-manylinux_2_16_x86_64"},
		{"cp311-cp311-manylinux_2_5_x86_64", "cp311-abi3-manylinux_2_28_x86_64"},
		{"cp311-abi3-manylinux_2_28_x86_64", "cp310-abi3-manylinux_2_28_x86_64"},
		{"cp311-none-any", "py311-none-any"},
		{"py311-none-any", "py3-none-any"},
		{"py3-none-any", "py30-none-any"},
		{"cp311-none-manylinux_2_28_x86_64", "py3-none-manylinux_2_28_x86_64"},
		{"py3-none-manylinux_2_5_x86_64", "cp311-none-any"},
	}
	for _, row := range before {
		a, b := indexOfTag(tags, row[0]), indexOfTag(tags, row[1])
		if a < 0 || b < 0 || a >= b {
			t.Errorf("%s at %d must come before %s at %d", row[0], a, row[1], b)
		}
	}
	for _, tg := range tags {
		if strings.HasPrefix(tg.Platform, "linux_") {
			t.Errorf("tag %s is not portable", tagString(tg))
		}
	}
	if indexOfTag(tags, "cp311-cp311-manylinux_2_29_x86_64") >= 0 {
		t.Error("a glibc 2.29 tag is offered to a 2.28 target")
	}
}

func TestTagsAarch64StopsAtManylinux2014(t *testing.T) {
	tags, err := Tags(Platform{Python: "3.11.2", OS: "linux", CPU: "aarch64", Glibc: "2.28"})
	if err != nil {
		t.Fatal(err)
	}
	if indexOfTag(tags, "cp311-cp311-manylinux2014_aarch64") < 0 {
		t.Error("manylinux2014_aarch64 is missing")
	}
	if indexOfTag(tags, "cp311-cp311-manylinux_2_16_aarch64") >= 0 {
		t.Error("aarch64 has no manylinux below 2_17")
	}
}

func TestTagsRefusesAPlatformItCannotRank(t *testing.T) {
	tests := []struct {
		name string
		p    Platform
		want string
	}{
		{"python 2", Platform{"2.7.18", "linux", "x86_64", "2.28"}, `python "2.7.18"`},
		{"empty python", Platform{"", "linux", "x86_64", "2.28"}, `python ""`},
		{"windows", Platform{"3.11.2", "windows", "x86_64", "2.28"}, `os "windows"`},
		{"arm32", Platform{"3.11.2", "linux", "armv7l", "2.28"}, `cpu "armv7l"`},
		{"glibc 3", Platform{"3.11.2", "linux", "x86_64", "3.0"}, `glibc "3.0"`},
		{"glibc too old", Platform{"3.11.2", "linux", "x86_64", "2.4"}, `glibc "2.4"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Tags(tc.p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name %s", err, tc.want)
			}
		})
	}
}

func TestParseWheelName(t *testing.T) {
	w, err := ParseWheelName("numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl")
	if err != nil {
		t.Fatal(err)
	}
	if w.Name != "numpy" || w.Version != "1.26.4" || w.Build != "" || len(w.Tags) != 2 {
		t.Fatalf("parsed %+v", w)
	}
	if tagString(w.Tags[1]) != "cp311-cp311-manylinux2014_x86_64" {
		t.Errorf("second tag = %s", tagString(w.Tags[1]))
	}
	w, err = ParseWheelName("six-1.16.0-1abc-py2.py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	if w.Build != "1abc" || len(w.Tags) != 2 || tagString(w.Tags[0]) != "py2-none-any" {
		t.Fatalf("parsed %+v", w)
	}

	refused := []struct{ name, file, reason string }{
		{"path", "../x.whl", "path separator"},
		{"backslash", `a\x-1.0-py3-none-any.whl`, "path separator"},
		{"not a wheel", "six-1.16.0.tar.gz", "not a wheel"},
		{"missing part", "six-1.16.0-py3-none.whl", "needs name, version, tags"},
		{"bad version", "six-latest-py3-none-any.whl", "invalid version"},
		{"bad build", "six-1.0-abc-py3-none-any.whl", "invalid build tag"},
		{"bad tag", "six-1.0-py3-no ne-any.whl", "invalid tag"},
		{"bad name", "s!x-1.0-py3-none-any.whl", "invalid project name"},
		{"too long", strings.Repeat("a", 300) + "-1.0-py3-none-any.whl", "longer than"},
		{"tag bomb", "a-1.0-" + strings.Repeat("p.", 20) + "p-" + strings.Repeat("a.", 20) + "a-any.whl", "more than"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWheelName(tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want %q", err, tc.reason)
			}
		})
	}
}
