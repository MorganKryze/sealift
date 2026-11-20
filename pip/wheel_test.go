package pip

import (
	"archive/zip"
	"bytes"
	"fmt"
	"hash/crc32"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// zipEntry is one file of a test wheel. A raw entry is written as stored
// bytes under a CRC32 that does not match them.
type zipEntry struct {
	name string
	body []byte
	raw  bool
}

func zipOf(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.raw {
			w, err := zw.CreateRaw(&zip.FileHeader{
				Name: e.name, Method: zip.Store, CRC32: crc32.ChecksumIEEE(e.body) + 1,
				CompressedSize64: uint64(len(e.body)), UncompressedSize64: uint64(len(e.body)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(e.body); err != nil {
				t.Fatal(err)
			}
			continue
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInspectWheel(t *testing.T) {
	const dist = "demo_pkg-1.2.dist-info/"
	metadata := func(headers string) zipEntry {
		return zipEntry{name: dist + "METADATA", body: []byte("Metadata-Version: 2.1\n" + headers + "Summary: a demo\n\nThe body is free text.\nName: other\n")}
	}
	wheelFile := func(version string) zipEntry {
		return zipEntry{name: dist + "WHEEL", body: []byte("Wheel-Version: " + version + "\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")}
	}
	meta := metadata("Name: Demo.Pkg\nVersion: 1.2\n")
	module := zipEntry{name: "demo_pkg/__init__.py", body: []byte("VERSION = '1.2'\n")}
	pure := []zipEntry{module, meta, wheelFile("1.0"), {name: dist + "RECORD"}}
	with := func(extra ...zipEntry) []zipEntry { return append(slices.Clone(pure), extra...) }
	without := func(names ...string) []zipEntry {
		return slices.DeleteFunc(slices.Clone(pure), func(e zipEntry) bool { return slices.Contains(names, e.name) })
	}
	replacing := func(r zipEntry) []zipEntry {
		out := slices.Clone(pure)
		for i := range out {
			if out[i].name == r.name {
				out[i] = r
			}
		}
		return out
	}
	renamed := func(from, to string) []zipEntry {
		out := slices.Clone(pure)
		for i := range out {
			out[i].name = strings.Replace(out[i].name, from, to, 1)
		}
		return out
	}

	const compiledDist = "markupsafe-3.0.2.dist-info/"
	compiled := []zipEntry{
		{name: "markupsafe/"},
		{name: "markupsafe/__init__.py", body: []byte("from ._speedups import escape\n")},
		{name: "markupsafe/_speedups.cpython-311-x86_64-linux-gnu.so", body: []byte("\x7fELF\x02\x01\x01\x00binary")},
		{name: "markupsafe-3.0.2.data/scripts/markup", body: []byte("#!python\n")},
		{name: compiledDist + "METADATA", body: []byte("Metadata-Version: 2.1\r\nName: MarkupSafe\r\nVersion: 3.0.2\r\nRequires-Python: >=3.9\r\n\r\nSafely add untrusted strings.\r\n")},
		{name: compiledDist + "WHEEL", body: []byte("Wheel-Version: 1.0\r\nGenerator: setuptools\r\nRoot-Is-Purelib: false\r\nTag: cp311-cp311-manylinux_2_17_x86_64\r\n")},
		{name: compiledDist + "RECORD"},
	}

	var crowded []zipEntry
	for i := range 3000 {
		crowded = append(crowded, zipEntry{name: fmt.Sprintf("demo_pkg/m%04d.py", i)})
	}
	crowded = append(crowded, pure...)

	longName := "Name: " + strings.Repeat("a", 300) + "\x1b]0;title\x07\nVersion: 1.2\n"

	// evil builds a wheel whose .dist-info names evil 1.0, with the METADATA
	// and WHEEL bodies given: Python's email parser, which pip reads both
	// files with, must find the same fields in them as InspectWheel does.
	evil := func(metadata, wheel string) []byte {
		const evilDist = "evil-1.0.dist-info/"
		return zipOf(t, zipEntry{name: evilDist + "METADATA", body: []byte(metadata)}, zipEntry{name: evilDist + "WHEEL", body: []byte(wheel)}, zipEntry{name: evilDist + "RECORD"})
	}
	const evilWheel = "Wheel-Version: 1.0\nTag: py3-none-any\n"

	// The bound covers the sum: each 60-byte entry fits under it, both do not.
	var pureBytes int64
	for _, e := range pure {
		pureBytes += int64(len(e.body))
	}
	sixty := bytes.Repeat([]byte{0}, 60)
	twoHalves := with(zipEntry{name: "demo_pkg/a.bin", body: sixty}, zipEntry{name: "demo_pkg/b.bin", body: sixty})

	rows := []struct {
		name    string
		data    []byte
		limits  WheelLimits
		want    WheelInfo
		reasons []string // words the refusal must hold; none for an accepted wheel
	}{
		{name: "a pure wheel", data: zipOf(t, pure...), want: WheelInfo{Name: "Demo.Pkg", Version: "1.2"}},
		{name: "a compiled wheel", data: zipOf(t, compiled...), want: WheelInfo{Name: "MarkupSafe", Version: "3.0.2"}},
		{name: "a Wheel-Version of 1 with no minor", data: zipOf(t, replacing(wheelFile("1"))...), want: WheelInfo{Name: "Demo.Pkg", Version: "1.2"}},
		{name: "a later minor Wheel-Version", data: zipOf(t, replacing(wheelFile("1.9"))...), want: WheelInfo{Name: "Demo.Pkg", Version: "1.2"}},

		{name: "not a zip", data: []byte("PK\x03\x04 this is not a zip archive"), reasons: []string{"the wheel is not a zip archive"}},
		{name: "an empty file", data: nil, reasons: []string{"the wheel is not a zip archive"}},

		{name: "entries over the limit", data: zipOf(t, pure...), limits: WheelLimits{Entries: 3}, reasons: []string{"the wheel holds more than 3 entries"}},
		{name: "a zip directory past what the limits allow", data: zipOf(t, crowded...), limits: WheelLimits{Entries: 10, NameBytes: 64},
			reasons: []string{"the wheel's zip directory is larger than what 10 entries with 64-byte names need"}},
		{name: "a name over the limit", data: zipOf(t, with(zipEntry{name: "demo_pkg/" + strings.Repeat("b", 200) + ".py"})...), limits: WheelLimits{NameBytes: 40},
			reasons: []string{"an entry name is longer than 40 bytes", `"demo_pkg/` + strings.Repeat("b", 91) + `"`}},
		{name: "declared unpacked bytes over the limit", data: zipOf(t, with(zipEntry{name: "demo_pkg/data.bin", body: bytes.Repeat([]byte{0}, 200)})...), limits: WheelLimits{Unpacked: 100},
			reasons: []string{"the wheel's entries declare more than 100 unpacked bytes"}},
		{name: "entries each under the unpacked limit, together over it", data: zipOf(t, twoHalves...), limits: WheelLimits{Unpacked: pureBytes + 100},
			reasons: []string{fmt.Sprintf("the wheel's entries declare more than %d unpacked bytes", pureBytes+100)}},
		{name: "entries that together meet the unpacked limit", data: zipOf(t, twoHalves...), limits: WheelLimits{Unpacked: pureBytes + 120},
			want: WheelInfo{Name: "Demo.Pkg", Version: "1.2"}},

		{name: "an absolute name", data: zipOf(t, with(zipEntry{name: "/etc/cron.d/evil"})...), reasons: []string{`entry "/etc/cron.d/evil" is an absolute path`}},
		{name: "a drive letter", data: zipOf(t, with(zipEntry{name: "C:/evil.py"})...), reasons: []string{`entry "C:/evil.py" is an absolute path`}},
		{name: "a parent segment", data: zipOf(t, with(zipEntry{name: "demo_pkg/../../evil.py"})...), reasons: []string{`entry "demo_pkg/../../evil.py" climbs to a parent directory`}},
		{name: "a backslash", data: zipOf(t, with(zipEntry{name: `demo_pkg\..\evil.py`})...), reasons: []string{`entry "demo_pkg\..\evil.py" holds a backslash`}},
		{name: "a control character", data: zipOf(t, with(zipEntry{name: "demo_pkg/\x1b[2Jevil.py"})...), reasons: []string{`entry "demo_pkg/[2Jevil.py" holds a control character`}},
		{name: "invalid UTF-8", data: zipOf(t, with(zipEntry{name: "demo_pkg/\xffevil.py"})...), reasons: []string{`entry "demo_pkg/evil.py" is not valid UTF-8`}},
		{name: "a duplicate name", data: zipOf(t, with(module)...), reasons: []string{`entry "demo_pkg/__init__.py" appears twice`}},
		{name: "an empty segment", data: zipOf(t, with(zipEntry{name: "demo_pkg//evil.py"})...), reasons: []string{`entry "demo_pkg//evil.py" is not a clean path`}},
		{name: "a dot segment", data: zipOf(t, with(zipEntry{name: "./demo_pkg/evil.py"})...), reasons: []string{`entry "./demo_pkg/evil.py" is not a clean path`}},
		{name: "an empty name", data: zipOf(t, with(zipEntry{name: ""})...), reasons: []string{`entry "" is not a clean path`}},
		{name: "a bad name is named before METADATA is read", data: zipOf(t, append(without(meta.name), zipEntry{name: meta.name, body: meta.body, raw: true}, zipEntry{name: "../evil.py"})...),
			reasons: []string{`entry "../evil.py" climbs to a parent directory`}},

		{name: "no dist-info directory", data: zipOf(t, module), reasons: []string{"the wheel has no top-level .dist-info directory"}},
		{name: "a dist-info directory below the top", data: zipOf(t, renamed(dist, "demo_pkg/"+dist)...), reasons: []string{"the wheel has no top-level .dist-info directory"}},
		{name: "two dist-info directories", data: zipOf(t, with(zipEntry{name: "other-1.0.dist-info/METADATA"})...),
			reasons: []string{`the wheel has two .dist-info directories: "demo_pkg-1.2.dist-info" and "other-1.0.dist-info"`}},
		{name: "a dist-info directory with no version", data: zipOf(t, renamed(dist, "demo_pkg.dist-info/")...),
			reasons: []string{`the .dist-info directory "demo_pkg.dist-info" is not named <name>-<version>.dist-info`}},
		{name: "a dist-info directory of another package", data: zipOf(t, renamed(dist, "other-1.2.dist-info/")...),
			reasons: []string{`the .dist-info directory "other-1.2.dist-info" does not match METADATA's Demo.Pkg 1.2`}},
		{name: "a dist-info directory of another version", data: zipOf(t, renamed(dist, "demo_pkg-1.3.dist-info/")...),
			reasons: []string{`the .dist-info directory "demo_pkg-1.3.dist-info" does not match METADATA's Demo.Pkg 1.2`}},

		{name: "METADATA missing", data: zipOf(t, without(meta.name)...), reasons: []string{`the wheel has no METADATA in "demo_pkg-1.2.dist-info"`}},
		{name: "METADATA over 1 MiB", data: zipOf(t, replacing(zipEntry{name: meta.name, body: append(slices.Clone(meta.body), bytes.Repeat([]byte("x"), 1<<20)...)})...),
			reasons: []string{"METADATA is larger than 1048576 bytes"}},
		{name: "METADATA failing its checksum", data: zipOf(t, append(without(meta.name), zipEntry{name: meta.name, body: meta.body, raw: true})...),
			reasons: []string{"cannot read METADATA: zip: checksum error"}},
		{name: "METADATA without Name", data: zipOf(t, replacing(metadata("Version: 1.2\n"))...), reasons: []string{"METADATA has no Name field"}},
		{name: "METADATA without Version", data: zipOf(t, replacing(metadata("Name: Demo.Pkg\n"))...), reasons: []string{"METADATA has no Version field"}},
		{name: "METADATA with Name only in its body", data: zipOf(t, replacing(zipEntry{name: meta.name, body: []byte("Version: 1.2\n\nName: Demo.Pkg\n")})...),
			reasons: []string{"METADATA has no Name field"}},
		{name: "METADATA with two Name fields", data: zipOf(t, replacing(metadata("Name: Demo.Pkg\nVersion: 1.2\nname: other\n"))...), reasons: []string{"METADATA has two Name fields"}},
		{name: "an invalid Name", data: zipOf(t, replacing(metadata("Name: demo pkg!\nVersion: 1.2\n"))...), reasons: []string{`METADATA's Name "demo pkg!" is not a valid project name`}},
		{name: "a folded Name", data: zipOf(t, replacing(metadata("Name: Demo.Pkg\n other\nVersion: 1.2\n"))...), reasons: []string{`METADATA's Name "Demo.Pkg other" is not a valid project name`}},
		{name: "a long Name is cut", data: zipOf(t, replacing(metadata(longName))...), reasons: []string{`METADATA's Name "` + strings.Repeat("a", 100) + `" is not a valid project name`}},
		{name: "a bare carriage return ends a header line for Python", data: evil("Metadata-Version: 2.1\nSummary: x\rName: requests\nName: evil\nVersion: 1.0\n\n", evilWheel),
			reasons: []string{"METADATA holds a carriage return that does not end a line"}},
		{name: "a carriage return closing the last line ends it", data: evil("Name: evil\r\nVersion: 1.0\r", evilWheel), want: WheelInfo{Name: "evil", Version: "1.0"}},
		{name: "a line that is not a field starts Python's body", data: evil("Version: 1.0\ngarbage line\nName: evil\n", evilWheel),
			reasons: []string{`METADATA holds a header line that is not a field: "garbage line"`}},
		{name: "a space before the colon is not a field name", data: evil("Name : evil\nVersion: 1.0\n", evilWheel),
			reasons: []string{`METADATA holds a header line that is not a field: "Name : evil"`}},
		{name: "an empty field name", data: evil(": requests\nName: evil\nVersion: 1.0\n", evilWheel),
			reasons: []string{`METADATA holds a header line that is not a field: ": requests"`}},
		{name: "a form feed before the Name is kept as Python keeps it", data: zipOf(t, replacing(metadata("Name:\fDemo.Pkg\nVersion: 1.2\n"))...),
			reasons: []string{`METADATA's Name "Demo.Pkg" is not a valid project name`}},
		{name: "a bare carriage return in WHEEL", data: evil("Name: evil\nVersion: 1.0\n", "Wheel-Version: 1.0\rTag: py3-none-any\n"),
			reasons: []string{"WHEEL holds a carriage return that does not end a line"}},
		{name: "a local Version", data: zipOf(t, replacing(metadata("Name: Demo.Pkg\nVersion: 1.2+cpu\n"))...), reasons: []string{`METADATA's Version "1.2+cpu" is not an exact version`}},

		{name: "WHEEL missing", data: zipOf(t, without(dist+"WHEEL")...), reasons: []string{`the wheel has no WHEEL file in "demo_pkg-1.2.dist-info"`}},
		{name: "WHEEL over 64 KiB", data: zipOf(t, replacing(zipEntry{name: dist + "WHEEL", body: append(wheelFile("1.0").body, bytes.Repeat([]byte("x"), 64<<10)...)})...),
			reasons: []string{"WHEEL is larger than 65536 bytes"}},
		{name: "WHEEL without Wheel-Version", data: zipOf(t, replacing(zipEntry{name: dist + "WHEEL", body: []byte("Generator: test\n")})...), reasons: []string{"WHEEL has no Wheel-Version field"}},
		{name: "Wheel-Version 2.0", data: zipOf(t, replacing(wheelFile("2.0"))...), reasons: []string{`WHEEL's Wheel-Version "2.0" is not 1.x, the only version this reader knows`}},
		{name: "Wheel-Version 0.9", data: zipOf(t, replacing(wheelFile("0.9"))...), reasons: []string{`WHEEL's Wheel-Version "0.9" is not 1.x`}},
		{name: "a Wheel-Version that is not a number", data: zipOf(t, replacing(wheelFile("one"))...), reasons: []string{`WHEEL's Wheel-Version "one" is not 1.x`}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, err := InspectWheel(bytes.NewReader(row.data), int64(len(row.data)), row.limits)
			if len(row.reasons) == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if got != row.want {
					t.Fatalf("got %+v, want %+v", got, row.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted as %+v, want a refusal", got)
			}
			reason := err.Error()
			for _, words := range row.reasons {
				if !strings.Contains(reason, words) {
					t.Errorf("reason %q lacks %q", reason, words)
				}
			}
			if !utf8.ValidString(reason) || strings.IndexFunc(reason, unicode.IsControl) >= 0 {
				t.Errorf("reason %q holds invalid UTF-8 or a control character", reason)
			}
			if strings.Contains(reason, strings.Repeat("a", 101)) || strings.Contains(reason, strings.Repeat("b", 101)) {
				t.Errorf("reason %q quotes more than 100 characters of the wheel", reason)
			}
		})
	}
}

func TestDefaultWheelLimits(t *testing.T) {
	if DefaultWheelLimits != (WheelLimits{Entries: 100000, NameBytes: 1024, Unpacked: 17179869184}) {
		t.Errorf("DefaultWheelLimits = %+v", DefaultWheelLimits)
	}
	if MaxMetadataBytes != 1048576 || MaxWheelBytes != 65536 {
		t.Errorf("MaxMetadataBytes = %d, MaxWheelBytes = %d", MaxMetadataBytes, MaxWheelBytes)
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r    *bytes.Reader
	read int64
}

func (c *countingReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.read += int64(n)
	return n, err
}

// A file past its bound is refused after its bound is read, however much the
// wheel holds: METADATA and WHEEL are stored, so their bytes are read as is.
func TestInspectWheelReadsNoFurtherThanTheBound(t *testing.T) {
	const dist = "demo_pkg-1.2.dist-info/"
	padding := make([]byte, 8<<20)
	for i := range padding {
		padding[i] = byte('a' + i%26)
	}
	metadata := []byte("Name: Demo.Pkg\nVersion: 1.2\n\n")
	wheel := []byte("Wheel-Version: 1.0\n")
	rows := []struct {
		file     string
		metadata []byte
		wheel    []byte
		reason   string
	}{
		{"METADATA", append(slices.Clone(metadata), padding...), wheel, "METADATA is larger than 1048576 bytes"},
		{"WHEEL", metadata, append(slices.Clone(wheel), padding...), "WHEEL is larger than 65536 bytes"},
	}
	for _, row := range rows {
		t.Run(row.file, func(t *testing.T) {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, e := range []zipEntry{{name: dist + "METADATA", body: row.metadata}, {name: dist + "WHEEL", body: row.wheel}} {
				w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Store})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(e.body); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			r := &countingReader{r: bytes.NewReader(buf.Bytes())}
			_, err := InspectWheel(r, int64(buf.Len()), WheelLimits{})
			if err == nil || !strings.Contains(err.Error(), row.reason) {
				t.Fatalf("err = %v, want %q", err, row.reason)
			}
			if r.read > 2<<20 {
				t.Errorf("read %d bytes of a %d-byte wheel to refuse %s", r.read, buf.Len(), row.file)
			}
		})
	}
}
