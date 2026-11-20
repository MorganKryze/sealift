package pip

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// WheelLimits bounds what InspectWheel accepts. A zero field takes its default.
type WheelLimits struct {
	Entries   int   // zip entries
	NameBytes int   // bytes in one entry name
	Unpacked  int64 // declared uncompressed bytes, all entries
}

// DefaultWheelLimits are 100,000 entries, 1,024-byte names and 16 GiB
// declared unpacked.
var DefaultWheelLimits = WheelLimits{Entries: 100000, NameBytes: 1024, Unpacked: 16 << 30}

// Bounds on the two files InspectWheel reads.
const (
	MaxMetadataBytes = 1 << 20  // the METADATA file
	MaxWheelBytes    = 64 << 10 // the WHEEL file
)

const (
	// maxShownChars cuts text from a wheel before it enters a reason.
	maxShownChars = 100
	// directoryEntryBytes is what one central directory record may take
	// besides its name: the 46-byte fixed part and room for extra fields
	// and a comment, which real wheels keep short.
	directoryEntryBytes = 46 + 512
	// directorySlack covers the reads that find the end of the directory,
	// 65 KiB at most, and the buffer that overshoots it.
	directorySlack = 128 << 10
)

// WheelInfo is what a wheel's own METADATA says it is.
type WheelInfo struct{ Name, Version string }

func (l WheelLimits) orDefault() WheelLimits {
	if l.Entries <= 0 {
		l.Entries = DefaultWheelLimits.Entries
	}
	if l.NameBytes <= 0 {
		l.NameBytes = DefaultWheelLimits.NameBytes
	}
	if l.Unpacked <= 0 {
		l.Unpacked = DefaultWheelLimits.Unpacked
	}
	return l
}

// errDirectory stops zip.NewReader once it has read more than the limits
// allow, before it holds every record of a forged directory in memory.
var errDirectory = errors.New("directory past its bound")

// directoryReader counts what zip.NewReader reads. Reads after the directory,
// those of METADATA and WHEEL, have their own bounds and are not counted.
type directoryReader struct {
	r    io.ReaderAt
	left int64
	read bool
}

func (d *directoryReader) ReadAt(p []byte, off int64) (int, error) {
	if !d.read {
		if int64(len(p)) > d.left {
			return 0, errDirectory
		}
		d.left -= int64(len(p))
	}
	return d.r.ReadAt(p, off)
}

// InspectWheel reads a wheel's zip directory, its METADATA and its WHEEL file
// and writes nothing. An error names the problem; text from the wheel is
// stripped of control characters and cut to 100 characters.
func InspectWheel(r io.ReaderAt, size int64, l WheelLimits) (WheelInfo, error) {
	l = l.orDefault()
	dir := &directoryReader{r: r, left: int64(l.Entries)*int64(directoryEntryBytes+l.NameBytes) + directorySlack}
	zr, err := zip.NewReader(dir, size)
	dir.read = true
	switch {
	case errors.Is(err, errDirectory):
		return WheelInfo{}, fmt.Errorf("the wheel's zip directory is larger than what %d entries with %d-byte names need", l.Entries, l.NameBytes)
	case errors.Is(err, zip.ErrInsecurePath):
		// The checks below name the entry the reader refused.
	case err != nil:
		return WheelInfo{}, errors.New("the wheel is not a zip archive")
	}
	if len(zr.File) > l.Entries {
		return WheelInfo{}, fmt.Errorf("the wheel holds more than %d entries", l.Entries)
	}
	if err := checkEntries(zr.File, l); err != nil {
		return WheelInfo{}, err
	}
	distInfo, err := findDistInfo(zr.File)
	if err != nil {
		return WheelInfo{}, err
	}

	metadata, err := readEntry(zr.File, distInfo, "METADATA", MaxMetadataBytes)
	if err != nil {
		return WheelInfo{}, err
	}
	info, err := parseMetadata(metadata)
	if err != nil {
		return WheelInfo{}, err
	}
	name, version, ok := strings.Cut(strings.TrimSuffix(distInfo, ".dist-info"), "-")
	if !ok || name == "" || version == "" {
		return WheelInfo{}, fmt.Errorf("the .dist-info directory \"%s\" is not named <name>-<version>.dist-info", shownText(distInfo))
	}
	if Normalize(name) != Normalize(info.Name) || !SameVersion(version, info.Version) {
		return WheelInfo{}, fmt.Errorf("the .dist-info directory \"%s\" does not match METADATA's %s %s", shownText(distInfo), shownText(info.Name), shownText(info.Version))
	}

	wheel, err := readEntry(zr.File, distInfo, "WHEEL", MaxWheelBytes)
	if err != nil {
		return WheelInfo{}, err
	}
	if err := checkWheelVersion(wheel); err != nil {
		return WheelInfo{}, err
	}
	return info, nil
}

// checkEntries refuses the first entry whose name could reach outside the
// directory a wheel installs into, or that breaks a bound. It opens nothing.
func checkEntries(files []*zip.File, l WheelLimits) error {
	seen := make(map[string]bool, len(files))
	limit := uint64(l.Unpacked) //nolint:gosec // orDefault keeps Unpacked positive
	var unpacked uint64
	for _, f := range files {
		name := f.Name
		shown := shownText(name)
		if len(name) > l.NameBytes {
			return fmt.Errorf("an entry name is longer than %d bytes: \"%s\"", l.NameBytes, shown)
		}
		if !utf8.ValidString(name) {
			return fmt.Errorf("entry \"%s\" is not valid UTF-8", shown)
		}
		if strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return fmt.Errorf("entry \"%s\" holds a control character", shown)
		}
		if strings.Contains(name, `\`) {
			return fmt.Errorf("entry \"%s\" holds a backslash", shown)
		}
		if strings.HasPrefix(name, "/") || hasDriveLetter(name) {
			return fmt.Errorf("entry \"%s\" is an absolute path", shown)
		}
		segments := strings.Split(strings.TrimSuffix(name, "/"), "/")
		if slices.Contains(segments, "..") {
			return fmt.Errorf("entry \"%s\" climbs to a parent directory", shown)
		}
		if slices.Contains(segments, "") || slices.Contains(segments, ".") {
			return fmt.Errorf("entry \"%s\" is not a clean path", shown)
		}
		if seen[name] {
			return fmt.Errorf("entry \"%s\" appears twice", shown)
		}
		seen[name] = true
		if f.UncompressedSize64 > limit-unpacked {
			return fmt.Errorf("the wheel's entries declare more than %d unpacked bytes", l.Unpacked)
		}
		unpacked += f.UncompressedSize64
	}
	return nil
}

func hasDriveLetter(name string) bool {
	return len(name) >= 2 && name[1] == ':' && ('a' <= name[0]|0x20 && name[0]|0x20 <= 'z')
}

// findDistInfo returns the one top-level directory whose name ends in
// .dist-info, as pip finds it.
func findDistInfo(files []*zip.File) (string, error) {
	var found []string
	for _, f := range files {
		top, _, _ := strings.Cut(f.Name, "/")
		if strings.HasSuffix(top, ".dist-info") && !slices.Contains(found, top) {
			found = append(found, top)
		}
	}
	switch len(found) {
	case 0:
		return "", errors.New("the wheel has no top-level .dist-info directory")
	case 1:
		return found[0], nil
	}
	slices.Sort(found)
	return "", fmt.Errorf("the wheel has two .dist-info directories: \"%s\" and \"%s\"", shownText(found[0]), shownText(found[1]))
}

// readEntry reads distInfo/file, refusing it past max bytes. The zip reader
// also refuses more data than the entry declares.
func readEntry(files []*zip.File, distInfo, file string, maxBytes int64) ([]byte, error) {
	i := slices.IndexFunc(files, func(f *zip.File) bool { return f.Name == distInfo+"/"+file })
	if i < 0 {
		if file == "WHEEL" {
			return nil, fmt.Errorf("the wheel has no WHEEL file in \"%s\"", shownText(distInfo))
		}
		return nil, fmt.Errorf("the wheel has no %s in \"%s\"", file, shownText(distInfo))
	}
	rc, err := files[i].Open()
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %s", file, shownText(err.Error()))
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %s", file, shownText(err.Error()))
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", file, maxBytes)
	}
	return data, nil
}

// headers reads the header block of a METADATA or WHEEL file, up to the first
// blank line, by lower-cased field name. A folded line joins the field above.
// pip reads these files with Python's email parser, which also ends a line at
// a bare carriage return and starts the body at the first line that is not a
// field. headers refuses both: either would let pip find other fields here.
func headers(file string, data []byte) (map[string][]string, error) {
	fields := map[string][]string{}
	var last string
	for line := range bytes.Lines(data) {
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if strings.Contains(text, "\r") {
			return nil, fmt.Errorf("%s holds a carriage return that does not end a line", file)
		}
		if text == "" {
			break
		}
		if text[0] == ' ' || text[0] == '\t' {
			if values := fields[last]; len(values) > 0 {
				values[len(values)-1] += " " + strings.TrimSpace(text)
			}
			continue
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok || !isFieldName(key) {
			return nil, fmt.Errorf("%s holds a header line that is not a field: \"%s\"", file, shownText(text))
		}
		last = strings.ToLower(key)
		// Python strips spaces and tabs only, so a form feed stays in the value.
		fields[last] = append(fields[last], strings.Trim(value, " \t"))
	}
	return fields, nil
}

// isFieldName reports whether key is a field name as RFC 5322 defines it:
// printable ASCII other than the colon, at least one character.
func isFieldName(key string) bool {
	if key == "" {
		return false
	}
	for i := range len(key) {
		if key[i] < '!' || key[i] > '~' {
			return false
		}
	}
	return true
}

func parseMetadata(data []byte) (WheelInfo, error) {
	fields, err := headers("METADATA", data)
	if err != nil {
		return WheelInfo{}, err
	}
	var info WheelInfo
	for _, f := range []struct {
		key, label string
		into       *string
	}{{"name", "Name", &info.Name}, {"version", "Version", &info.Version}} {
		switch values := fields[f.key]; len(values) {
		case 0:
			return WheelInfo{}, fmt.Errorf("METADATA has no %s field", f.label)
		case 1:
			*f.into = values[0]
		default:
			return WheelInfo{}, fmt.Errorf("METADATA has two %s fields", f.label)
		}
	}
	if !ValidName(info.Name) {
		return WheelInfo{}, fmt.Errorf("METADATA's Name \"%s\" is not a valid project name", shownText(info.Name))
	}
	if !IsExactVersion(info.Version) {
		return WheelInfo{}, fmt.Errorf("METADATA's Version \"%s\" is not an exact version", shownText(info.Version))
	}
	return info, nil
}

// checkWheelVersion accepts a Wheel-Version of major 1, as pip does: a later
// major may change the layout this reader relies on.
func checkWheelVersion(data []byte) error {
	fields, err := headers("WHEEL", data)
	if err != nil {
		return err
	}
	values := fields["wheel-version"]
	if len(values) == 0 {
		return errors.New("WHEEL has no Wheel-Version field")
	}
	major, minor, _ := strings.Cut(values[0], ".")
	if major != "1" || (minor != "" && !isDigits(minor)) {
		return fmt.Errorf("WHEEL's Wheel-Version \"%s\" is not 1.x, the only version this reader knows", shownText(values[0]))
	}
	return nil
}

func isDigits(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// shownText makes text from a wheel safe to quote: valid UTF-8, no control
// or format character, at most maxShownChars characters.
func shownText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > maxShownChars {
		s = string(r[:maxShownChars])
	}
	return s
}
