package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/MorganKryze/sealift/npm"
)

const (
	// root is the one directory an archive holds, written as sealift writes it.
	root = "out/"
	// keyEntry is the signature key's entry name below root.
	keyEntry = "signature.key"
	// maxKeySize is the most Verify reads of the archive's signature key: 64 KiB.
	maxKeySize = 64 << 10
	// maxTrailingBytes is the most zero padding Verify accepts after the tar
	// end marker: 16 KiB, above the 10 KiB record padding of GNU tar.
	maxTrailingBytes = 16 << 10
	// entryOverhead is the tar framing Verify allows each entry on top of its
	// content: 4 KiB covers the header block, the padding of the content and
	// the PAX path header a name over 100 bytes needs.
	entryOverhead = 4 << 10
	// tarEndBytes is the tar end marker: two zero blocks of 512 bytes.
	tarEndBytes = 1 << 10
	// sparsePrefix starts the PAX records of a sparse file, which the tar
	// reader expands into zeros far beyond the bytes the archive holds.
	sparsePrefix = "GNU.sparse."
)

// Limits bounds what an archive may hold. A zero field takes its default.
type Limits struct {
	Entries   int   // entries, the directory included
	Unpacked  int64 // bytes of file content
	NameBytes int   // bytes in one entry name
}

// DefaultLimits are the bounds of the tool the import replaces, so no archive
// it accepted is refused: 10,000 entries, 10 GiB unpacked, 255-byte names.
var DefaultLimits = Limits{Entries: 10000, Unpacked: 10 << 30, NameBytes: 255}

func (l Limits) orDefault() Limits {
	if l.Entries <= 0 {
		l.Entries = DefaultLimits.Entries
	}
	if l.Unpacked <= 0 {
		l.Unpacked = DefaultLimits.Unpacked
	}
	if l.NameBytes <= 0 {
		l.NameBytes = DefaultLimits.NameBytes
	}
	return l
}

// streamBound is the most inflated tar data an archive within l may hold:
// its content, the framing of each entry with a name of NameBytes, and the
// end marker. It saturates at the largest int64.
func (l Limits) streamBound() int64 {
	perEntry := entryOverhead + int64(l.NameBytes)
	if int64(l.Entries) > (math.MaxInt64-tarEndBytes)/perEntry {
		return math.MaxInt64
	}
	framing := int64(l.Entries)*perEntry + tarEndBytes
	if l.Unpacked > math.MaxInt64-framing {
		return math.MaxInt64
	}
	return l.Unpacked + framing
}

// boundedReader passes on at most left bytes and fails with err at the next
// one. The tar reader folds any number of consecutive extended and long-name
// headers, up to 1 MiB each, into a single call to Next, so neither the entry
// count nor the declared sizes see the inflation they cause.
type boundedReader struct {
	r    io.Reader
	left int64
	err  error
}

func (b *boundedReader) Read(p []byte) (int, error) {
	// Read one byte past the limit to tell the end of the data from more of it.
	if int64(len(p)) > b.left {
		p = p[:b.left+1]
	}
	n, err := b.r.Read(p)
	if int64(n) > b.left {
		n, err = int(b.left), b.err
	}
	b.left -= int64(n)
	return n, err
}

// readRefusal names why reading the archive's tar data failed: a refusal from
// the reader below, such as the bound on the inflated stream, or the error.
func readRefusal(err error) error {
	var r *Refusal
	if errors.As(err, &r) {
		return r
	}
	return refuse("could not read the archive: %v", err)
}

// VerifyOptions tell Verify what to expect and where to put the tarballs.
type VerifyOptions struct {
	ExpectedSHA256 string // hex sha256 received through a separate channel; empty skips the check
	SignatureKey   []byte // expected content of out/signature.key; the caller trims its newline
	Dir            string // existing private directory that receives the tarballs
	Limits         Limits
}

// Checked is a tarball that passed every check, copied to Path.
type Checked struct {
	Package Package
	Path    string
	SHA512  []byte
}

// Verify reads a packages_npm.tar.gz once and refuses it unless it matches m
// and opts. It copies each listed tarball into opts.Dir (mode 0600, never
// over an existing file) and returns them in manifest order. A *Refusal names
// the first problem, with a damaged digest or size taking precedence; any
// other error is a local failure. Files already copied stay in Dir after an
// error, for the caller to remove.
func Verify(r io.Reader, m Manifest, opts VerifyOptions) ([]Checked, error) {
	if len(opts.SignatureKey) == 0 {
		return nil, refuse("no expected signature key was given")
	}
	src := &trackedReader{r: io.LimitReader(r, m.Archive.Size+1)}
	sum := sha256.New()
	var size int64
	tee := io.TeeReader(src, writerFunc(func(p []byte) (int, error) {
		size += int64(len(p))
		return sum.Write(p)
	}))

	checked, scanErr := scan(tee, m, opts)
	// A damaged archive is named by its digest, so read to the end first.
	if _, err := io.Copy(io.Discard, tee); err != nil && src.err == nil {
		src.err = err
	}
	if src.err != nil {
		return nil, fmt.Errorf("read the archive: %w", src.err)
	}
	if size != m.Archive.Size {
		return nil, refuse("archive size is %d bytes, the manifest says %d", size, m.Archive.Size)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if got != m.Archive.SHA256 {
		return nil, refuse("archive sha256 %s differs from the manifest's %s", got, m.Archive.SHA256)
	}
	if opts.ExpectedSHA256 != "" && got != strings.ToLower(opts.ExpectedSHA256) {
		return nil, refuse("archive sha256 %s differs from the expected sha256 %s", got, strings.ToLower(opts.ExpectedSHA256))
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return checked, nil
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// trackedReader remembers a failure of the underlying reader, which is local,
// apart from a gzip or tar error, which is the archive's.
type trackedReader struct {
	r   io.Reader
	err error
}

func (t *trackedReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF && t.err == nil {
		t.err = err
	}
	return n, err
}

// shown quotes a name from the archive when it holds anything unprintable.
func shown(s string) string {
	if q := strconv.Quote(s); q[1:len(q)-1] == s {
		return s
	}
	return strconv.Quote(s)
}

type pending struct {
	pkg   Package
	index int
	want  []byte
	sri   []byte
	newH  func() hash.Hash
}

func scan(r io.Reader, m Manifest, opts VerifyOptions) ([]Checked, error) {
	limits := opts.Limits.orDefault()
	listed := make(map[string]*pending, len(m.Packages))
	for i, p := range m.Packages {
		want, err := hex.DecodeString(p.ShippedSHA512)
		if err != nil {
			return nil, refuse("%s: shippedSha512 is not hex", p.File)
		}
		pend := &pending{pkg: p, index: i, want: want}
		if !p.PublishConfigStripped {
			pend.newH, pend.sri, err = npm.ParseIntegrity(p.OriginalIntegrity)
			if err != nil {
				return nil, refuse("%s: originalIntegrity is not usable", p.File)
			}
		}
		listed[p.File] = pend
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return nil, refuse("the archive is not a gzip-compressed tar")
		}
		return nil, refuse("could not read the archive: %v", err)
	}
	defer gz.Close()
	bound := limits.streamBound()
	tooMuch := refuse("the archive holds more than %d bytes of tar data, the most %d entries and %d bytes of content need", bound, limits.Entries, limits.Unpacked)
	tr := tar.NewReader(&boundedReader{r: gz, left: bound, err: tooMuch})

	checked := make([]Checked, len(m.Packages))
	done := make([]bool, len(m.Packages))
	seen := map[string]bool{}
	keySeen := false
	var unpacked int64
	for n := 1; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, readRefusal(err)
		}
		if n > limits.Entries {
			return nil, refuse("the archive holds more than %d entries", limits.Entries)
		}
		if len(h.Name) > limits.NameBytes {
			return nil, refuse("an entry name is longer than %d bytes", limits.NameBytes)
		}
		if err := checkEntryName(h, seen); err != nil {
			return nil, err
		}
		seen[h.Name] = true
		if h.Typeflag == tar.TypeDir {
			continue
		}
		for key := range h.PAXRecords {
			if strings.HasPrefix(key, sparsePrefix) {
				return nil, refuse("entry %s is a sparse file", shown(h.Name))
			}
		}
		// Compare before adding: a size near MaxInt64 would wrap the sum.
		if h.Size > limits.Unpacked-unpacked {
			return nil, refuse("the archive holds more than %d bytes unpacked", limits.Unpacked)
		}
		unpacked += h.Size
		file := strings.TrimPrefix(h.Name, root)
		if file == keyEntry {
			if err := checkKey(tr, opts.SignatureKey); err != nil {
				return nil, err
			}
			keySeen = true
			continue
		}
		pend, ok := listed[file]
		if !ok {
			return nil, refuse("%s is not listed in the manifest", shown(h.Name))
		}
		c, err := copyPackage(tr, pend, opts.Dir)
		if err != nil {
			return nil, err
		}
		checked[pend.index], done[pend.index] = c, true
	}
	if err := checkTrailing(gz); err != nil {
		return nil, err
	}

	for i, ok := range done {
		if !ok {
			return nil, refuse("%s is absent from the archive", m.Packages[i].File)
		}
	}
	if !keySeen {
		return nil, refuse("%s is absent from the archive", keyEntry)
	}
	return checked, nil
}

// checkTrailing reads what follows the tar end marker, which also reaches the
// gzip trailer and its checksum. Only zero padding is accepted, and reading
// stops at the bound, so appended data costs no more than maxTrailingBytes of
// inflation.
func checkTrailing(gz io.Reader) error {
	rest, err := io.ReadAll(io.LimitReader(gz, maxTrailingBytes+1))
	if err != nil {
		return refuse("could not read the archive: %v", err)
	}
	if len(rest) > maxTrailingBytes || slices.ContainsFunc(rest, func(b byte) bool { return b != 0 }) {
		return refuse("the archive holds more than %d bytes of zero padding after the end of the tar", maxTrailingBytes)
	}
	return nil
}

// checkEntryName accepts only the directory out/ and regular files directly
// below it, each once.
func checkEntryName(h *tar.Header, seen map[string]bool) error {
	name := shown(h.Name)
	if strings.HasPrefix(h.Name, "/") {
		return refuse("entry %s is an absolute path", name)
	}
	if slices.Contains(strings.Split(h.Name, "/"), "..") {
		return refuse("entry %s climbs to a parent directory", name)
	}
	if seen[h.Name] {
		return refuse("entry %s appears twice", name)
	}
	if h.Name == root {
		if h.Typeflag != tar.TypeDir {
			return refuse("entry %s is not a directory", name)
		}
		return nil
	}
	if !strings.HasPrefix(h.Name, root) {
		return refuse("entry %s lies outside out/", name)
	}
	rest := strings.TrimPrefix(h.Name, root)
	switch {
	case h.Typeflag == tar.TypeDir:
		return refuse("entry %s is a directory other than out/", name)
	case strings.Contains(rest, "/"):
		return refuse("entry %s lies in a subdirectory of out/", name)
	case h.Typeflag != tar.TypeReg:
		return refuse("entry %s is not a regular file", name)
	}
	return nil
}

func checkKey(r io.Reader, want []byte) error {
	got, err := io.ReadAll(io.LimitReader(r, maxKeySize+1))
	if err != nil {
		return readRefusal(err)
	}
	if len(got) > maxKeySize {
		return refuse("%s is larger than %d bytes", keyEntry, maxKeySize)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return refuse("%s differs from the expected value", keyEntry)
	}
	return nil
}

// copyPackage writes one tarball into dir while hashing it.
func copyPackage(r io.Reader, p *pending, dir string) (Checked, error) {
	path := filepath.Join(dir, p.pkg.File)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Checked{}, fmt.Errorf("copy %s: %w", p.pkg.File, err)
	}
	shipped := sha512.New()
	writers := []io.Writer{shipped}
	var original hash.Hash
	if p.newH != nil {
		original = p.newH()
		writers = append(writers, original)
	}
	local := &trackedWriter{w: f}
	_, copyErr := io.Copy(io.MultiWriter(append(writers, local)...), r)
	closeErr := f.Close()
	if local.err != nil {
		return Checked{}, fmt.Errorf("copy %s: %w", p.pkg.File, local.err)
	}
	if copyErr != nil {
		return Checked{}, readRefusal(copyErr)
	}
	if closeErr != nil {
		return Checked{}, fmt.Errorf("copy %s: %w", p.pkg.File, closeErr)
	}
	sum := shipped.Sum(nil)
	if !bytes.Equal(sum, p.want) {
		return Checked{}, refuse("%s does not match its shipped sha512", p.pkg.File)
	}
	if original != nil && !bytes.Equal(original.Sum(nil), p.sri) {
		return Checked{}, refuse("%s does not match its original integrity", p.pkg.File)
	}
	return Checked{Package: p.pkg, Path: path, SHA512: sum}, nil
}

type trackedWriter struct {
	w   io.Writer
	err error
}

func (t *trackedWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if err != nil && t.err == nil {
		t.err = err
	}
	return n, err
}
