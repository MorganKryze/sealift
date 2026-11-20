package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
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
	Dir            string // absolute, existing, private directory that receives the tarballs
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
	// A relative directory would resolve against the working directory, which
	// a service does not control.
	if !filepath.IsAbs(opts.Dir) {
		return nil, errors.New("archive: Verify needs an absolute directory")
	}
	files := make([]expected, len(m.Packages))
	for i, p := range m.Packages {
		want, err := hex.DecodeString(p.ShippedSHA512)
		if err != nil {
			return nil, refuse("%s: shippedSha512 is not hex", p.File)
		}
		files[i] = expected{file: p.File, sha512: want, what: "original integrity"}
		if !p.PublishConfigStripped {
			files[i].newH, files[i].want, err = npm.ParseIntegrity(p.OriginalIntegrity)
			if err != nil {
				return nil, refuse("%s: originalIntegrity is not usable", p.File)
			}
		}
	}
	copies, err := verifyStream(r, m.Archive, files, opts)
	if err != nil {
		return nil, err
	}
	checked := make([]Checked, len(copies))
	for i, c := range copies {
		checked[i] = Checked{Package: m.Packages[i], Path: c.path, SHA512: c.sha512}
	}
	return checked, nil
}

// expected is one file an archive must hold under out/, with the digests its
// bytes must have.
type expected struct {
	file   string
	sha512 []byte
	newH   func() hash.Hash // nil when only the sha512 is checked
	want   []byte
	what   string // the second digest's name in a refusal: "original integrity" or "sha256"
}

// copied is a file that passed its digests, copied to path.
type copied struct {
	path   string
	sha512 []byte
}

// verifyStream reads an archive once and refuses it unless it matches sum and
// holds exactly files under out/, each with its digests. It returns the copies
// in the order of files. opts.Dir is absolute: the callers check it.
func verifyStream(r io.Reader, sum Summary, files []expected, opts VerifyOptions) ([]copied, error) {
	src := &trackedReader{r: io.LimitReader(r, sum.Size+1)}
	digest := sha256.New()
	var size int64
	tee := io.TeeReader(src, writerFunc(func(p []byte) (int, error) {
		size += int64(len(p))
		return digest.Write(p)
	}))

	copies, scanErr := scan(tee, files, opts)
	// A damaged archive is named by its digest, so read to the end first.
	if _, err := io.Copy(io.Discard, tee); err != nil && src.err == nil {
		src.err = err
	}
	if src.err != nil {
		return nil, fmt.Errorf("read the archive: %w", src.err)
	}
	if size != sum.Size {
		return nil, refuse("archive size is %d bytes, the manifest says %d", size, sum.Size)
	}
	got := hex.EncodeToString(digest.Sum(nil))
	if got != sum.SHA256 {
		return nil, refuse("archive sha256 %s differs from the manifest's %s", got, sum.SHA256)
	}
	if opts.ExpectedSHA256 != "" && got != strings.ToLower(opts.ExpectedSHA256) {
		return nil, refuse("archive sha256 %s differs from the expected sha256 %s", got, strings.ToLower(opts.ExpectedSHA256))
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return copies, nil
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

func scan(r io.Reader, files []expected, opts VerifyOptions) ([]copied, error) {
	limits := opts.Limits.orDefault()
	listed := make(map[string]int, len(files))
	for i, e := range files {
		listed[e.file] = i
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

	copies := make([]copied, len(files))
	done := make([]bool, len(files))
	seen := map[string]bool{}
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
		i, ok := listed[file]
		if !ok {
			return nil, refuse("%s is not listed in the manifest", shown(h.Name))
		}
		c, err := copyFile(tr, files[i], opts.Dir)
		if err != nil {
			return nil, err
		}
		copies[i], done[i] = c, true
	}
	if err := checkTrailing(gz); err != nil {
		return nil, err
	}

	for i, ok := range done {
		if !ok {
			return nil, refuse("%s is absent from the archive", files[i].file)
		}
	}
	return copies, nil
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

// copyFile writes one expected file into dir while hashing it.
func copyFile(r io.Reader, e expected, dir string) (copied, error) {
	path := filepath.Join(dir, e.file)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return copied{}, fmt.Errorf("copy %s: %w", e.file, err)
	}
	shipped := sha512.New()
	writers := []io.Writer{shipped}
	var second hash.Hash
	if e.newH != nil {
		second = e.newH()
		writers = append(writers, second)
	}
	local := &trackedWriter{w: f}
	_, copyErr := io.Copy(io.MultiWriter(append(writers, local)...), r)
	closeErr := f.Close()
	if local.err != nil {
		return copied{}, fmt.Errorf("copy %s: %w", e.file, local.err)
	}
	if copyErr != nil {
		return copied{}, readRefusal(copyErr)
	}
	if closeErr != nil {
		return copied{}, fmt.Errorf("copy %s: %w", e.file, closeErr)
	}
	sum := shipped.Sum(nil)
	if !bytes.Equal(sum, e.sha512) {
		return copied{}, refuse("%s does not match its shipped sha512", e.file)
	}
	if second != nil && !bytes.Equal(second.Sum(nil), e.want) {
		return copied{}, refuse("%s does not match its %s", e.file, e.what)
	}
	return copied{path: path, sha512: sum}, nil
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
