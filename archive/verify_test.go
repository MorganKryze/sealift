package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	testKey      = "test-key"
	otherKey     = "other-key-value"
	sameLenKey   = "test-kez"
	alphaBody    = "alpha"
	betaBody     = "beta"
	alphaFile    = "alpha-1.0.0.tgz"
	betaFile     = "s-beta-2.0.0.tgz"
	otherSHA256  = "0000000000000000000000000000000000000000000000000000000000000000"
	otherSRISeed = "some other bytes"
)

type item struct {
	name     string
	typeflag byte
	body     string
	link     string
}

func reg(name, body string) item { return item{name: name, typeflag: tar.TypeReg, body: body} }

func baseItems() []item {
	return []item{
		{name: "out/", typeflag: tar.TypeDir},
		reg("out/"+alphaFile, alphaBody),
		reg("out/"+betaFile, betaBody),
		reg("out/signature.key", testKey),
	}
}

func build(t *testing.T, items []item) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, it := range items {
		h := &tar.Header{Name: it.name, Typeflag: it.typeflag, Mode: 0o644, Linkname: it.link}
		if it.typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if it.typeflag == tar.TypeReg {
			h.Size = int64(len(it.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if it.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(it.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sri(body string) string {
	sum := sha512.Sum512([]byte(body))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func shipped(body string) string {
	sum := sha512.Sum512([]byte(body))
	return hex.EncodeToString(sum[:])
}

// fixture is a valid archive, its manifest and its options. The manifest lists
// the scoped package first, so manifest order differs from archive order.
type fixture struct {
	data []byte
	m    Manifest
	opts VerifyOptions
}

func newFixture(t *testing.T, items []item) fixture {
	t.Helper()
	data := build(t, items)
	sum := sha256.Sum256(data)
	return fixture{
		data: data,
		m: Manifest{
			FormatVersion: 1, ToolVersion: "0.3.0", AnalysisID: "a1", CreatedAt: "2026-09-23T12:04:24Z",
			Target:  Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
			Archive: Summary{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))},
			Packages: []Package{
				{Name: "@s/beta", Version: "2.0.0", File: betaFile, OriginalIntegrity: sri(otherSRISeed), ShippedSHA512: shipped(betaBody), PublishConfigStripped: true},
				{Name: "alpha", Version: "1.0.0", File: alphaFile, OriginalIntegrity: sri(alphaBody), ShippedSHA512: shipped(alphaBody)},
			},
		},
		opts: VerifyOptions{SignatureKey: []byte(testKey), Dir: t.TempDir()},
	}
}

func (f fixture) verify() ([]Checked, error) {
	return Verify(bytes.NewReader(f.data), f.m, f.opts)
}

func without(items []item, name string) []item {
	return slices.DeleteFunc(slices.Clone(items), func(it item) bool { return it.name == name })
}

func replace(items []item, name string, with item) []item {
	items = slices.Clone(items)
	for i := range items {
		if items[i].name == name {
			items[i] = with
		}
	}
	return items
}

func TestVerifyRefuses(t *testing.T) {
	tests := []struct {
		name   string
		items  func() []item
		edit   func(f *fixture)
		reason string
	}{
		{name: "size", edit: func(f *fixture) { f.m.Archive.Size++ }, reason: "archive size"},
		{name: "size larger than declared", edit: func(f *fixture) { f.m.Archive.Size-- }, reason: "archive size"},
		{name: "sha256", edit: func(f *fixture) { f.m.Archive.SHA256 = otherSHA256 }, reason: "differs from the manifest"},
		{name: "expected sha256", edit: func(f *fixture) { f.opts.ExpectedSHA256 = otherSHA256 }, reason: "expected sha256"},
		{
			name:   "unlisted",
			items:  func() []item { return append(baseItems(), reg("out/extra.tgz", "x")) },
			reason: "out/extra.tgz is not listed",
		},
		{
			name:   "absent",
			items:  func() []item { return without(baseItems(), "out/"+alphaFile) },
			reason: alphaFile + " is absent",
		},
		{
			name:   "shipped sha512",
			items:  func() []item { return replace(baseItems(), "out/"+alphaFile, reg("out/"+alphaFile, "tampered")) },
			reason: alphaFile + " does not match its shipped sha512",
		},
		{
			name:   "original integrity",
			edit:   func(f *fixture) { f.m.Packages[1].OriginalIntegrity = sri(otherSRISeed) },
			reason: alphaFile + " does not match its original integrity",
		},
		{
			name:   "key absent",
			items:  func() []item { return without(baseItems(), "out/signature.key") },
			reason: "signature.key is absent",
		},
		{
			name:   "key differs",
			items:  func() []item { return replace(baseItems(), "out/signature.key", reg("out/signature.key", otherKey)) },
			reason: "signature.key differs",
		},
		{
			name:   "key of the same length",
			items:  func() []item { return replace(baseItems(), "out/signature.key", reg("out/signature.key", sameLenKey)) },
			reason: "signature.key differs",
		},
		{
			name: "key longer than the expected key",
			items: func() []item {
				return replace(baseItems(), "out/signature.key", reg("out/signature.key", testKey+"\n"))
			},
			reason: "signature.key differs",
		},
		{
			name: "key over 64 KiB",
			items: func() []item {
				return replace(baseItems(), "out/signature.key", reg("out/signature.key", strings.Repeat("k", 64<<10+1)))
			},
			reason: "signature.key is larger than",
		},
		{name: "no expected key", edit: func(f *fixture) { f.opts.SignatureKey = nil }, reason: "no expected signature key"},
		{
			name:   "not an archive",
			items:  func() []item { return nil },
			edit:   func(f *fixture) { f.data = []byte("plain text"); f.m.Archive = digestOf(f.data) },
			reason: "not a gzip-compressed tar",
		},
		{
			name:   "truncated",
			edit:   func(f *fixture) { f.data = f.data[:len(f.data)-20]; f.m.Archive = digestOf(f.data) },
			reason: "could not read the archive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := baseItems()
			if tt.items != nil {
				items = tt.items()
			}
			f := newFixture(t, items)
			if tt.edit != nil {
				tt.edit(&f)
			}
			_, err := f.verify()
			assertRefusal(t, err, tt.reason)
			assertNoKey(t, err)
		})
	}
}

func digestOf(data []byte) Summary {
	sum := sha256.Sum256(data)
	return Summary{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func assertNoKey(t *testing.T, err error) {
	t.Helper()
	for _, secret := range []string{testKey, otherKey, sameLenKey, base64.StdEncoding.EncodeToString([]byte(testKey)), hex.EncodeToString([]byte(testKey))} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("a refusal repeats a key value")
		}
	}
}

func TestVerifyRefusesEntries(t *testing.T) {
	long := strings.Repeat("n", 252) + ".tgz"
	tests := []struct {
		name   string
		items  func() []item
		limits Limits
		reason string
	}{
		{
			name:   "absolute",
			items:  func() []item { return replace(baseItems(), "out/"+alphaFile, reg("/out/"+alphaFile, alphaBody)) },
			reason: "absolute path",
		},
		{
			name:   "dot dot",
			items:  func() []item { return replace(baseItems(), "out/"+alphaFile, reg("out/../"+alphaFile, alphaBody)) },
			reason: "parent directory",
		},
		{
			name:   "dot dot out of the archive",
			items:  func() []item { return append(baseItems(), reg("out/../../etc/cron.d/x", "x")) },
			reason: "parent directory",
		},
		{
			name:   "outside out",
			items:  func() []item { return append(baseItems(), reg("other/"+alphaFile, alphaBody)) },
			reason: "outside out/",
		},
		{
			name:   "dot slash prefix",
			items:  func() []item { return replace(baseItems(), "out/"+alphaFile, reg("./out/"+alphaFile, alphaBody)) },
			reason: "outside out/",
		},
		{
			name:   "subdirectory file",
			items:  func() []item { return append(baseItems(), reg("out/sub/"+alphaFile, alphaBody)) },
			reason: "subdirectory",
		},
		{
			name: "symlink under a listed name",
			items: func() []item {
				return replace(baseItems(), "out/"+alphaFile, item{name: "out/" + alphaFile, typeflag: tar.TypeSymlink, link: "/etc/passwd"})
			},
			reason: "not a regular file",
		},
		{
			name: "hardlink under a listed name",
			items: func() []item {
				return replace(baseItems(), "out/"+alphaFile, item{name: "out/" + alphaFile, typeflag: tar.TypeLink, link: "out/" + betaFile})
			},
			reason: "not a regular file",
		},
		{
			name: "symlink under the key name",
			items: func() []item {
				return replace(baseItems(), "out/signature.key", item{name: "out/signature.key", typeflag: tar.TypeSymlink, link: "/etc/passwd"})
			},
			reason: "not a regular file",
		},
		{
			name:   "directory other than out",
			items:  func() []item { return append(baseItems(), item{name: "out/sub/", typeflag: tar.TypeDir}) },
			reason: "directory other than out/",
		},
		{
			name:   "duplicate entry",
			items:  func() []item { return append(baseItems(), reg("out/"+alphaFile, alphaBody)) },
			reason: "appears twice",
		},
		{
			name:   "duplicate out directory",
			items:  func() []item { return append(baseItems(), item{name: "out/", typeflag: tar.TypeDir}) },
			reason: "appears twice",
		},
		{name: "entries", items: baseItems, limits: Limits{Entries: 3}, reason: "more than 3 entries"},
		{name: "unpacked", items: baseItems, limits: Limits{Unpacked: 10}, reason: "more than 10 bytes unpacked"},
		{name: "name bytes", items: baseItems, limits: Limits{NameBytes: 10}, reason: "longer than 10 bytes"},
		{
			name:   "name bytes by default",
			items:  func() []item { return append(baseItems(), reg("out/"+long, "x")) },
			reason: "longer than 255 bytes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.items())
			f.opts.Limits = tt.limits
			_, err := f.verify()
			assertRefusal(t, err, tt.reason)
			assertNoKey(t, err)
		})
	}
}

// buildEnding is build with a last header that declares size bytes and ends
// the archive there, as an archive does when it lies about its entry.
func buildEnding(t *testing.T, items []item, last *tar.Header, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, it := range items {
		h := &tar.Header{Name: it.name, Typeflag: it.typeflag, Mode: 0o644}
		if it.typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if it.typeflag == tar.TypeReg {
			h.Size = int64(len(it.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(it.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	// A second writer emits the last header and stops short of its body.
	if err := tar.NewWriter(gz).WriteHeader(last); err != nil {
		t.Fatal(err)
	}
	if _, err := gz.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVerifyRefusesSizesThatOverflow(t *testing.T) {
	items := []item{{name: "out/", typeflag: tar.TypeDir}, reg("out/"+alphaFile, alphaBody)}
	tests := []struct {
		name string
		size int64
	}{
		{"largest size", math.MaxInt64},
		{"one past the room left", DefaultLimits.Unpacked - int64(len(alphaBody)) + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, baseItems())
			f.data = buildEnding(t, items, &tar.Header{Name: "out/" + betaFile, Typeflag: tar.TypeReg, Mode: 0o644, Size: tt.size}, []byte(betaBody))
			f.m.Archive = digestOf(f.data)
			_, err := f.verify()
			assertRefusal(t, err, "bytes unpacked")
			entries, _ := os.ReadDir(f.opts.Dir)
			for _, e := range entries {
				if e.Name() == betaFile {
					t.Errorf("%s was written before the bound refused it", betaFile)
				}
			}
		})
	}
}

// paxRecord is one "length key=value\n" record of a PAX extended header.
func paxRecord(key, value string) string {
	n := len(key) + len(value) + 3
	for {
		s := fmt.Sprintf("%d %s=%s\n", n, key, value)
		if len(s) == n {
			return s
		}
		n = len(s)
	}
}

// sparseArchive holds one PAX 1.0 sparse entry named name that expands to
// realsize bytes of zeros. The tar writer cannot emit one, so the extended
// header is a regular entry whose type flag and checksum are patched.
func sparseArchive(t *testing.T, name string, realsize int) []byte {
	t.Helper()
	records := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.name", name) + paxRecord("GNU.sparse.realsize", strconv.Itoa(realsize))
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: "out/PaxHeader", Typeflag: tar.TypeReg, Size: int64(len(records))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(records)); err != nil {
		t.Fatal(err)
	}
	// The sparse map is a block that lists no data segment.
	block := append([]byte("0\n"), make([]byte, 510)...)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(block))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(block); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	data := raw.Bytes()
	data[156] = tar.TypeXHeader
	for i := 148; i < 156; i++ {
		data[i] = ' '
	}
	sum := 0
	for _, c := range data[:512] {
		sum += int(c)
	}
	copy(data[148:], fmt.Sprintf("%06o\x00 ", sum))

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVerifyRefusesSparseEntries(t *testing.T) {
	f := newFixture(t, baseItems())
	f.data = sparseArchive(t, "out/"+alphaFile, 1<<20)
	f.m.Archive = digestOf(f.data)
	_, err := f.verify()
	assertRefusal(t, err, "is a sparse file")
}

// gzipped compresses tar bytes into one gzip member.
func gzipped(t *testing.T, tarBytes []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gunzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyRefusesADamagedGzipTrailer(t *testing.T) {
	f := newFixture(t, baseItems())
	// The last 8 bytes are the CRC-32 and the length of the content.
	f.data[len(f.data)-8] ^= 0xff
	f.m.Archive = digestOf(f.data)
	_, err := f.verify()
	assertRefusal(t, err, "invalid checksum")
}

func TestVerifyRefusesDataAfterTheTarEnd(t *testing.T) {
	tests := []struct {
		name  string
		extra func() []byte
	}{
		{"zeros beyond the padding", func() []byte { return make([]byte, maxTrailingBytes+1) }},
		{"entry after the end marker", func() []byte { return gunzipped(t, build(t, []item{reg("out/late.tgz", "x")})) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, baseItems())
			f.data = gzipped(t, append(gunzipped(t, f.data), tt.extra()...))
			f.m.Archive = digestOf(f.data)
			_, err := f.verify()
			assertRefusal(t, err, "after the end of the tar")
		})
	}
}

func TestVerifyRefusesAGzipMemberAfterTheFirst(t *testing.T) {
	f := newFixture(t, baseItems())
	f.data = append(f.data, gzipped(t, make([]byte, 4<<20))...)
	f.m.Archive = digestOf(f.data)
	_, err := f.verify()
	assertRefusal(t, err, "after the end of the tar")
}

func TestVerifyAcceptsTarPadding(t *testing.T) {
	f := newFixture(t, baseItems())
	f.data = gzipped(t, append(gunzipped(t, f.data), make([]byte, maxTrailingBytes)...))
	f.m.Archive = digestOf(f.data)
	if _, err := f.verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRefusesWritesNothingOutsideDir(t *testing.T) {
	f := newFixture(t, replace(baseItems(), "out/"+alphaFile, reg("out/../escape.tgz", alphaBody)))
	if _, err := f.verify(); err == nil {
		t.Fatal("want a refusal")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.opts.Dir), "escape.tgz")); err == nil {
		t.Error("an entry escaped the directory")
	}
}

func TestVerifyStrippedSkipsOriginalIntegrity(t *testing.T) {
	tests := []struct {
		name     string
		stripped bool
		reason   string
	}{
		{"stripped", true, ""},
		{"not stripped", false, "original integrity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, baseItems())
			f.m.Packages[1].OriginalIntegrity = sri(otherSRISeed)
			f.m.Packages[1].PublishConfigStripped = tt.stripped
			_, err := f.verify()
			if tt.reason == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestVerifyAccepts(t *testing.T) {
	f := newFixture(t, baseItems())
	f.opts.ExpectedSHA256 = strings.ToUpper(f.m.Archive.SHA256)

	got, err := f.verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got) != 2 || got[0].Package.File != betaFile || got[1].Package.File != alphaFile {
		t.Fatalf("checked = %+v, want the manifest order beta, alpha", got)
	}
	for i, body := range []string{betaBody, alphaBody} {
		c := got[i]
		if want := filepath.Join(f.opts.Dir, c.Package.File); c.Path != want {
			t.Errorf("path = %q, want %q", c.Path, want)
		}
		data, err := os.ReadFile(c.Path)
		if err != nil || string(data) != body {
			t.Errorf("%s holds %q (%v), want %q", c.Path, data, err, body)
		}
		info, err := os.Stat(c.Path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", c.Path, info.Mode().Perm())
		}
		if hex.EncodeToString(c.SHA512) != shipped(body) {
			t.Errorf("%s digest = %x, want %s", c.Path, c.SHA512, shipped(body))
		}
	}
	entries, err := os.ReadDir(f.opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("Dir holds %d files, want only the 2 packages", len(entries))
	}
}

func TestVerifyAcceptsAnArchiveWithoutTheDirectoryEntry(t *testing.T) {
	f := newFixture(t, without(baseItems(), "out/"))
	if _, err := f.verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyLocalFailureIsNotARefusal(t *testing.T) {
	f := newFixture(t, baseItems())
	f.opts.Dir = filepath.Join(f.opts.Dir, "missing")
	_, err := f.verify()
	if err == nil {
		t.Fatal("want an error")
	}
	var r *Refusal
	if errors.As(err, &r) {
		t.Errorf("a full or missing directory read as a refusal: %v", err)
	}
}

func TestVerifyDoesNotOverwrite(t *testing.T) {
	f := newFixture(t, baseItems())
	path := filepath.Join(f.opts.Dir, alphaFile)
	if err := os.WriteFile(path, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(); err == nil {
		t.Fatal("want an error")
	}
	if data, _ := os.ReadFile(path); string(data) != "planted" {
		t.Errorf("an existing file was overwritten: %q", data)
	}
}
