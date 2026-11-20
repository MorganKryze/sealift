// Package importtest builds the files the import reads, for tests: wheels in
// memory and signed pip archives. Import it from _test.go files only.
package importtest

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/report"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// WheelFile is one wheel a pip archive carries.
type WheelFile struct {
	Name, Version, File string // Name as the manifest lists it
	Body                []byte
}

// Entry is one extra file of a wheel.
type Entry struct {
	Name string
	Body []byte
}

// Wheel builds a valid wheel in memory: <dist>-<version>.dist-info/ with
// METADATA, WHEEL and RECORD, plus extra entries.
func Wheel(t testing.TB, name, version, tags string, extra ...Entry) WheelFile {
	t.Helper()
	dist := strings.ReplaceAll(pip.Normalize(name), "-", "_")
	info := dist + "-" + version + ".dist-info/"
	purelib := strings.HasSuffix(tags, "-none-any")
	entries := append([]Entry{{Name: dist + "/__init__.py", Body: []byte("__version__ = \"" + version + "\"\n")}}, extra...)
	entries = append(entries,
		Entry{Name: info + "METADATA", Body: []byte("Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n\n")},
		Entry{Name: info + "WHEEL", Body: fmt.Appendf(nil, "Wheel-Version: 1.0\nGenerator: importtest\nRoot-Is-Purelib: %t\nTag: %s\n", purelib, tags)},
	)
	var record strings.Builder
	for _, e := range entries {
		sum := sha256.Sum256(e.Body)
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", e.Name, base64.RawURLEncoding.EncodeToString(sum[:]), len(e.Body))
	}
	record.WriteString(info + "RECORD,,\n")
	entries = append(entries, Entry{Name: info + "RECORD", Body: []byte(record.String())})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.Name, Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.Body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return WheelFile{Name: pip.Normalize(name), Version: version, File: fmt.Sprintf("%s-%s-%s.whl", dist, version, tags), Body: buf.Bytes()}
}

// PipFiles are the three files of a pip export.
type PipFiles struct{ Archive, Manifest, Signature string }

// PipArchive writes packages_pip.tar.gz, manifest.json (format 3, target
// python 3.11.2 linux x86_64 glibc 2.28) and manifest.json.sig into dir.
func PipArchive(t testing.TB, dir string, key ed25519.PrivateKey, wheels ...WheelFile) PipFiles {
	t.Helper()
	f := PipFiles{
		Archive:   filepath.Join(dir, archive.PipArchiveFile),
		Manifest:  filepath.Join(dir, "manifest.json"),
		Signature: filepath.Join(dir, archive.SignatureFile),
	}
	entries := make([]archive.Entry, len(wheels))
	listed := make([]report.WheelEntry, len(wheels))
	for i, w := range wheels {
		body := w.Body
		entries[i] = archive.Entry{Name: w.File, Size: int64(len(body)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}}
		index, shipped := sha256.Sum256(body), sha512.Sum512(body)
		listed[i] = report.WheelEntry{
			Name: w.Name, Version: w.Version, File: w.File,
			SHA256: hex.EncodeToString(index[:]), ShippedSHA512: hex.EncodeToString(shipped[:]),
		}
	}
	var tgz bytes.Buffer
	if err := archive.WriteTarGz(&tgz, "out", entries); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tgz.Bytes())
	writeFile(t, f.Archive, tgz.Bytes())

	m := report.PipManifest{
		FormatVersion: report.PipManifestFormatVersion,
		Ecosystem:     store.Pip,
		ToolVersion:   "0.7.0",
		AnalysisID:    "20261120T091500Z",
		CreatedAt:     time.Date(2026, 11, 20, 9, 17, 42, 0, time.UTC),
		Target:        store.DefaultPipTarget,
		Archive:       report.ArchiveManifest{SHA256: hex.EncodeToString(sum[:]), Size: int64(tgz.Len())},
		Packages:      listed,
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeSigned(t, f, key, data)
	return f
}

// EditManifest rewrites the manifest through edit and signs it again with key.
func EditManifest(t testing.TB, f PipFiles, key ed25519.PrivateKey, edit func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(f.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	data, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeSigned(t, f, key, data)
}

// writeSigned writes the manifest and the signature of those exact bytes.
func writeSigned(t testing.TB, f PipFiles, key ed25519.PrivateKey, manifest []byte) {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("the signing key is not an Ed25519 key")
	}
	sig, err := archive.SignatureFor(archive.PublicKeySHA256(pub), ed25519.Sign(key, manifest))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.Manifest, manifest)
	writeFile(t, f.Signature, sig)
}

func writeFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
