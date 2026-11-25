package importer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/npm"
)

// testPub and testPriv are the key pair of this test run: every fixture is
// signed with testPriv and every settings value trusts testPub.
var testPub, testPriv = newTestKey()

var testPubSHA = archive.PublicKeySHA256(testPub)

// testPrivPEM is testPriv as a PKCS#8 PEM block, and privateKeyBody its base64 line:
// no error or report may repeat either.
var testPrivPEM, privateKeyBody = func() ([]byte, string) {
	der, err := x509.MarshalPKCS8PrivateKey(testPriv)
	if err != nil {
		panic(err)
	}
	text := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return text, strings.Split(string(text), "\n")[1]
}()

// wrongSHA256 is a well-formed sha256 no archive of these tests has.
const wrongSHA256 = "abababababababababababababababababababababababababababababababab"

func newTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// signManifest writes manifestPath+".sig" for the file's current bytes. A test
// that edits a manifest calls it again, or its edit would show as a changed
// signature instead of the refusal it provokes.
func signManifest(t *testing.T, manifestPath string) {
	t.Helper()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := archive.SignatureFor(testPubSHA, ed25519.Sign(testPriv, data))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// testArchive writes packages_npm.tar.gz, manifest.json and its signature for the given
// name@version to body pairs and returns their paths.
func testArchive(t *testing.T, dir string, pkgs ...[3]string) (arch, manifest string) {
	t.Helper()
	var entries []archive.Entry
	var listed []map[string]any
	for _, p := range pkgs {
		name, version := p[0], p[1]
		body := string(packed(t, name, version, p[2]))
		file, err := npm.PackFileName(name, version)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha512.Sum512([]byte(body))
		entries = append(entries, archive.Entry{Name: file, Size: int64(len(body)), Open: opener(body)})
		listed = append(listed, map[string]any{
			"name": name, "version": version, "file": file,
			"originalIntegrity":     "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
			"shippedSha512":         hex.EncodeToString(sum[:]),
			"publishConfigStripped": false,
		})
	}
	var buf bytes.Buffer
	if err := archive.WriteTarGz(&buf, "out", entries); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buf.Bytes())
	doc := map[string]any{
		"formatVersion": 2, "toolVersion": "0.3.0", "analysisId": "20260923T120255Z", "createdAt": "2026-09-23T12:04:24Z",
		"target":   map[string]any{"os": "linux", "cpu": "x64", "libc": "glibc", "node": "22.17.1", "pnpmVer": "10.34.5"},
		"archive":  map[string]any{"sha256": hex.EncodeToString(digest[:]), "size": buf.Len()},
		"packages": listed,
	}
	mb, _ := json.Marshal(doc)
	arch, manifest = filepath.Join(dir, "packages_npm.tar.gz"), filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(arch, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, mb, 0o600); err != nil {
		t.Fatal(err)
	}
	signManifest(t, manifest)
	return arch, manifest
}

// tarEntry is one file of a test tarball.
type tarEntry struct{ name, body string }

// packEntries returns a gzip-compressed tarball of the given regular files.
func packEntries(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	return packEntriesAt(t, gzip.DefaultCompression, entries...)
}

// packEntriesAt is packEntries with a gzip level; gzip.NoCompression makes
// the size depend only on the entries, not on their order.
func packEntriesAt(t *testing.T, level int, entries ...tarEntry) []byte {
	t.Helper()
	return packEntriesThen(t, level, nil, entries...)
}

// packEntriesThen is packEntriesAt with raw bytes written into the gzip
// stream after the tar end marker.
func packEntriesThen(t *testing.T, level int, after []byte, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := gz.Write(after); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tarBytes returns an uncompressed tar stream of the given regular files,
// end marker included.
func tarBytes(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// packed returns a valid tarball of name@version whose index.js holds body.
func packed(t *testing.T, name, version, body string) []byte {
	t.Helper()
	manifest, _ := jsonOf(map[string]string{"name": name, "version": version})
	return packEntries(t, tarEntry{"package/package.json", manifest}, tarEntry{"package/index.js", body})
}

func opener(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader([]byte(s))), nil }
}
