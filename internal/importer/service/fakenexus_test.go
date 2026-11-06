package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/nexus"
	"github.com/MorganKryze/sealift/npm"
)

const (
	testRepo     = "npm-hosted"
	testPassword = "test-password"
	testSigKey   = "test-signature-key"
	testMinioKey = "test-minio-secret"
)

// testPkg is one package of a test archive.
type testPkg struct{ name, version string }

// testBundle is an archive and its manifest as they sit in MinIO.
type testBundle struct {
	archive, manifest []byte
	sha256            string
	pkgs              []testPkg
}

func tarballOf(t *testing.T, name, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	pj, _ := json.Marshal(map[string]string{"name": name, "version": version})
	for _, f := range []struct{ name, body string }{{"package/package.json", string(pj)}, {"package/index.js", "module.exports = 1"}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
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

func opener(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

// buildBundle makes a signed archive of the packages and its manifest.json.
func buildBundle(t *testing.T, pkgs ...testPkg) testBundle {
	t.Helper()
	entries := []archive.Entry{{Name: "signature.key", Size: int64(len(testSigKey)), Open: opener([]byte(testSigKey))}}
	var listed []map[string]any
	for _, p := range pkgs {
		body := tarballOf(t, p.name, p.version)
		file := npm.PackFileName(p.name, p.version)
		sum := sha512.Sum512(body)
		entries = append(entries, archive.Entry{Name: file, Size: int64(len(body)), Open: opener(body)})
		listed = append(listed, map[string]any{
			"name": p.name, "version": p.version, "file": file,
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
		"formatVersion": 1, "toolVersion": "0.3.0", "analysisId": "20260923T120255Z", "createdAt": "2026-09-23T12:04:24Z",
		"target":   map[string]any{"os": "linux", "cpu": "x64", "libc": "glibc", "node": "22.17.1", "pnpmVer": "10.34.5"},
		"archive":  map[string]any{"sha256": hex.EncodeToString(digest[:]), "size": buf.Len()},
		"packages": listed,
	}
	mb, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return testBundle{archive: buf.Bytes(), manifest: mb, sha256: hex.EncodeToString(digest[:]), pkgs: pkgs}
}

// fakeNexus answers what the Nexus client asks: the repository check, a
// tarball read and an upload. An upload is served back at its package path.
type fakeNexus struct {
	srv *httptest.Server
	mu  sync.Mutex

	byFile   map[string]string // upload file name to the path it is served at
	tarballs map[string][]byte
	uploads  int
}

// newFakeNexus serves the packages over TLS; the returned file is the CA that trusts it.
func newFakeNexus(t *testing.T, pkgs ...testPkg) (*fakeNexus, string) {
	t.Helper()
	f := &fakeNexus{byFile: map[string]string{}, tarballs: map[string][]byte{}}
	for _, p := range pkgs {
		f.byFile[npm.PackFileName(p.name, p.version)] = npm.TarballURL("/repository/"+testRepo, p.name, p.version)
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	ca := filepath.Join(t.TempDir(), "nexus-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return f, ca
}

func (f *fakeNexus) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/service/rest/v1/repositories":
		_, _ = io.WriteString(w, `[{"name":"`+testRepo+`","format":"npm","type":"hosted"}]`)
	case r.URL.Path == "/service/rest/v1/components" && r.Method == http.MethodPost:
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			body, _ := io.ReadAll(part)
			f.mu.Lock()
			if path, ok := f.byFile[part.FileName()]; ok {
				f.tarballs[path] = body
				f.uploads++
			}
			f.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet:
		f.mu.Lock()
		body, ok := f.tarballs[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeNexus) uploadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.uploads
}

// settings are the import settings that point at the fake, trusted through caFile.
func (f *fakeNexus) settings(t *testing.T, caFile string) importer.Settings {
	t.Helper()
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return importer.Settings{
		NexusURL: u, Repository: testRepo, User: "sealift-import", Password: importer.Secret(testPassword),
		CAFile: caFile, SignatureKey: importer.Secret(testSigKey),
		MinIO: &importer.MinIOSettings{AccessKey: importer.Secret("test-access-id"), SecretKey: importer.Secret(testMinioKey)},
	}
}

func newPublisher(s importer.Settings) (importer.Publisher, error) {
	c, err := nexus.New(nexus.Config{URL: s.NexusURL, Repository: s.Repository, User: s.User, Password: s.Password, CAFile: s.CAFile})
	if err != nil {
		return nil, err
	}
	return c, nil
}
