package importer

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/npm"
)

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// testArchive writes packages_npm.tar.gz and manifest.json for the given
// name@version to body pairs and returns their paths.
func testArchive(t *testing.T, dir, key string, pkgs ...[3]string) (arch, manifest string) {
	t.Helper()
	entries := []archive.Entry{{Name: "signature.key", Size: int64(len(key)), Open: opener(key)}}
	var listed []map[string]any
	for _, p := range pkgs {
		name, version, body := p[0], p[1], p[2]
		file := npm.PackFileName(name, version)
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
		"formatVersion": 1, "toolVersion": "0.3.0", "analysisId": "20260923T120255Z", "createdAt": "2026-09-23T12:04:24Z",
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
	return arch, manifest
}

func opener(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader([]byte(s))), nil }
}
