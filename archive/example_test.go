package archive_test

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
	"os"
	"strings"

	"github.com/MorganKryze/sealift/archive"
)

func ExampleWriteTarGz() {
	key := "import-secret"
	entries := []archive.Entry{{
		Name: "signature.key",
		Size: int64(len(key)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(key)), nil },
	}}

	var buf bytes.Buffer
	if err := archive.WriteTarGz(&buf, "out", entries); err != nil {
		panic(err)
	}

	gz, _ := gzip.NewReader(&buf)
	tr := tar.NewReader(gz)
	for h, err := tr.Next(); err == nil; h, err = tr.Next() {
		fmt.Println(h.Name)
	}
	// Output:
	// out/
	// out/signature.key
}

func ExampleVerify() {
	tarball := "package bytes"
	sum := sha512.Sum512([]byte(tarball))
	entries := []archive.Entry{
		{Name: "left-pad-1.3.0.tgz", Size: int64(len(tarball)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(tarball)), nil
		}},
		{Name: "signature.key", Size: 10, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("import-key")), nil
		}},
	}
	var buf bytes.Buffer
	if err := archive.WriteTarGz(&buf, "out", entries); err != nil {
		panic(err)
	}
	digest := sha256.Sum256(buf.Bytes())

	m := archive.Manifest{
		FormatVersion: 1, ToolVersion: "0.3.0", AnalysisID: "20260923T120255Z", CreatedAt: "2026-09-23T12:04:24Z",
		Target:  archive.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"},
		Archive: archive.Summary{SHA256: hex.EncodeToString(digest[:]), Size: int64(buf.Len())},
		Packages: []archive.Package{{
			Name: "left-pad", Version: "1.3.0", File: "left-pad-1.3.0.tgz",
			OriginalIntegrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
			ShippedSHA512:     hex.EncodeToString(sum[:]),
		}},
	}

	dir, err := os.MkdirTemp("", "verify")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	checked, err := archive.Verify(&buf, m, archive.VerifyOptions{SignatureKey: []byte("import-key"), Dir: dir})
	if err != nil {
		panic(err)
	}
	for _, c := range checked {
		fmt.Println(c.Package.Name, c.Package.Version)
	}

	_, err = archive.Verify(strings.NewReader("not an archive"), m, archive.VerifyOptions{SignatureKey: []byte("import-key"), Dir: dir})
	var refusal *archive.Refusal
	fmt.Println(errors.As(err, &refusal))
	// Output:
	// left-pad 1.3.0
	// true
}
