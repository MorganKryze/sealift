package archive_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
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
