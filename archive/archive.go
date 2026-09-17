// Package archive writes reproducible tar.gz archives: for a given build of
// sealift, the same entries always give the same bytes.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Entry is one file of an archive.
type Entry struct {
	Name string // path below the root directory, such as "express-4.21.2.tgz"
	Size int64
	Open func() (io.ReadCloser, error)
}

// WriteTarGz writes a gzip-compressed tar holding root/ and every entry
// below it, sorted by name. Timestamps are the Unix epoch, owners are 0,
// files get mode 0644 and the root directory 0755. Entries open one at a time.
func WriteTarGz(w io.Writer, root string, entries []Entry) error {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Name == sorted[i-1].Name {
			return fmt.Errorf("duplicate archive entry %q", sorted[i].Name)
		}
	}

	epoch := time.Unix(0, 0)
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: root + "/", Mode: 0o755, ModTime: epoch}); err != nil {
		return err
	}
	for _, e := range sorted {
		if err := writeEntry(tw, root+"/"+e.Name, e, epoch); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeEntry(tw *tar.Writer, name string, e Entry, mtime time.Time) error {
	hdr := &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: e.Size, Mode: 0o644, ModTime: mtime}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	body, err := e.Open()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer body.Close()
	if _, err := io.Copy(tw, body); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
