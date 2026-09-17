package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func entry(name, body string) Entry {
	return Entry{Name: name, Size: int64(len(body)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(body)), nil
	}}
}

func TestWriteTarGzIsReproducible(t *testing.T) {
	var first, second bytes.Buffer
	if err := WriteTarGz(&first, "out", []Entry{entry("b.tgz", "bbb"), entry("a.tgz", "aa"), entry("signature.key", "k")}); err != nil {
		t.Fatal(err)
	}
	if err := WriteTarGz(&second, "out", []Entry{entry("signature.key", "k"), entry("a.tgz", "aa"), entry("b.tgz", "bbb")}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("same entries in another order gave different bytes")
	}
}

func TestWriteTarGzLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTarGz(&buf, "out", []Entry{entry("b.tgz", "bbb"), entry("a.tgz", "aa")}); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gz.Name != "" || !gz.ModTime.IsZero() {
		t.Errorf("gzip header name %q, mtime %v; want both empty", gz.Name, gz.ModTime)
	}
	tr := tar.NewReader(gz)
	var got []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		got = append(got, fmt.Sprintf("%s %o %d %d %q", h.Name, h.Mode, h.ModTime.Unix(), h.Uid, body))
	}
	want := []string{`out/ 755 0 0 ""`, `out/a.tgz 644 0 0 "aa"`, `out/b.tgz 644 0 0 "bbb"`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWriteTarGzRejectsDuplicates(t *testing.T) {
	err := WriteTarGz(io.Discard, "out", []Entry{entry("a.tgz", "1"), entry("a.tgz", "2")})
	if err == nil {
		t.Fatal("want an error for duplicate names")
	}
}

func BenchmarkWriteTarGz(b *testing.B) {
	body := strings.Repeat("x", 64_000)
	entries := make([]Entry, 500)
	for i := range entries {
		entries[i] = entry(fmt.Sprintf("pkg-%03d.tgz", i), body)
	}
	for b.Loop() {
		if err := WriteTarGz(io.Discard, "out", entries); err != nil {
			b.Fatal(err)
		}
	}
}
