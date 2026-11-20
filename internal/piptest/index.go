// Package piptest is a fake package index for tests: it serves the JSON
// simple API and wheels built in memory, on loopback.
package piptest

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/pip"
)

// Dist describes one file to publish.
type Dist struct {
	Name, Version, Tag string   // Tag is empty for a source distribution
	Requires           []string // Requires-Dist lines
	RequiresPython     string
	Uploaded           time.Time
	Yanked             string            // the reason; "-" for yanked without one
	Payload            map[string][]byte // extra zip entries, such as uv-0.13.7.data/scripts/uv
}

// Index is a running fake index.
type Index struct {
	URL string // ends with /simple/

	mu       sync.Mutex
	base     string
	pages    map[string][]Dist // by normalized project name
	files    map[string][]byte
	requests map[string]int
}

// NewIndex starts a fake index on loopback, closed when the test ends.
func NewIndex(t testing.TB) *Index {
	ix := &Index{pages: map[string][]Dist{}, files: map[string][]byte{}, requests: map[string]int{}}
	srv := httptest.NewServer(ix)
	t.Cleanup(srv.Close)
	ix.base = srv.URL + "/"
	ix.URL = ix.base + "simple/"
	return ix
}

// Add publishes a file and returns the entry the index lists for it.
func (ix *Index) Add(d Dist) pip.IndexFile {
	norm := pip.Normalize(d.Name)
	escaped := escape(d.Name)
	filename := filenameOf(d)
	data := buildWheel(d, escaped)
	if d.Tag == "" {
		data = buildSdist(d, escaped)
	}
	sum := sha256.Sum256(data)
	f := pip.IndexFile{
		Filename:       filename,
		URL:            ix.base + "files/" + filename,
		Sha256:         hex.EncodeToString(sum[:]),
		Size:           int64(len(data)),
		RequiresPython: d.RequiresPython,
		Yanked:         d.Yanked != "",
		UploadTime:     d.Uploaded,
	}
	if d.Yanked != "" && d.Yanked != "-" {
		f.YankedReason = d.Yanked
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.pages[norm] = append(ix.pages[norm], d)
	ix.files[filename] = data
	return f
}

// Requests counts the requests made for a URL path.
func (ix *Index) Requests(path string) int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.requests[path]
}

func (ix *Index) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ix.mu.Lock()
	ix.requests[r.URL.Path]++
	defer ix.mu.Unlock()

	switch {
	case strings.HasPrefix(r.URL.Path, "/files/"):
		data, ok := ix.files[strings.TrimPrefix(r.URL.Path, "/files/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	case strings.HasPrefix(r.URL.Path, "/simple/"):
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/simple/"), "/")
		dists, ok := ix.pages[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_ = json.NewEncoder(w).Encode(ix.pageFor(name, dists))
	default:
		http.NotFound(w, r)
	}
}

func (ix *Index) pageFor(name string, dists []Dist) map[string]any {
	var files []map[string]any
	for _, d := range dists {
		filename := filenameOf(d)
		data := ix.files[filename]
		sum := sha256.Sum256(data)
		e := map[string]any{
			"filename": filename,
			"url":      "../../files/" + filename,
			"hashes":   map[string]string{"sha256": hex.EncodeToString(sum[:])},
			"size":     len(data),
		}
		if d.RequiresPython != "" {
			e["requires-python"] = d.RequiresPython
		}
		if !d.Uploaded.IsZero() {
			e["upload-time"] = d.Uploaded.UTC().Format(time.RFC3339Nano)
		}
		switch d.Yanked {
		case "":
			e["yanked"] = false
		case "-":
			e["yanked"] = true
		default:
			e["yanked"] = d.Yanked
		}
		files = append(files, e)
	}
	return map[string]any{"meta": map[string]string{"api-version": "1.0"}, "name": name, "files": files}
}

func escape(name string) string { return strings.ReplaceAll(pip.Normalize(name), "-", "_") }

func filenameOf(d Dist) string {
	if d.Tag == "" {
		return escape(d.Name) + "-" + d.Version + ".tar.gz"
	}
	return escape(d.Name) + "-" + d.Version + "-" + d.Tag + ".whl"
}

func metadata(d Dist) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Metadata-Version: 2.1\nName: %s\nVersion: %s\n", d.Name, d.Version)
	if d.RequiresPython != "" {
		fmt.Fprintf(&b, "Requires-Python: %s\n", d.RequiresPython)
	}
	for _, r := range d.Requires {
		fmt.Fprintf(&b, "Requires-Dist: %s\n", r)
	}
	return b.String()
}

func buildWheel(d Dist, escaped string) []byte {
	dir := escaped + "-" + d.Version + ".dist-info/"
	entries := map[string][]byte{
		dir + "METADATA": []byte(metadata(d)),
		dir + "WHEEL":    []byte("Wheel-Version: 1.0\nGenerator: piptest\nRoot-Is-Purelib: true\nTag: " + d.Tag + "\n"),
	}
	for name, content := range d.Payload {
		entries[name] = content
	}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	var record strings.Builder
	for _, n := range names {
		sum := sha256.Sum256(entries[n])
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", n, base64.RawURLEncoding.EncodeToString(sum[:]), len(entries[n]))
	}
	fmt.Fprintf(&record, "%sRECORD,,\n", dir)
	entries[dir+"RECORD"] = []byte(record.String())
	names = append(names, dir+"RECORD")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})
		_, _ = w.Write(entries[n])
	}
	_ = zw.Close()
	return buf.Bytes()
}

func buildSdist(d Dist, escaped string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte(metadata(d))
	_ = tw.WriteHeader(&tar.Header{Name: escaped + "-" + d.Version + "/PKG-INFO", Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}
