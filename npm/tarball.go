package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
)

// DefaultRegistry is the public npm registry.
const DefaultRegistry = "https://registry.npmjs.org"

// Bounds on one tarball read from an archive or from Nexus.
const (
	maxTarballEntries = 100_000  // entries in one tarball
	maxTarballBytes   = 10 << 30 // decompressed bytes in one tarball
	maxManifestBytes  = 16 << 20 // bytes in one package.json
	maxEntryNameBytes = 4096     // bytes in an entry name or link target, the usual PATH_MAX
)

// ErrUnsafePath reports a tarball entry with an absolute path or a ".." segment.
var ErrUnsafePath = errors.New("unsafe path in tarball")

// TarballURL returns the registry URL of a package tarball, such as
// <registry>/@scope/name/-/name-1.2.3.tgz.
func TarballURL(registry, name, version string) string {
	base := name[strings.LastIndex(name, "/")+1:]
	return strings.TrimSuffix(registry, "/") + "/" + name + "/-/" + base + "-" + version + ".tgz"
}

// PackFileName returns the file name npm pack gives a package:
// name-1.2.3.tgz, or scope-name-1.2.3.tgz for @scope/name.
func PackFileName(name, version string) string {
	return strings.ReplaceAll(strings.TrimPrefix(name, "@"), "/", "-") + "-" + version + ".tgz"
}

// TarballInfo describes a package tarball.
type TarballInfo struct {
	ManifestPath     string // first-level package.json, such as "package/package.json"
	Name, Version    string // from package.json; empty when absent or not a string
	HasPublishConfig bool
}

// InspectTarball reads a gzip-compressed package tarball, rejects unsafe
// entry paths and tarballs with multiple first-level package.json files,
// and reports the name and version of its package.json and whether it holds
// publishConfig.
func InspectTarball(r io.Reader) (TarballInfo, error) {
	var info TarballInfo
	err := walkTarball(r, func(h *tar.Header, body io.Reader) error {
		if !isManifest(h) {
			return nil
		}
		if info.ManifestPath != "" {
			return fmt.Errorf("tarball has several package.json files: %q and %q", info.ManifestPath, h.Name)
		}
		var fields map[string]json.RawMessage
		dec := json.NewDecoder(boundedManifest(body))
		if err := dec.Decode(&fields); err != nil {
			return fmt.Errorf("%s: %w", h.Name, err)
		}
		if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
			return fmt.Errorf("%s: unexpected data after the JSON object", h.Name)
		}
		info.ManifestPath = h.Name
		_, info.HasPublishConfig = fields["publishConfig"]
		info.Name = stringField(fields, "name")
		info.Version = stringField(fields, "version")
		return nil
	})
	if err != nil {
		return TarballInfo{}, err
	}
	if info.ManifestPath == "" {
		return TarballInfo{}, errors.New("tarball has no package.json")
	}
	return info, nil
}

// StripPublishConfig copies a package tarball from r to w without the
// publishConfig key of its first-level package.json. That file gets
// re-encoded with sorted keys and two-space indentation; every other entry
// keeps its header and bytes. It rejects tarballs with multiple first-level
// package.json files. The same input gives the same output.
func StripPublishConfig(w io.Writer, r io.Reader) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	rewritten := false
	var firstManifest string
	err := walkTarball(r, func(h *tar.Header, body io.Reader) error {
		hdr := *h
		if isManifest(h) {
			if rewritten {
				return fmt.Errorf("tarball has several package.json files: %q and %q", firstManifest, h.Name)
			}
			data, err := withoutPublishConfig(body)
			if err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
			rewritten = true
			firstManifest = h.Name
			hdr.Size = int64(len(data))
			delete(hdr.PAXRecords, "size")
			body = bytes.NewReader(data)
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			return err
		}
		_, err := io.Copy(tw, body)
		return err
	})
	if err != nil {
		return err
	}
	if !rewritten {
		return errors.New("tarball has no package.json")
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func stringField(fields map[string]json.RawMessage, key string) string {
	var v string
	if json.Unmarshal(fields[key], &v) != nil {
		return ""
	}
	return v
}

func withoutPublishConfig(r io.Reader) ([]byte, error) {
	dec := json.NewDecoder(boundedManifest(r))
	dec.UseNumber()
	var fields map[string]any
	if err := dec.Decode(&fields); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON object")
	}
	delete(fields, "publishConfig")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fields); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func walkTarball(r io.Reader, fn func(*tar.Header, io.Reader) error) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open tarball: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&boundedReader{r: gz, left: maxTarballBytes, what: "tarball", unit: "10 GiB"})
	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tarball: %w", err)
		}
		if entries >= maxTarballEntries {
			return fmt.Errorf("tarball has more than %d entries", maxTarballEntries)
		}
		if len(h.Name) > maxEntryNameBytes || len(h.Linkname) > maxEntryNameBytes {
			return fmt.Errorf("tarball has an entry name or link target longer than %d bytes", maxEntryNameBytes)
		}
		if strings.HasPrefix(h.Name, "/") || slices.Contains(strings.Split(h.Name, "/"), "..") {
			return fmt.Errorf("%w: %q", ErrUnsafePath, h.Name)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if name == "" || path.Clean(name) != name {
			return fmt.Errorf("%w: %q", ErrUnsafePath, h.Name)
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}

// isManifest reports whether h is a regular file named package.json one
// directory below the tarball root.
func isManifest(h *tar.Header) bool {
	parts := strings.Split(strings.TrimPrefix(h.Name, "./"), "/")
	return h.Typeflag == tar.TypeReg && len(parts) == 2 && parts[1] == "package.json"
}

// boundedReader fails, rather than truncates, once more than left bytes are read.
type boundedReader struct {
	r          io.Reader
	left       int64
	what, unit string
}

func (b *boundedReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p[:min(int64(len(p)), b.left+1)])
	b.left -= int64(n)
	if b.left < 0 {
		return 0, fmt.Errorf("%s is larger than %s", b.what, b.unit)
	}
	return n, err
}

func boundedManifest(r io.Reader) io.Reader {
	return &boundedReader{r: r, left: maxManifestBytes, what: "package.json", unit: "16 MiB"}
}

// entryDigest is what SameContent compares for one tarball entry. Link
// targets and names are kept as hashes, so memory grows with the entry count
// and not with the length of the text.
type entryDigest struct {
	typeflag byte
	mode     int64
	linkname [sha256.Size]byte
	sum      [sha256.Size]byte
}

// SameContent reports whether two gzip-compressed package tarballs hold the
// same entry names, types, modes and bytes. Owners, times and entry order are
// ignored. The first-level package.json compares as decoded JSON once
// publishConfig is removed from both. A tarball that holds a name twice never
// compares equal. The error is for unreadable or over-bound input.
func SameContent(a, b io.Reader) (bool, error) {
	da, dupA, err := digestTarball(a)
	if err != nil {
		return false, err
	}
	db, dupB, err := digestTarball(b)
	if err != nil {
		return false, err
	}
	if dupA || dupB || len(da) != len(db) {
		return false, nil
	}
	for name, d := range da {
		if other, ok := db[name]; !ok || other != d {
			return false, nil
		}
	}
	return true, nil
}

func digestTarball(r io.Reader) (map[[sha256.Size]byte]entryDigest, bool, error) {
	digests := map[[sha256.Size]byte]entryDigest{}
	duplicate := false
	err := walkTarball(r, func(h *tar.Header, body io.Reader) error {
		d := entryDigest{typeflag: h.Typeflag, mode: h.Mode & 0o7777, linkname: sha256.Sum256([]byte(h.Linkname))}
		hash := sha256.New()
		if isManifest(h) {
			data, err := withoutPublishConfig(body)
			if err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
			hash.Write(data)
		} else if _, err := io.Copy(hash, body); err != nil {
			return fmt.Errorf("read tarball: %w", err)
		}
		hash.Sum(d.sum[:0])
		key := sha256.Sum256([]byte(h.Name))
		if _, seen := digests[key]; seen {
			duplicate = true
		}
		digests[key] = d
		return nil
	})
	return digests, duplicate, err
}
