package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	HasPublishConfig bool
}

// InspectTarball reads a gzip-compressed package tarball, rejects unsafe
// entry paths and tarballs with multiple first-level package.json files,
// and reports whether its package.json holds publishConfig.
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
		dec := json.NewDecoder(body)
		if err := dec.Decode(&fields); err != nil {
			return fmt.Errorf("%s: %w", h.Name, err)
		}
		if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
			return fmt.Errorf("%s: unexpected data after the JSON object", h.Name)
		}
		info.ManifestPath = h.Name
		_, info.HasPublishConfig = fields["publishConfig"]
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

func withoutPublishConfig(r io.Reader) ([]byte, error) {
	dec := json.NewDecoder(r)
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
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tarball: %w", err)
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
