package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type tarFile struct {
	name string
	body string
}

func makeTarball(t testing.TB, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg, ModTime: time.Unix(499162500, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
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

func readTarball(t *testing.T, data []byte) (map[string]string, map[string]*tar.Header) {
	t.Helper()
	bodies, headers := map[string]string{}, map[string]*tar.Header{}
	err := walkTarball(bytes.NewReader(data), func(h *tar.Header, body io.Reader) error {
		b, err := io.ReadAll(body)
		bodies[h.Name], headers[h.Name] = string(b), h
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return bodies, headers
}

func TestTarballURLAndPackFileName(t *testing.T) {
	for _, tc := range []struct{ name, version, url, file string }{
		{"express", "4.21.2", "https://registry.npmjs.org/express/-/express-4.21.2.tgz", "express-4.21.2.tgz"},
		{"@esbuild/linux-x64", "0.25.0", "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.25.0.tgz", "esbuild-linux-x64-0.25.0.tgz"},
	} {
		if got := TarballURL(DefaultRegistry+"/", tc.name, tc.version); got != tc.url {
			t.Errorf("TarballURL(%s) = %s, want %s", tc.name, got, tc.url)
		}
		if got := PackFileName(tc.name, tc.version); got != tc.file {
			t.Errorf("PackFileName(%s) = %s, want %s", tc.name, got, tc.file)
		}
	}
}

func TestInspectTarball(t *testing.T) {
	with := makeTarball(t, tarFile{"package/package.json", `{"name":"a","publishConfig":{"registry":"https://example.com"}}`})
	info, err := InspectTarball(bytes.NewReader(with))
	if err != nil || !info.HasPublishConfig || info.ManifestPath != "package/package.json" {
		t.Errorf("with publishConfig: %+v, %v", info, err)
	}

	without := makeTarball(t, tarFile{"package/package.json", `{"name":"a"}`}, tarFile{"package/lib/package.json", `{"publishConfig":{}}`})
	info, err = InspectTarball(bytes.NewReader(without))
	if err != nil || info.HasPublishConfig {
		t.Errorf("without publishConfig: %+v, %v", info, err)
	}

	if _, err := InspectTarball(bytes.NewReader(makeTarball(t, tarFile{"package/index.js", "x"}))); err == nil {
		t.Error("no package.json: want an error")
	}
	for _, name := range []string{"../evil", "package/../../evil", "/etc/passwd", "package/./package.json", "package//package.json"} {
		_, err := InspectTarball(bytes.NewReader(makeTarball(t, tarFile{name, "x"})))
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s: err = %v, want ErrUnsafePath", name, err)
		}
	}
}

func TestTarballRejectsTrailingData(t *testing.T) {
	src := makeTarball(t, tarFile{"package/package.json", `{"name":"a"} {"publishConfig":{}}`})
	if _, err := InspectTarball(bytes.NewReader(src)); err == nil {
		t.Error("InspectTarball: want an error for trailing data")
	}
	if err := StripPublishConfig(io.Discard, bytes.NewReader(src)); err == nil {
		t.Error("StripPublishConfig: want an error for trailing data")
	}
}

func TestTarballRejectsDuplicateManifest(t *testing.T) {
	src := makeTarball(t,
		tarFile{"package/package.json", `{"name":"a"}`},
		tarFile{"package/package.json", `{"name":"a","publishConfig":{"registry":"https://example.com"}}`},
	)
	if _, err := InspectTarball(bytes.NewReader(src)); err == nil {
		t.Error("InspectTarball: want an error for duplicate manifests")
	}
	if err := StripPublishConfig(io.Discard, bytes.NewReader(src)); err == nil {
		t.Error("StripPublishConfig: want an error for duplicate manifests")
	}
}

func TestStripPublishConfig(t *testing.T) {
	src := makeTarball(t,
		tarFile{"package/package.json", `{"version":"1.0.0","name":"a","publishConfig":{"provenance":true},"main":"index.js","size":1e3}`},
		tarFile{"package/index.js", "module.exports = 42\n"},
	)
	var out bytes.Buffer
	if err := StripPublishConfig(&out, bytes.NewReader(src)); err != nil {
		t.Fatal(err)
	}

	bodies, headers := readTarball(t, out.Bytes())
	var manifest map[string]any
	if err := json.Unmarshal([]byte(bodies["package/package.json"]), &manifest); err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest["publishConfig"]; ok {
		t.Error("publishConfig still present")
	}
	wantManifest := "{\n  \"main\": \"index.js\",\n  \"name\": \"a\",\n  \"size\": 1e3,\n  \"version\": \"1.0.0\"\n}\n"
	if bodies["package/package.json"] != wantManifest {
		t.Errorf("package.json:\n%s\nwant:\n%s", bodies["package/package.json"], wantManifest)
	}
	if bodies["package/index.js"] != "module.exports = 42\n" {
		t.Errorf("index.js changed: %q", bodies["package/index.js"])
	}
	if !headers["package/index.js"].ModTime.Equal(time.Unix(499162500, 0)) {
		t.Errorf("index.js mtime changed: %v", headers["package/index.js"].ModTime)
	}

	var again bytes.Buffer
	if err := StripPublishConfig(&again, bytes.NewReader(src)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Error("two runs on the same input gave different bytes")
	}
}

func BenchmarkStripPublishConfig(b *testing.B) {
	files := []tarFile{{"package/package.json", `{"name":"a","publishConfig":{"access":"public"}}`}}
	chunk := strings.Repeat("x", 10_000)
	for i := range 200 {
		files = append(files, tarFile{fmt.Sprintf("package/lib/%03d.js", i), chunk})
	}
	src := makeTarball(b, files...)
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if err := StripPublishConfig(io.Discard, bytes.NewReader(src)); err != nil {
			b.Fatal(err)
		}
	}
}
