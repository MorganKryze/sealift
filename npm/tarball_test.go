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

func TestTarballDataAfterTheEndMarker(t *testing.T) {
	base := []packedEntry{reg("package/package.json", `{"name":"a","version":"1.0.0"}`), reg("package/index.js", "one")}
	extra := rawTar(t, reg("package/install.js", "x"))
	for _, tc := range []struct {
		name string
		src  []byte
		ok   bool
	}{
		{"nothing", packThen(t, nil, base...), true},
		{"zero padding", packThen(t, make([]byte, 9216), base...), true},
		{"entries", packThen(t, extra, base...), false},
		{"one byte after zeros", packThen(t, append(make([]byte, 20000), 1), base...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := InspectTarball(bytes.NewReader(tc.src))
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, errTrailingData)) {
				t.Errorf("InspectTarball: err = %v", err)
			}
			err = StripPublishConfig(io.Discard, bytes.NewReader(tc.src))
			if tc.ok != (err == nil) {
				t.Errorf("StripPublishConfig: err = %v", err)
			}
		})
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

func TestInspectTarballNameVersion(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, wantName, wantVersion string
	}{
		{"both", `{"name":"@scope/a","version":"1.2.3"}`, "@scope/a", "1.2.3"},
		{"missing", `{"main":"index.js"}`, "", ""},
		{"not strings", `{"name":7,"version":{"a":1}}`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := InspectTarball(bytes.NewReader(makeTarball(t, tarFile{"package/package.json", tc.manifest})))
			if err != nil || info.Name != tc.wantName || info.Version != tc.wantVersion {
				t.Fatalf("got %+v, %v", info, err)
			}
		})
	}
}

func TestInspectTarballBounds(t *testing.T) {
	t.Run("package.json over 16 MiB", func(t *testing.T) {
		big := `{"name":"a","pad":"` + strings.Repeat("x", maxManifestBytes) + `"}`
		_, err := InspectTarball(bytes.NewReader(makeTarball(t, tarFile{"package/package.json", big})))
		if err == nil || !strings.Contains(err.Error(), "larger than 16 MiB") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("more than 100,000 entries", func(t *testing.T) {
		files := []tarFile{{"package/package.json", `{"name":"a"}`}}
		for i := range maxTarballEntries {
			files = append(files, tarFile{fmt.Sprintf("package/f%d", i), ""})
		}
		_, err := InspectTarball(bytes.NewReader(makeTarball(t, files...)))
		if err == nil || !strings.Contains(err.Error(), "more than 100000 entries") {
			t.Fatalf("err = %v", err)
		}
	})
}

type packedEntry struct {
	hdr  tar.Header
	body string
}

func reg(name, body string) packedEntry {
	return packedEntry{hdr: tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg}, body: body}
}

func pack(t *testing.T, entries ...packedEntry) []byte {
	t.Helper()
	return packThen(t, nil, entries...)
}

// rawTar returns an uncompressed tar stream, end marker included.
func rawTar(t *testing.T, entries ...packedEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.hdr
		h.Size = int64(len(e.body))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// packThen is pack with raw bytes written into the gzip stream after the
// tar end marker.
func packThen(t *testing.T, after []byte, entries ...packedEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(rawTar(t, entries...)); err != nil {
		t.Fatal(err)
	}
	if _, err := gz.Write(after); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSameContent(t *testing.T) {
	const manifest = `{"name":"a","version":"1.0.0","scripts":{"test":"x"}}`
	base := func() []packedEntry {
		return []packedEntry{reg("package/package.json", manifest), reg("package/index.js", "one"), reg("package/lib/b.js", "two")}
	}
	with := func(f func(e []packedEntry) []packedEntry) []byte { return pack(t, f(base())...) }

	for _, tc := range []struct {
		name string
		a, b []byte
		want bool
	}{
		{"identical", pack(t, base()...), pack(t, base()...), true},
		{"other owners, times and order", pack(t, base()...), with(func(e []packedEntry) []packedEntry {
			for i := range e {
				e[i].hdr.Uid, e[i].hdr.Gid, e[i].hdr.Uname = 1000, 1000, "someone"
				e[i].hdr.ModTime = time.Unix(1_700_000_000, 0)
			}
			return []packedEntry{e[2], e[0], e[1]}
		}), true},
		{"publishConfig in one only", pack(t, base()...), with(func(e []packedEntry) []packedEntry {
			e[0].body = `{"name":"a","version":"1.0.0","scripts":{"test":"x"},"publishConfig":{"registry":"https://example.com"}}`
			return e
		}), true},
		{"package.json reformatted", pack(t, base()...), with(func(e []packedEntry) []packedEntry {
			e[0].body = "{\n  \"version\": \"1.0.0\",\n  \"scripts\": {\"test\": \"x\"},\n  \"name\": \"a\"\n}\n"
			return e
		}), true},
		{"file added", pack(t, base()...), with(func(e []packedEntry) []packedEntry { return append(e, reg("package/extra.js", "x")) }), false},
		{"file removed", pack(t, base()...), with(func(e []packedEntry) []packedEntry { return e[:2] }), false},
		{"byte changed", pack(t, base()...), with(func(e []packedEntry) []packedEntry { e[1].body = "onf"; return e }), false},
		{"mode changed", pack(t, base()...), with(func(e []packedEntry) []packedEntry { e[1].hdr.Mode = 0o755; return e }), false},
		{"symlink for a file", pack(t, base()...), with(func(e []packedEntry) []packedEntry {
			e[1] = packedEntry{hdr: tar.Header{Name: "package/index.js", Mode: 0o644, Typeflag: tar.TypeSymlink, Linkname: "lib/b.js"}}
			return e
		}), false},
		{"symlink target changed", with(func(e []packedEntry) []packedEntry {
			return append(e, packedEntry{hdr: tar.Header{Name: "package/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "index.js"}})
		}), with(func(e []packedEntry) []packedEntry {
			return append(e, packedEntry{hdr: tar.Header{Name: "package/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "lib/b.js"}})
		}), false},
		{"type changed, same empty body and mode", with(func(e []packedEntry) []packedEntry { return append(e, reg("package/empty", "")) }),
			with(func(e []packedEntry) []packedEntry {
				return append(e, packedEntry{hdr: tar.Header{Name: "package/empty", Mode: 0o644, Typeflag: tar.TypeFifo}})
			}), false},
		{"scripts changed", pack(t, base()...), with(func(e []packedEntry) []packedEntry {
			e[0].body = `{"name":"a","version":"1.0.0","scripts":{"test":"y"}}`
			return e
		}), false},
		{"name twice in one", pack(t, base()...), with(func(e []packedEntry) []packedEntry { return append(e, e[1]) }), false},
		{"name twice in the first", with(func(e []packedEntry) []packedEntry { return append(e, e[1]) }), pack(t, base()...), false},
		{"entries after the end marker", pack(t, base()...), packThen(t, rawTar(t, reg("package/install.js", "x"), reg("package/index.js", "other")), base()...), false},
		{"entries after the end marker in the first", packThen(t, rawTar(t, reg("package/install.js", "x")), base()...), pack(t, base()...), false},
		{"zero padding after the end marker", pack(t, base()...), packThen(t, make([]byte, 9216), base()...), true},
		{"name twice in both", with(func(e []packedEntry) []packedEntry { return append(e, e[1]) }), with(func(e []packedEntry) []packedEntry { return append(e, e[1]) }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SameContent(bytes.NewReader(tc.a), bytes.NewReader(tc.b))
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v, want %v", got, err, tc.want)
			}
		})
	}

	t.Run("unreadable input", func(t *testing.T) {
		if _, err := SameContent(strings.NewReader("not a tarball"), bytes.NewReader(pack(t, base()...))); err == nil {
			t.Error("want an error")
		}
	})
}

func TestTarballEntryNameBound(t *testing.T) {
	long := func(n int) string { return "package/" + strings.Repeat("n", n-len("package/")) }
	manifest := reg("package/package.json", `{"name":"a","version":"1.0.0"}`)
	for _, tc := range []struct {
		name    string
		entry   packedEntry
		wantErr string
	}{
		{"name at the bound", reg(long(maxEntryNameBytes), "x"), ""},
		{"name over the bound", reg(long(maxEntryNameBytes+1), "x"), "longer than 4096 bytes"},
		{"link target at the bound", packedEntry{hdr: tar.Header{Name: "package/l", Typeflag: tar.TypeSymlink, Linkname: strings.Repeat("l", maxEntryNameBytes)}}, ""},
		{"link target over the bound", packedEntry{hdr: tar.Header{Name: "package/l", Typeflag: tar.TypeSymlink, Linkname: strings.Repeat("l", maxEntryNameBytes+1)}}, "longer than 4096 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pack(t, manifest, tc.entry)
			_, errInspect := InspectTarball(bytes.NewReader(data))
			_, errSame := SameContent(bytes.NewReader(data), bytes.NewReader(data))
			for _, err := range []error{errInspect, errSame} {
				if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
					t.Errorf("err = %v, want %q", err, tc.wantErr)
				}
			}
		})
	}
}

func TestTarballErrorsQuoteEntryNames(t *testing.T) {
	name := "\x1b[2J\r\nforged/package.json"
	data := pack(t, reg(name, "not json"))
	_, errInspect := InspectTarball(bytes.NewReader(data))
	_, errSame := SameContent(bytes.NewReader(data), bytes.NewReader(data))
	for _, err := range []error{errInspect, errSame} {
		if err == nil || strings.ContainsAny(err.Error(), "\x1b\r\n") || !strings.Contains(err.Error(), `\x1b[2J\r\nforged`) {
			t.Errorf("err = %q", err)
		}
	}
}
