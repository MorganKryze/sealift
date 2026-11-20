package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"unicode"
)

// pipManifestExample is the example of docs/dev/archive-format.md, byte for byte.
const pipManifestExample = `{
  "formatVersion": 3,
  "ecosystem": "pip",
  "toolVersion": "dev",
  "analysisId": "20261120T091500Z",
  "createdAt": "2026-11-20T09:17:42.518204331Z",
  "target": {
    "python": "3.11.2",
    "os": "linux",
    "cpu": "x86_64",
    "glibc": "2.28",
    "uvVer": "0.13.7"
  },
  "archive": {
    "sha256": "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7",
    "size": 1395712
  },
  "packages": [
    {
      "name": "jinja2",
      "version": "3.1.6",
      "file": "jinja2-3.1.6-py3-none-any.whl",
      "sha256": "dc4cadfd8d415504c2c06cd7f95028fcce2e45cd2297b52222fba1c0b0be8abb",
      "shippedSha512": "43e5e55037605ffd406599cb282af332714528dfd8cb7d3aa42e46c782fb4c7abab45a415ba60b3698e72fd2915750813cdf4a53b47e856db3d78a66712dabde"
    },
    {
      "name": "markupsafe",
      "version": "3.0.2",
      "file": "MarkupSafe-3.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
      "sha256": "7743268b07457bf5f423266c39c8de26a3bbea92091b6a7d715a5bdfeffecbc0",
      "shippedSha512": "2567b4efaa0966369b002906a9ed2f891befe023b797e90a664ddc12b1fb9cc54c9de7d96b7a4aebaa161927a7ff8e1d24ef18e08a998eb92a930f8a213e61ec"
    }
  ]
}`

const jinjaWheel = "jinja2-3.1.6-py3-none-any.whl"

func TestManifestEcosystem(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		want   Ecosystem
		reason string
	}{
		{name: "format 2", data: `{"formatVersion":2}`, want: NPM},
		{name: "format 2 with npm", data: `{"formatVersion":2,"ecosystem":"npm"}`, want: NPM},
		{name: "format 3 with pip", data: `{"formatVersion":3,"ecosystem":"pip"}`, want: Pip},
		{name: "format 2 with pip", data: `{"formatVersion":2,"ecosystem":"pip"}`, reason: "formatVersion 2 is an npm manifest, and its ecosystem is not npm"},
		{name: "format 3 without ecosystem", data: `{"formatVersion":3}`, reason: "formatVersion 3 is a pip manifest, and its ecosystem is not pip"},
		{name: "format 3 with npm", data: `{"formatVersion":3,"ecosystem":"npm"}`, reason: "formatVersion 3 is a pip manifest, and its ecosystem is not pip"},
		{name: "format 4", data: `{"formatVersion":4,"ecosystem":"pip"}`, reason: "formatVersion is not 2 or 3, the versions this import reads"},
		{name: "no format", data: `{"ecosystem":"pip"}`, reason: "formatVersion is missing"},
		{name: "data after the document", data: `{"formatVersion":2} {}`, reason: "the manifest holds data after the manifest"},
		{name: "not JSON", data: `{"formatVersion":`, reason: "the manifest is not valid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ManifestEcosystem([]byte(tt.data))
			if tt.reason != "" {
				assertRefusal(t, err, tt.reason)
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("ManifestEcosystem = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestManifestEcosystemRepeatsNoValue(t *testing.T) {
	_, err := ManifestEcosystem([]byte(`{"formatVersion":2,"ecosystem":"\u001b[2Jowned"}`))
	assertRefusal(t, err, "its ecosystem is not npm")
	if strings.Contains(err.Error(), "owned") {
		t.Errorf("the refusal repeats the value: %q", err)
	}
}

func TestPipManifestIsRefusedByTheNPMReader(t *testing.T) {
	_, err := ParseManifest([]byte(pipManifestExample))
	assertRefusal(t, err, "formatVersion is missing or not 2, the only version this import reads")
}

func TestParsePipManifestAcceptsTheExample(t *testing.T) {
	page, err := os.ReadFile("../docs/dev/archive-format.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("```json\n"+pipManifestExample+"\n```")) {
		t.Fatal("the format page does not hold the example this test parses")
	}
	m, err := ParsePipManifest([]byte(pipManifestExample))
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	want := PipManifest{
		FormatVersion: PipFormatVersion, Ecosystem: Pip, ToolVersion: "dev",
		AnalysisID: "20261120T091500Z", CreatedAt: "2026-11-20T09:17:42.518204331Z",
		Target:  PipTarget{Python: "3.11.2", OS: "linux", CPU: "x86_64", Glibc: "2.28", UvVer: "0.13.7"},
		Archive: Summary{SHA256: testSHA256, Size: 1395712},
	}
	if m.FormatVersion != want.FormatVersion || m.Ecosystem != want.Ecosystem || m.ToolVersion != want.ToolVersion ||
		m.AnalysisID != want.AnalysisID || m.CreatedAt != want.CreatedAt || m.Target != want.Target || m.Archive != want.Archive {
		t.Errorf("manifest = %+v", m)
	}
	if len(m.Packages) != 2 {
		t.Fatalf("packages = %+v", m.Packages)
	}
	w := m.Packages[1]
	if w.Name != "markupsafe" || w.Version != "3.0.2" || !strings.HasPrefix(w.File, "MarkupSafe-3.0.2-") ||
		w.SHA256 != "7743268b07457bf5f423266c39c8de26a3bbea92091b6a7d715a5bdfeffecbc0" || len(w.ShippedSHA512) != 128 {
		t.Errorf("packages[1] = %+v", w)
	}
}

// pipManifestDoc returns a valid pip manifest as a generic document a case
// can edit.
func pipManifestDoc() map[string]any {
	return map[string]any{
		"formatVersion": 3,
		"ecosystem":     "pip",
		"toolVersion":   "0.7.0",
		"analysisId":    "20261120T091500Z",
		"createdAt":     "2026-11-20T09:17:42.518204331Z",
		"target": map[string]any{
			"python": "3.11.2", "os": "linux", "cpu": "x86_64", "glibc": "2.28", "uvVer": "0.13.7",
		},
		"archive": map[string]any{"sha256": testSHA256, "size": 1395712},
		"packages": []any{
			map[string]any{
				"name": "jinja2", "version": "3.1.6", "file": jinjaWheel,
				"sha256": testSHA256, "shippedSha512": testSHA512Hex,
			},
		},
	}
}

func addWheel(doc map[string]any, name, version, file string) {
	doc["packages"] = append(doc["packages"].([]any), map[string]any{
		"name": name, "version": version, "file": file, "sha256": testSHA256, "shippedSha512": testSHA512Hex,
	})
}

// wheelOfBytes is a valid wheel name of n bytes for jinja2 3.1.6.
func wheelOfBytes(n int) string {
	const prefix, suffix = "jinja2-3.1.6-py3-none-", ".whl"
	return prefix + strings.Repeat("a", n-len(prefix)-len(suffix)) + suffix
}

func TestParsePipManifestAccepts(t *testing.T) {
	tests := []struct {
		name string
		edit func(doc map[string]any)
	}{
		{"fields this version does not know", func(d map[string]any) {
			d["futureField"] = map[string]any{"x": 1}
			pkgOf(d, 0)["futureField"] = true
		}},
		{"a file spelling the name another way", func(d map[string]any) {
			pkgOf(d, 0)["file"] = "Jinja2-3.1.6-py3-none-any.whl"
		}},
		{"a file spelling the version another way", func(d map[string]any) { pkgOf(d, 0)["version"] = "3.1.6.0" }},
		{"a file with a build tag", func(d map[string]any) { pkgOf(d, 0)["file"] = "jinja2-3.1.6-1-py3-none-any.whl" }},
		{"a file of 251 bytes", func(d map[string]any) { pkgOf(d, 0)["file"] = wheelOfBytes(251) }},
		{"two packages", func(d map[string]any) {
			addWheel(d, "markupsafe", "3.0.2", "MarkupSafe-3.0.2-cp311-cp311-manylinux_2_17_x86_64.whl")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := pipManifestDoc()
			tt.edit(doc)
			m, err := ParsePipManifest(encode(t, doc))
			if err != nil {
				t.Fatalf("ParsePipManifest: %v", err)
			}
			if m.Packages[0].Name != "jinja2" || m.Packages[0].File != pkgOf(doc, 0)["file"] {
				t.Errorf("packages = %+v", m.Packages)
			}
		})
	}
}

func TestParsePipManifestRefuses(t *testing.T) {
	const notAWheelFile = "packages[0].file is not a plain file name ending in .whl of at most 251 bytes"
	tests := []struct {
		name   string
		edit   func(doc map[string]any)
		reason string
	}{
		{"format 2", func(d map[string]any) { d["formatVersion"] = 2 }, "formatVersion is missing or not 3, the version of a pip manifest"},
		{"format missing", func(d map[string]any) { delete(d, "formatVersion") }, "formatVersion is missing or not 3, the version of a pip manifest"},
		{"no ecosystem", func(d map[string]any) { delete(d, "ecosystem") }, "ecosystem is missing or not pip"},
		{"ecosystem npm", func(d map[string]any) { d["ecosystem"] = "npm" }, "ecosystem is missing or not pip"},
		{"toolVersion missing", func(d map[string]any) { delete(d, "toolVersion") }, "toolVersion is missing"},
		{"analysisId missing", func(d map[string]any) { delete(d, "analysisId") }, "analysisId is missing"},
		{"createdAt missing", func(d map[string]any) { delete(d, "createdAt") }, "createdAt is missing"},
		{"createdAt malformed", func(d map[string]any) { d["createdAt"] = "yesterday" }, "createdAt is not an RFC 3339 time"},
		{"target missing", func(d map[string]any) { delete(d, "target") }, "target.python is missing"},
		{"target python missing", func(d map[string]any) { delete(d["target"].(map[string]any), "python") }, "target.python is missing"},
		{"target os missing", func(d map[string]any) { delete(d["target"].(map[string]any), "os") }, "target.os is missing"},
		{"target cpu missing", func(d map[string]any) { delete(d["target"].(map[string]any), "cpu") }, "target.cpu is missing"},
		{"target glibc missing", func(d map[string]any) { delete(d["target"].(map[string]any), "glibc") }, "target.glibc is missing"},
		{"target uvVer missing", func(d map[string]any) { delete(d["target"].(map[string]any), "uvVer") }, "target.uvVer is missing"},
		{"target value with a control character", func(d map[string]any) { d["target"].(map[string]any)["os"] = "linux\x1b[2J" }, "target.os holds a control or unprintable character"},
		{"target value too long", func(d map[string]any) { d["target"].(map[string]any)["glibc"] = strings.Repeat("2", maxTextBytes+1) }, "target.glibc is longer than 256 bytes"},
		{"archive missing", func(d map[string]any) { delete(d, "archive") }, "archive.sha256 is missing or not a lowercase hex sha256"},
		{"archive size zero", func(d map[string]any) { d["archive"].(map[string]any)["size"] = 0 }, "archive.size is missing or not positive"},
		{"no package", func(d map[string]any) { d["packages"] = []any{} }, "the manifest lists no package"},
		{"packages missing", func(d map[string]any) { delete(d, "packages") }, "the manifest lists no package"},
		{"name missing", func(d map[string]any) { delete(pkgOf(d, 0), "name") }, "packages[0].name is missing"},
		{"version missing", func(d map[string]any) { delete(pkgOf(d, 0), "version") }, "packages[0].version is missing"},
		{"file missing", func(d map[string]any) { delete(pkgOf(d, 0), "file") }, "packages[0].file is missing"},
		{"sha256 missing", func(d map[string]any) { delete(pkgOf(d, 0), "sha256") }, "packages[0].sha256 is missing"},
		{"sha512 missing", func(d map[string]any) { delete(pkgOf(d, 0), "shippedSha512") }, "packages[0].shippedSha512 is missing"},
		{"name not normalized", func(d map[string]any) { pkgOf(d, 0)["name"] = "Jinja2" }, "packages[0].name is not a normalized package name"},
		{"name with a path", func(d map[string]any) { pkgOf(d, 0)["name"] = "../jinja2" }, "packages[0].name is not a normalized package name"},
		{"range version", func(d map[string]any) { pkgOf(d, 0)["version"] = ">=3.1" }, "packages[0].version is not an exact version"},
		{"version too long", func(d map[string]any) { pkgOf(d, 0)["version"] = strings.Repeat("1", maxVersionBytes+1) }, "packages[0].version is longer than 256 bytes"},
		{"file climbing to a parent", func(d map[string]any) { pkgOf(d, 0)["file"] = "../" + jinjaWheel }, notAWheelFile},
		{"file with a backslash", func(d map[string]any) { pkgOf(d, 0)["file"] = `sub\` + jinjaWheel }, notAWheelFile},
		{"sdist file", func(d map[string]any) { pkgOf(d, 0)["file"] = "jinja2-3.1.6.tar.gz" }, notAWheelFile},
		{"file of 252 bytes", func(d map[string]any) { pkgOf(d, 0)["file"] = wheelOfBytes(252) }, notAWheelFile},
		{"file that is not a wheel name", func(d map[string]any) { pkgOf(d, 0)["file"] = "jinja2-3.1.6.whl" }, "packages[0].file is not a wheel name"},
		{"file of another package", func(d map[string]any) { pkgOf(d, 0)["file"] = "markupsafe-3.1.6-py3-none-any.whl" }, "markupsafe-3.1.6-py3-none-any.whl names another package than packages[0].name"},
		{"file of another version", func(d map[string]any) { pkgOf(d, 0)["file"] = "jinja2-3.1.5-py3-none-any.whl" }, "jinja2-3.1.5-py3-none-any.whl names another version than packages[0].version"},
		{"short sha256", func(d map[string]any) { pkgOf(d, 0)["sha256"] = testSHA256[:63] }, "packages[0].sha256 is not a lowercase hex sha256"},
		{"uppercase sha256", func(d map[string]any) { pkgOf(d, 0)["sha256"] = strings.ToUpper(testSHA256) }, "packages[0].sha256 is not a lowercase hex sha256"},
		{"short sha512", func(d map[string]any) { pkgOf(d, 0)["shippedSha512"] = testSHA512Hex[:100] }, "packages[0].shippedSha512 is not a lowercase hex sha512"},
		{"two versions of one name", func(d map[string]any) {
			addWheel(d, "jinja2", "3.1.5", "jinja2-3.1.5-py3-none-any.whl")
		}, "jinja2 is listed twice: a pip archive carries one wheel per package"},
		{"two wheels of one version", func(d map[string]any) {
			addWheel(d, "jinja2", "3.1.6", "jinja2-3.1.6-py3-none-manylinux_2_17_x86_64.whl")
		}, "jinja2 is listed twice: a pip archive carries one wheel per package"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := pipManifestDoc()
			tt.edit(doc)
			_, err := ParsePipManifest(encode(t, doc))
			assertRefusal(t, err, tt.reason)
		})
	}
}

// unsafeText holds one value of each kind of text a refusal must never repeat.
// Each holds "owned", so a test can tell when a refusal quotes it, raw or escaped.
var unsafeText = map[string]string{
	"escape sequence": "owned\x1b]0;owned\a\x1b[2J",
	"bidi override":   "owned\u202eevil",
	"newline":         "owned\nb",
	"delete":          "owned\x7f",
	"zero width":      "owned\u200bb",
}

func assertRepeatsNoValue(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	reason := err.Error()
	if strings.Contains(reason, "owned") || strings.IndexFunc(reason, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		t.Errorf("the refusal repeats the manifest's text: %q", reason)
	}
}

func TestParsePipManifestRefusesUnsafeText(t *testing.T) {
	long := "owned" + strings.Repeat("a", maxTextBytes)
	target := func(key string) func(map[string]any, string) {
		return func(d map[string]any, v string) { d["target"].(map[string]any)[key] = v }
	}
	fields := []struct {
		name string
		set  func(doc map[string]any, v string)
	}{
		{"toolVersion", func(d map[string]any, v string) { d["toolVersion"] = v }},
		{"analysisId", func(d map[string]any, v string) { d["analysisId"] = v }},
		{"createdAt", func(d map[string]any, v string) { d["createdAt"] = v }},
		{"target.python", target("python")},
		{"target.os", target("os")},
		{"target.cpu", target("cpu")},
		{"target.glibc", target("glibc")},
		{"target.uvVer", target("uvVer")},
	}
	for _, f := range fields {
		t.Run(f.name+" too long", func(t *testing.T) {
			doc := pipManifestDoc()
			f.set(doc, long)
			_, err := ParsePipManifest(encode(t, doc))
			assertRefusal(t, err, f.name+" is longer than 256 bytes")
			assertRepeatsNoValue(t, err)
		})
		for kind, value := range unsafeText {
			t.Run(f.name+" "+kind, func(t *testing.T) {
				doc := pipManifestDoc()
				f.set(doc, value)
				_, err := ParsePipManifest(encode(t, doc))
				assertRefusal(t, err, f.name+" holds a control or unprintable character")
				assertRepeatsNoValue(t, err)
			})
		}
	}
}

func TestParsePipManifestRefusesBadDocuments(t *testing.T) {
	for _, tt := range []struct{ name, data, reason string }{
		{"not JSON", `{"formatVersion":`, "the manifest is not valid JSON"},
		{"data after the document", pipManifestExample + "{}", "the manifest holds data after the manifest"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePipManifest([]byte(tt.data))
			assertRefusal(t, err, tt.reason)
		})
	}
}

const (
	markupWheel = "MarkupSafe-3.0.2-cp311-cp311-manylinux_2_17_x86_64.whl"
	jinjaBody   = "jinja wheel bytes"
	markupBody  = "markupsafe wheel bytes"
)

func sha256Of(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func pipItems() []item {
	return []item{
		{name: "out/", typeflag: tar.TypeDir},
		reg("out/"+markupWheel, markupBody),
		reg("out/"+jinjaWheel, jinjaBody),
	}
}

// pipFixture is a valid pip archive and its manifest. The manifest lists
// jinja2 first, so manifest order differs from archive order.
type pipFixture struct {
	data []byte
	m    PipManifest
	opts VerifyOptions
}

func newPipFixture(t *testing.T, items []item) pipFixture {
	t.Helper()
	data := build(t, items)
	return pipFixture{
		data: data,
		m: PipManifest{
			FormatVersion: PipFormatVersion, Ecosystem: Pip, ToolVersion: "0.7.0", AnalysisID: "a1", CreatedAt: "2026-11-20T09:17:42Z",
			Target:  PipTarget{Python: "3.11.2", OS: "linux", CPU: "x86_64", Glibc: "2.28", UvVer: "0.13.7"},
			Archive: digestOf(data),
			Packages: []Wheel{
				{Name: "jinja2", Version: "3.1.6", File: jinjaWheel, SHA256: sha256Of(jinjaBody), ShippedSHA512: shipped(jinjaBody)},
				{Name: "markupsafe", Version: "3.0.2", File: markupWheel, SHA256: sha256Of(markupBody), ShippedSHA512: shipped(markupBody)},
			},
		},
		opts: VerifyOptions{Dir: t.TempDir()},
	}
}

func (f pipFixture) verify() ([]CheckedWheel, error) {
	return VerifyPip(bytes.NewReader(f.data), f.m, f.opts)
}

func TestVerifyPipAccepts(t *testing.T) {
	f := newPipFixture(t, pipItems())
	got, err := f.verify()
	if err != nil {
		t.Fatalf("VerifyPip: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d wheels, want 2", len(got))
	}
	for i, body := range []string{jinjaBody, markupBody} {
		c := got[i]
		if c.Wheel != f.m.Packages[i] {
			t.Errorf("wheel %d = %+v, want %+v in manifest order", i, c.Wheel, f.m.Packages[i])
		}
		if hex.EncodeToString(c.SHA512) != shipped(body) {
			t.Errorf("wheel %d sha512 = %x", i, c.SHA512)
		}
		data, err := os.ReadFile(c.Path)
		if err != nil || string(data) != body {
			t.Errorf("wheel %d copy = %q, %v", i, data, err)
		}
		info, err := os.Stat(c.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("wheel %d mode = %v, %v; want 0600", i, info.Mode().Perm(), err)
		}
	}
}

func TestVerifyPip(t *testing.T) {
	tests := []struct {
		name   string
		items  func() []item
		edit   func(f *pipFixture)
		reason string
	}{
		{
			name:   "sha256 mismatch",
			edit:   func(f *pipFixture) { f.m.Packages[0].SHA256 = otherSHA256 },
			reason: jinjaWheel + " does not match its sha256",
		},
		{
			name:   "sha512 mismatch",
			edit:   func(f *pipFixture) { f.m.Packages[0].ShippedSHA512 = shipped("other bytes") },
			reason: jinjaWheel + " does not match its shipped sha512",
		},
		{
			name:   "entry not listed",
			items:  func() []item { return append(pipItems(), reg("out/extra-1.0-py3-none-any.whl", "x")) },
			reason: "out/extra-1.0-py3-none-any.whl is not listed in the manifest",
		},
		{
			name:   "listed wheel absent",
			items:  func() []item { return without(pipItems(), "out/"+jinjaWheel) },
			reason: jinjaWheel + " is absent from the archive",
		},
		{
			name:   "wrong archive size before a wheel's digest",
			items:  func() []item { return replace(pipItems(), "out/"+jinjaWheel, reg("out/"+jinjaWheel, "tampered")) },
			edit:   func(f *pipFixture) { f.m.Archive.Size++ },
			reason: "archive size is",
		},
		{
			name:   "wrong archive sha256 before a wheel's digest",
			items:  func() []item { return replace(pipItems(), "out/"+jinjaWheel, reg("out/"+jinjaWheel, "tampered")) },
			edit:   func(f *pipFixture) { f.m.Archive.SHA256 = otherSHA256 },
			reason: "differs from the manifest's",
		},
		{
			name:   "expected sha256",
			edit:   func(f *pipFixture) { f.opts.ExpectedSHA256 = otherSHA256 },
			reason: "differs from the expected sha256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := pipItems()
			if tt.items != nil {
				items = tt.items()
			}
			f := newPipFixture(t, items)
			if tt.edit != nil {
				tt.edit(&f)
			}
			_, err := f.verify()
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestVerifyPipNeedsAnAbsoluteDirectory(t *testing.T) {
	f := newPipFixture(t, pipItems())
	f.opts.Dir = "relative"
	_, err := f.verify()
	var r *Refusal
	if err == nil || errors.As(err, &r) {
		t.Errorf("a relative directory is a local error, not a refusal: %v", err)
	}
}
