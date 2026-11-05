package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	testSHA256    = "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7"
	testSHA512Hex = "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4"
	testIntegrity = "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA=="
)

// manifestDoc returns a valid manifest as a generic document a case can edit.
func manifestDoc() map[string]any {
	return map[string]any{
		"formatVersion": 1,
		"toolVersion":   "0.3.0",
		"analysisId":    "20260923T120255Z",
		"createdAt":     "2026-09-23T12:04:24.410131126Z",
		"target": map[string]any{
			"os": "linux", "cpu": "x64", "libc": "glibc", "node": "22.17.1", "pnpmVer": "10.34.5",
		},
		"archive": map[string]any{"sha256": testSHA256, "size": 7031361},
		"packages": []any{
			map[string]any{
				"name": "express", "version": "5.1.0", "file": "express-5.1.0.tgz",
				"originalIntegrity": testIntegrity, "shippedSha512": testSHA512Hex, "publishConfigStripped": false,
			},
		},
	}
}

func pkgOf(doc map[string]any, i int) map[string]any {
	return doc["packages"].([]any)[i].(map[string]any)
}

func addPackage(doc map[string]any, name, version, file string) {
	doc["packages"] = append(doc["packages"].([]any), map[string]any{
		"name": name, "version": version, "file": file,
		"originalIntegrity": testIntegrity, "shippedSha512": testSHA512Hex, "publishConfigStripped": false,
	})
}

func encode(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseManifestAccepts(t *testing.T) {
	doc := manifestDoc()
	doc["futureField"] = map[string]any{"x": 1}
	pkgOf(doc, 0)["futureField"] = true
	addPackage(doc, "@babel/code-frame", "7.29.7", "babel-code-frame-7.29.7.tgz")
	pkgOf(doc, 1)["publishConfigStripped"] = true

	m, err := ParseManifest(bytes.NewReader(encode(t, doc)))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.FormatVersion != 1 || m.Target.PnpmVer != "10.34.5" || m.Archive.Size != 7031361 || m.Archive.SHA256 != testSHA256 {
		t.Errorf("manifest = %+v", m)
	}
	if len(m.Packages) != 2 || m.Packages[1].Name != "@babel/code-frame" || !m.Packages[1].PublishConfigStripped {
		t.Errorf("packages = %+v", m.Packages)
	}
}

func TestParseManifestRefuses(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(doc map[string]any)
		reason string
	}{
		{"format version 2", func(d map[string]any) { d["formatVersion"] = 2 }, "formatVersion"},
		{"format version missing", func(d map[string]any) { delete(d, "formatVersion") }, "formatVersion"},
		{"toolVersion missing", func(d map[string]any) { delete(d, "toolVersion") }, "toolVersion"},
		{"analysisId missing", func(d map[string]any) { delete(d, "analysisId") }, "analysisId"},
		{"createdAt missing", func(d map[string]any) { delete(d, "createdAt") }, "createdAt"},
		{"createdAt malformed", func(d map[string]any) { d["createdAt"] = "yesterday" }, "createdAt"},
		{"target missing", func(d map[string]any) { delete(d, "target") }, "target.os"},
		{"target os missing", func(d map[string]any) { delete(d["target"].(map[string]any), "os") }, "target.os"},
		{"target cpu missing", func(d map[string]any) { delete(d["target"].(map[string]any), "cpu") }, "target.cpu"},
		{"target libc missing", func(d map[string]any) { delete(d["target"].(map[string]any), "libc") }, "target.libc"},
		{"target node missing", func(d map[string]any) { delete(d["target"].(map[string]any), "node") }, "target.node"},
		{"target pnpmVer missing", func(d map[string]any) { delete(d["target"].(map[string]any), "pnpmVer") }, "target.pnpmVer"},
		{"archive missing", func(d map[string]any) { delete(d, "archive") }, "archive.sha256"},
		{"archive sha256 missing", func(d map[string]any) { delete(d["archive"].(map[string]any), "sha256") }, "archive.sha256"},
		{"archive sha256 malformed", func(d map[string]any) { d["archive"].(map[string]any)["sha256"] = "abc" }, "archive.sha256"},
		{"archive size missing", func(d map[string]any) { delete(d["archive"].(map[string]any), "size") }, "archive.size"},
		{"archive size zero", func(d map[string]any) { d["archive"].(map[string]any)["size"] = 0 }, "archive.size"},
		{"packages missing", func(d map[string]any) { delete(d, "packages") }, "no package"},
		{"packages empty", func(d map[string]any) { d["packages"] = []any{} }, "no package"},
		{"name missing", func(d map[string]any) { delete(pkgOf(d, 0), "name") }, "packages[0].name"},
		{"version missing", func(d map[string]any) { delete(pkgOf(d, 0), "version") }, "packages[0].version"},
		{"file missing", func(d map[string]any) { delete(pkgOf(d, 0), "file") }, "packages[0].file"},
		{"originalIntegrity missing", func(d map[string]any) { delete(pkgOf(d, 0), "originalIntegrity") }, "packages[0].originalIntegrity"},
		{"shippedSha512 missing", func(d map[string]any) { delete(pkgOf(d, 0), "shippedSha512") }, "packages[0].shippedSha512"},
		{"publishConfigStripped missing", func(d map[string]any) { delete(pkgOf(d, 0), "publishConfigStripped") }, "packages[0].publishConfigStripped"},
		{"file with a slash", func(d map[string]any) { pkgOf(d, 0)["file"] = "sub/express-5.1.0.tgz" }, "plain file name"},
		{"file with a backslash", func(d map[string]any) { pkgOf(d, 0)["file"] = `sub\express-5.1.0.tgz` }, "plain file name"},
		{"file with a leading dot", func(d map[string]any) { pkgOf(d, 0)["file"] = ".express-5.1.0.tgz" }, "plain file name"},
		{"file with dots only", func(d map[string]any) { pkgOf(d, 0)["file"] = "..tgz" }, "plain file name"},
		{"file without tgz", func(d map[string]any) { pkgOf(d, 0)["file"] = "express-5.1.0.tar" }, "plain file name"},
		{"file of 256 bytes", func(d map[string]any) { pkgOf(d, 0)["file"] = strings.Repeat("a", 256-4) + ".tgz" }, "plain file name"},
		{"file twice", func(d map[string]any) { addPackage(d, "koa", "2.0.0", "express-5.1.0.tgz") }, "listed twice"},
		{"name and version twice", func(d map[string]any) { addPackage(d, "express", "5.1.0", "other-5.1.0.tgz") }, "listed twice"},
		{"invalid name", func(d map[string]any) { pkgOf(d, 0)["name"] = "../express" }, "not a valid package name"},
		{"range version", func(d map[string]any) { pkgOf(d, 0)["version"] = "^5.1.0" }, "not an exact version"},
		{"shippedSha512 malformed", func(d map[string]any) { pkgOf(d, 0)["shippedSha512"] = "zz" }, "shippedSha512"},
		{"shippedSha512 too short", func(d map[string]any) { pkgOf(d, 0)["shippedSha512"] = testSHA512Hex[:100] }, "shippedSha512"},
		{"originalIntegrity malformed", func(d map[string]any) { pkgOf(d, 0)["originalIntegrity"] = "sha512-AAAA" }, "originalIntegrity"},
		{"originalIntegrity unsupported", func(d map[string]any) { pkgOf(d, 0)["originalIntegrity"] = "md5-AA==" }, "originalIntegrity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := manifestDoc()
			tt.edit(doc)
			_, err := ParseManifest(bytes.NewReader(encode(t, doc)))
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestParseManifestRefusesUnsafeText(t *testing.T) {
	long := strings.Repeat("a", maxTextBytes+1)
	unsafe := map[string]string{
		"escape sequence": "\x1b]0;owned\a\x1b[2J",
		"bidi override":   "\u202eevil",
		"newline":         "a\nb",
		"delete":          "a\x7f",
		"zero width":      "a\u200bb",
	}
	type field struct {
		name string
		set  func(doc map[string]any, v string)
	}
	target := func(key string) func(map[string]any, string) {
		return func(d map[string]any, v string) { d["target"].(map[string]any)[key] = v }
	}
	fields := []field{
		{"toolVersion", func(d map[string]any, v string) { d["toolVersion"] = v }},
		{"analysisId", func(d map[string]any, v string) { d["analysisId"] = v }},
		{"target.os", target("os")},
		{"target.cpu", target("cpu")},
		{"target.libc", target("libc")},
		{"target.node", target("node")},
		{"target.pnpmVer", target("pnpmVer")},
	}
	for _, f := range fields {
		t.Run(f.name+" too long", func(t *testing.T) {
			doc := manifestDoc()
			f.set(doc, long)
			_, err := ParseManifest(bytes.NewReader(encode(t, doc)))
			assertRefusal(t, err, f.name+" is longer than")
		})
		for kind, value := range unsafe {
			t.Run(f.name+" "+kind, func(t *testing.T) {
				doc := manifestDoc()
				f.set(doc, "x"+value)
				_, err := ParseManifest(bytes.NewReader(encode(t, doc)))
				assertRefusal(t, err, f.name+" holds a control or unprintable character")
				if strings.ContainsAny(err.Error(), "\x1b\u202e\u200b\a\n") {
					t.Errorf("the refusal repeats the manifest's text: %q", err)
				}
			})
		}
	}

	others := []struct {
		name   string
		edit   func(d map[string]any)
		reason string
	}{
		{"createdAt too long", func(d map[string]any) {
			d["createdAt"] = "2026-09-23T12:04:24." + strings.Repeat("0", maxTextBytes) + "Z"
		}, "createdAt is longer than"},
		{"version too long", func(d map[string]any) { pkgOf(d, 0)["version"] = "1.0.0-" + strings.Repeat("a", maxVersionBytes) }, "packages[0].version is longer than"},
		{"originalIntegrity too long", func(d map[string]any) {
			pkgOf(d, 0)["originalIntegrity"] = testIntegrity + strings.Repeat(" ", maxIntegrityBytes)
		}, "packages[0].originalIntegrity is longer than"},
	}
	for _, tt := range others {
		t.Run(tt.name, func(t *testing.T) {
			doc := manifestDoc()
			tt.edit(doc)
			_, err := ParseManifest(bytes.NewReader(encode(t, doc)))
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestParseManifestAcceptsTextAtTheBound(t *testing.T) {
	doc := manifestDoc()
	doc["toolVersion"] = strings.Repeat("a", maxTextBytes)
	doc["target"].(map[string]any)["os"] = strings.Repeat("é", maxTextBytes/2)
	pkgOf(doc, 0)["version"] = "1.0.0-" + strings.Repeat("a", maxVersionBytes-len("1.0.0-"))
	if _, err := ParseManifest(bytes.NewReader(encode(t, doc))); err != nil {
		t.Errorf("text of exactly the bound: %v", err)
	}
}

func TestParseManifestRefusesBadDocuments(t *testing.T) {
	big := append([]byte(`{"toolVersion":"`), bytes.Repeat([]byte("a"), MaxManifestSize)...)
	tests := []struct {
		name   string
		doc    string
		reason string
	}{
		{"over 16 MiB", string(big), "larger than"},
		{"not JSON", "<html>", "not valid JSON"},
		{"empty", "", "not valid JSON"},
		{"trailing data", string(encode(t, manifestDoc())) + `{"x":1}`, "after the manifest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseManifest(strings.NewReader(tt.doc))
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestParseManifestAtTheBound(t *testing.T) {
	data := encode(t, manifestDoc())
	pad := bytes.Repeat([]byte(" "), MaxManifestSize-len(data))
	if _, err := ParseManifest(io.MultiReader(bytes.NewReader(data), bytes.NewReader(pad))); err != nil {
		t.Errorf("a manifest of exactly %d bytes: %v", MaxManifestSize, err)
	}
}

func assertRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want a refusal containing %q, got none", reason)
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want a *Refusal containing %q, got %T: %v", reason, err, err)
	}
	if !strings.Contains(r.Reason, reason) {
		t.Errorf("reason = %q, want it to contain %q", r.Reason, reason)
	}
	if r.Error() != r.Reason {
		t.Errorf("Error() = %q, want the reason %q", r.Error(), r.Reason)
	}
}
