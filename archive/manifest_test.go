package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

const (
	testSHA256    = "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7"
	testSHA512Hex = "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4"
	testIntegrity = "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA=="
)

// manifestDoc returns a valid manifest as a generic document a case can edit.
func manifestDoc() map[string]any {
	return map[string]any{
		"formatVersion": 2,
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

	m, err := ParseManifest(encode(t, doc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.FormatVersion != 2 || m.Target.PnpmVer != "10.34.5" || m.Archive.Size != 7031361 || m.Archive.SHA256 != testSHA256 {
		t.Errorf("manifest = %+v", m)
	}
	if len(m.Packages) != 2 || m.Packages[1].Name != "@babel/code-frame" || !m.Packages[1].PublishConfigStripped {
		t.Errorf("packages = %+v", m.Packages)
	}
}

func TestParseManifestAcceptsAnEmptyLibc(t *testing.T) {
	doc := manifestDoc()
	doc["target"].(map[string]any)["libc"] = ""
	m, err := ParseManifest(encode(t, doc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.Target.Libc != "" || m.Target.OS != "linux" {
		t.Errorf("target = %+v", m.Target)
	}
}

func TestParseManifestRefuses(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(doc map[string]any)
		reason string
	}{
		{"format version 1", func(d map[string]any) { d["formatVersion"] = 1 }, "formatVersion is missing or not 2, the only version this import reads"},
		{"format version missing", func(d map[string]any) { delete(d, "formatVersion") }, "formatVersion is missing or not 2, the only version this import reads"},
		{"toolVersion missing", func(d map[string]any) { delete(d, "toolVersion") }, "toolVersion"},
		{"analysisId missing", func(d map[string]any) { delete(d, "analysisId") }, "analysisId"},
		{"createdAt missing", func(d map[string]any) { delete(d, "createdAt") }, "createdAt"},
		{"createdAt malformed", func(d map[string]any) { d["createdAt"] = "yesterday" }, "createdAt"},
		{"target missing", func(d map[string]any) { delete(d, "target") }, "target.os"},
		{"target os missing", func(d map[string]any) { delete(d["target"].(map[string]any), "os") }, "target.os"},
		{"target cpu missing", func(d map[string]any) { delete(d["target"].(map[string]any), "cpu") }, "target.cpu"},
		{"target libc missing", func(d map[string]any) { delete(d["target"].(map[string]any), "libc") }, "target.libc"},
		{"target libc null", func(d map[string]any) { d["target"].(map[string]any)["libc"] = nil }, "target.libc"},
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
			_, err := ParseManifest(encode(t, doc))
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
			_, err := ParseManifest(encode(t, doc))
			assertRefusal(t, err, f.name+" is longer than")
		})
		for kind, value := range unsafe {
			t.Run(f.name+" "+kind, func(t *testing.T) {
				doc := manifestDoc()
				f.set(doc, "x"+value)
				_, err := ParseManifest(encode(t, doc))
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
			_, err := ParseManifest(encode(t, doc))
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestParseManifestAcceptsTextAtTheBound(t *testing.T) {
	doc := manifestDoc()
	doc["toolVersion"] = strings.Repeat("a", maxTextBytes)
	doc["target"].(map[string]any)["os"] = strings.Repeat("é", maxTextBytes/2)
	pkgOf(doc, 0)["version"] = "1.0.0-" + strings.Repeat("a", maxVersionBytes-len("1.0.0-"))
	if _, err := ParseManifest(encode(t, doc)); err != nil {
		t.Errorf("text of exactly the bound: %v", err)
	}
}

func TestParseManifestRefusesBadDocuments(t *testing.T) {
	tests := []struct {
		name   string
		doc    string
		reason string
	}{
		{"not JSON", "<html>", "not valid JSON"},
		{"empty", "", "not valid JSON"},
		{"trailing data", string(encode(t, manifestDoc())) + `{"x":1}`, "after the manifest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tt.doc))
			assertRefusal(t, err, tt.reason)
		})
	}
}

func TestReadManifestBound(t *testing.T) {
	data := encode(t, manifestDoc())
	pad := bytes.Repeat([]byte(" "), MaxManifestSize-len(data))
	exact := io.MultiReader(bytes.NewReader(data), bytes.NewReader(pad))
	got, err := ReadManifest(exact)
	if err != nil || len(got) != MaxManifestSize {
		t.Fatalf("a manifest of exactly %d bytes: %d bytes, %v", MaxManifestSize, len(got), err)
	}
	if _, err := ParseManifest(got); err != nil {
		t.Errorf("ParseManifest of the exact-bound manifest: %v", err)
	}

	over := io.MultiReader(bytes.NewReader(data), bytes.NewReader(pad), strings.NewReader(" "))
	_, err = ReadManifest(over)
	assertRefusal(t, err, "the manifest is larger than 16777216 bytes")

	_, err = ReadManifest(iotest.ErrReader(errors.New("disk gone")))
	var r *Refusal
	if err == nil || errors.As(err, &r) {
		t.Errorf("a read failure is a local error, not a refusal: %v", err)
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

func TestParseManifestReadsAReview(t *testing.T) {
	doc := manifestDoc()
	doc["review"] = reviewDoc("express", "4.17.1", "5.1.0")
	m, err := ParseManifest(encode(t, doc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.ReviewProblem != "" {
		t.Fatalf("ReviewProblem = %q", m.ReviewProblem)
	}
	if want := wantReview("express", "4.17.1", "5.1.0"); !reflect.DeepEqual(m.Review, want) {
		t.Errorf("Review = %+v, want %+v", m.Review, want)
	}
}

func TestParseManifestReadsAReviewWithoutProjectedCounts(t *testing.T) {
	doc := manifestDoc()
	doc["review"] = map[string]any{"cves": map[string]any{"before": []any{0, 0, 0, 0, 0}}}
	m, err := ParseManifest(encode(t, doc))
	if err != nil || m.ReviewProblem != "" || m.Review == nil {
		t.Fatalf("ParseManifest = %+v, %v", m, err)
	}
	if m.Review.CVEs.After != nil || m.Review.Updates != nil || m.Review.Left != nil || m.Review.Unchanged != 0 {
		t.Errorf("Review = %+v", m.Review)
	}
}

func TestParseManifestWithoutAReviewReadsNotCarried(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"absent": func(map[string]any) {},
		"null":   func(d map[string]any) { d["review"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			doc := manifestDoc()
			edit(doc)
			m, err := ParseManifest(encode(t, doc))
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if m.Review != nil || m.ReviewProblem != "" {
				t.Errorf("Review = %+v, ReviewProblem = %q", m.Review, m.ReviewProblem)
			}
		})
	}
}

func repeated(entry map[string]any, n int) []any {
	list := make([]any, n)
	for i := range list {
		list[i] = entry
	}
	return list
}

// TestTheReviewListsHoldTheirBound reads each list of a review at its bound.
func TestTheReviewListsHoldTheirBound(t *testing.T) {
	tests := []struct {
		name string
		edit func(r map[string]any)
		got  func(r *Review) int
	}{
		{"updates", func(r map[string]any) { r["updates"] = repeated(entryOf(r, "updates", 0), maxReviewEntries) }, func(r *Review) int { return len(r.Updates) }},
		{"kept", func(r map[string]any) { r["kept"] = repeated(entryOf(r, "kept", 0), maxReviewEntries) }, func(r *Review) int { return len(r.Kept) }},
		{"jumps", func(r map[string]any) { r["jumps"] = repeated(entryOf(r, "jumps", 1), maxReviewEntries) }, func(r *Review) int { return len(r.Jumps) }},
		{"packages of a jump", func(r map[string]any) {
			j := entryOf(r, "jumps", 0)
			j["packages"] = repeated(j["packages"].([]any)[0].(map[string]any), maxReviewEntries)
		}, func(r *Review) int { return len(r.Jumps[0].Packages) }},
		{"left", func(r map[string]any) { r["left"] = repeated(entryOf(r, "left", 1), maxReviewEntries) }, func(r *Review) int { return len(r.Left) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := manifestDoc()
			doc["review"] = reviewDoc("express", "4.17.1", "5.1.0")
			tt.edit(reviewOf(doc))
			m, err := ParseManifest(encode(t, doc))
			if err != nil {
				t.Fatal(err)
			}
			if m.Review == nil {
				t.Fatalf("the review was kept out: %s", m.ReviewProblem)
			}
			if n := tt.got(m.Review); n != maxReviewEntries {
				t.Errorf("read %d entries, want %d", n, maxReviewEntries)
			}
		})
	}
}

func TestAnUnreadableReviewRefusesNothing(t *testing.T) {
	many := make([]any, maxReviewEntries+1)
	for i := range many {
		many[i] = map[string]any{}
	}
	tests := []struct {
		name    string
		edit    func(review map[string]any, doc map[string]any)
		problem string
	}{
		{"a string", func(_, d map[string]any) { d["review"] = "owned" }, "review is not an object"},
		{"a vector of 4", func(r, _ map[string]any) {
			r["cves"].(map[string]any)["before"] = []any{1, 2, 3, 4}
		}, "review.cves.before does not hold 5 counts"},
		{"a vector of 6", func(r, _ map[string]any) {
			entryOf(r, "updates", 0)["fixed"] = []any{1, 2, 3, 4, 5, 6}
		}, "review.updates[0].fixed does not hold 5 counts"},
		{"a null count", func(r, _ map[string]any) {
			entryOf(r, "updates", 0)["left"] = []any{0, nil, 0, 0, 0}
		}, "review.updates[0].left holds a null count"},
		{"a null count before", func(r, _ map[string]any) {
			r["cves"].(map[string]any)["before"] = []any{nil, 0, 0, 0, 0}
		}, "review.cves.before holds a null count"},
		{"a negative count", func(r, _ map[string]any) {
			r["cves"].(map[string]any)["after"] = []any{0, 0, -1, 0, 0}
		}, "review.cves.after holds a negative count"},
		{"no counts before", func(r, _ map[string]any) { delete(r, "cves") }, "review.cves.before is missing"},
		{"a severity SEVERE", func(r, _ map[string]any) { entryOf(r, "left", 1)["severity"] = "SEVERE" }, "review.left[1].severity is not one of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN"},
		{"a reason with a bidi override", func(r, _ map[string]any) {
			entryOf(r, "jumps", 0)["reason"] = "owned\u202eevil"
		}, "review.jumps[0].reason holds a control, line-separating, bidirectional or format character"},
		{"a jump without reason", func(r, _ map[string]any) { delete(entryOf(r, "jumps", 1), "reason") }, "review.jumps[1].reason is empty"},
		{"a version of 300 bytes", func(r, _ map[string]any) {
			entryOf(r, "updates", 0)["to"] = "1.0.0-owned" + strings.Repeat("a", 300-len("1.0.0-owned"))
		}, "review.updates[0].to is longer than 256 bytes"},
		{"a range for a version", func(r, _ map[string]any) { entryOf(r, "kept", 0)["version"] = "^4.0.0-owned" }, "review.kept[0].version is not an exact version"},
		{"an invalid name", func(r, _ map[string]any) {
			entryOf(r, "jumps", 0)["packages"].([]any)[0].(map[string]any)["name"] = "../owned"
		}, "review.jumps[0].packages[0].name is not a valid package name"},
		{"an id with an escape sequence", func(r, _ map[string]any) {
			entryOf(r, "left", 0)["id"] = "owned\x1b[2J"
		}, "review.left[0].id holds a control or unprintable character"},
		{"a kept CVE's reason with a bidi override", func(r, _ map[string]any) {
			entryOf(r, "left", 0)["reason"] = "owned\u202eevil"
		}, "review.left[0].reason holds a control, line-separating, bidirectional or format character"},
		{"a fixing version with an escape sequence", func(r, _ map[string]any) {
			entryOf(r, "left", 1)["fixedIn"] = "owned\x1b[2J"
		}, "review.left[1].fixedIn holds a control or unprintable character"},
		{"an invalid package of a kept CVE", func(r, _ map[string]any) { entryOf(r, "left", 0)["package"] = "../owned" }, "review.left[0].package is not a valid package name"},
		{"a jump that is not an exact version", func(r, _ map[string]any) { entryOf(r, "kept", 0)["jump"] = "owned\n" }, "review.kept[0].jump is not an exact version"},
		{"a family of 300 bytes", func(r, _ map[string]any) {
			entryOf(r, "jumps", 0)["family"] = "owned" + strings.Repeat("a", 300)
		}, "review.jumps[0].family is longer than 256 bytes"},
		{"a count of the wrong type", func(r, _ map[string]any) { r["unchanged"] = "owned" }, "review.unchanged has the wrong type"},
		{"100,001 left", func(r, _ map[string]any) { r["left"] = repeated(entryOf(r, "left", 1), maxReviewEntries+1) }, "review.left holds more than 100000 entries"},
		{"100,001 updates", func(r, _ map[string]any) { r["updates"] = repeated(entryOf(r, "updates", 0), maxReviewEntries+1) }, "review.updates holds more than 100000 entries"},
		{"100,001 kept", func(r, _ map[string]any) { r["kept"] = repeated(entryOf(r, "kept", 0), maxReviewEntries+1) }, "review.kept holds more than 100000 entries"},
		{"100,001 jumps", func(r, _ map[string]any) { r["jumps"] = repeated(entryOf(r, "jumps", 1), maxReviewEntries+1) }, "review.jumps holds more than 100000 entries"},
		{"100,001 packages in a jump", func(r, _ map[string]any) {
			j := entryOf(r, "jumps", 0)
			j["packages"] = repeated(j["packages"].([]any)[0].(map[string]any), maxReviewEntries+1)
		}, "review.jumps[0].packages holds more than 100000 entries"},
		{"many empty entries", func(r, _ map[string]any) { r["left"] = many }, "review.left holds more than 100000 entries"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := manifestDoc()
			doc["review"] = reviewDoc("express", "4.17.1", "5.1.0")
			tt.edit(reviewOf(doc), doc)
			m, err := ParseManifest(encode(t, doc))
			if err != nil {
				t.Fatalf("an unreadable review refused the manifest: %v", err)
			}
			if len(m.Packages) != 1 || m.Packages[0].Name != "express" || m.Archive.SHA256 != testSHA256 {
				t.Errorf("the manifest lost its packages: %+v", m)
			}
			if m.Review != nil {
				t.Errorf("Review = %+v, want nil", m.Review)
			}
			if !strings.Contains(m.ReviewProblem, tt.problem) {
				t.Errorf("ReviewProblem = %q, want it to contain %q", m.ReviewProblem, tt.problem)
			}
			assertRepeatsNoValue(t, errors.New(m.ReviewProblem))
			for _, value := range []string{"SEVERE", "aaaa"} {
				if strings.Contains(m.ReviewProblem, value) {
					t.Errorf("ReviewProblem repeats a value: %q", m.ReviewProblem)
				}
			}
		})
	}
}
