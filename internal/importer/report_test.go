package importer

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestReportFields(t *testing.T) {
	r := newRunFixture(t)
	r.serveUploads()
	r.f.put("left-pad", "1.3.0", []byte("left body")) // already there
	rep := r.run(t)

	var doc map[string]any
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"outcome", "reason", "unencrypted", "importVersion", "archive", "toolVersion", "analysisId", "target", "nexus", "counts", "packages"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("no %q in %s", k, b)
		}
	}
	if doc["outcome"] != "complete" || doc["importVersion"] != "0.3.0" || doc["toolVersion"] != "0.3.0" || doc["analysisId"] != "20260923T120255Z" {
		t.Errorf("scalars = %s", b)
	}
	arch := doc["archive"].(map[string]any)
	if arch["file"] != "packages_npm.tar.gz" || len(arch["sha256"].(string)) != 64 || arch["size"].(float64) <= 0 {
		t.Errorf("archive = %v", arch)
	}
	if tg := doc["target"].(map[string]any); tg["os"] != "linux" || tg["cpu"] != "x64" || tg["libc"] != "glibc" || tg["node"] != "22.17.1" || tg["pnpmVer"] != "10.34.5" {
		t.Errorf("target = %v", tg)
	}
	if nx := doc["nexus"].(map[string]any); nx["url"] != r.f.srv.URL || nx["repository"] != testRepo {
		t.Errorf("nexus = %v", nx)
	}
	if c := doc["counts"].(map[string]any); c["published"] != 1.0 || c["present"] != 1.0 || c["failed"] != 0.0 {
		t.Errorf("counts = %v", c)
	}
	pk := doc["packages"].([]any)
	if len(pk) != 2 {
		t.Fatalf("packages = %v", pk)
	}
	p := pk[0].(map[string]any)
	for _, k := range []string{"name", "version", "file", "state", "reason", "note"} {
		if _, ok := p[k]; !ok {
			t.Errorf("package has no %q", k)
		}
	}
	if p["name"] != "left-pad" || p["state"] != "present" || pk[1].(map[string]any)["state"] != "published" {
		t.Errorf("packages = %v", pk)
	}

	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(text.String(), "\n"), "\n")
	if lines[0] != "import complete (unencrypted): 1 published, 1 present, 0 failed" {
		t.Errorf("first line = %q", lines[0])
	}
	for _, want := range []string{"packages_npm.tar.gz", "20260923T120255Z", "left-pad@1.3.0", "@scope/zeta@2.0.0", "present", "published"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
}

func TestReportMarksUnencrypted(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		want   bool
		first  string
	}{
		{"http", true, "import refused (unencrypted): 0 published, 0 present, 0 failed"},
		{"https", false, "import refused: 0 published, 0 present, 0 failed"},
	} {
		t.Run(tc.scheme, func(t *testing.T) {
			r := newRunFixture(t)
			r.opts.Settings.NexusURL, _ = url.Parse(tc.scheme + "://nexus.example.internal")
			r.opts.Settings.SignatureKey = Secret("other-key") // refused before any connection
			rep := r.run(t)
			if rep.Unencrypted != tc.want {
				t.Errorf("unencrypted = %v", rep.Unencrypted)
			}
			var text bytes.Buffer
			_ = rep.WriteText(&text)
			if first, _, _ := strings.Cut(text.String(), "\n"); first != tc.first {
				t.Errorf("first line = %q", first)
			}
		})
	}
}

func TestRefusedReport(t *testing.T) {
	r := newRunFixture(t)
	r.opts.Settings.SignatureKey = Secret("other-key")
	rep := r.run(t)
	b, _ := json.Marshal(rep)
	var doc struct {
		Outcome, Reason string
		Archive         struct {
			SHA256 string
			Size   int64
		}
		Counts   map[string]int
		Packages []any
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Outcome != "refused" || !strings.Contains(doc.Reason, "signature.key differs from the expected value") {
		t.Errorf("outcome %q reason %q", doc.Outcome, doc.Reason)
	}
	if doc.Counts["published"]+doc.Counts["present"]+doc.Counts["failed"] != 0 {
		t.Errorf("counts = %v", doc.Counts)
	}
	if !strings.Contains(string(b), `"packages":[]`) || len(doc.Packages) != 0 {
		t.Errorf("packages must be an empty list: %s", b)
	}
	if len(doc.Archive.SHA256) != 64 || doc.Archive.Size <= 0 {
		t.Errorf("archive block = %+v", doc.Archive)
	}
	var text bytes.Buffer
	_ = rep.WriteText(&text)
	if !strings.Contains(text.String(), "reason: "+rep.Reason) {
		t.Errorf("text lacks the reason:\n%s", text.String())
	}
	if strings.Contains(text.String(), "left-pad") {
		t.Errorf("a refused report lists no package:\n%s", text.String())
	}
}

func TestExitCode(t *testing.T) {
	for outcome, want := range map[string]int{"complete": 0, "incomplete": 1, "refused": 3} {
		if got := (Report{Outcome: outcome}).ExitCode(); got != want {
			t.Errorf("%s: %d, want %d", outcome, got, want)
		}
	}
}
