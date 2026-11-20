package importer

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportFields(t *testing.T) {
	r := newRunFixture(t)
	r.serveUploads()
	r.f.put("left-pad", "1.3.0", packed(t, "left-pad", "1.3.0", "left body")) // already there
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
	if !strings.Contains("\n"+text.String(), "\nimport version: "+doc["importVersion"].(string)+"\n") {
		t.Errorf("text has no import version line:\n%s", text.String())
	}
	for _, e := range pk {
		pkg := e.(map[string]any)
		line := pkg["name"].(string) + "@" + pkg["version"].(string) + " " + pkg["state"].(string) + " " + pkg["file"].(string)
		if !strings.Contains("\n"+text.String(), "\n"+line) {
			t.Errorf("text has no line starting %q:\n%s", line, text.String())
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
			r.opts.ExpectedSHA256 = wrongSHA256 // refused before any connection
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
	r.opts.ExpectedSHA256 = wrongSHA256
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
	if doc.Outcome != "refused" || !strings.Contains(doc.Reason, "differs from the expected sha256") {
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

func TestReportNamesTheTrustedKey(t *testing.T) {
	check := func(t *testing.T, rep Report, outcome string) {
		t.Helper()
		if rep.Outcome != outcome {
			t.Fatalf("outcome %q (%s), want %q", rep.Outcome, rep.Reason, outcome)
		}
		b, _ := json.Marshal(rep)
		var doc struct {
			PublicKeySha256 string `json:"publicKeySha256"`
		}
		if err := json.Unmarshal(b, &doc); err != nil || doc.PublicKeySha256 != testPubSHA {
			t.Errorf("json publicKeySha256 %q (%v), want %q:\n%s", doc.PublicKeySha256, err, testPubSHA, b)
		}
		var text bytes.Buffer
		_ = rep.WriteText(&text)
		if !strings.Contains("\n"+text.String(), "\npublic key sha256: "+testPubSHA+"\n") {
			t.Errorf("text has no public key sha256 line:\n%s", text.String())
		}
		lines := strings.Split(text.String(), "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "import version: ") && !strings.HasPrefix(lines[i+1], "public key sha256: ") {
				t.Errorf("the key line does not follow the import version line:\n%s", text.String())
			}
		}
	}
	t.Run("complete", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		check(t, r.run(t), OutcomeComplete)
	})
	t.Run("incomplete", func(t *testing.T) {
		r := newRunFixture(t)
		r.f.postStatus = 500
		check(t, r.run(t), OutcomeIncomplete)
	})
	t.Run("refused", func(t *testing.T) {
		r := newRunFixture(t)
		r.opts.ExpectedSHA256 = wrongSHA256
		check(t, r.run(t), OutcomeRefused)
	})
	t.Run("refused as unsigned", func(t *testing.T) {
		r := newRunFixture(t)
		if err := os.Remove(r.opts.Manifest + ".sig"); err != nil {
			t.Fatal(err)
		}
		check(t, r.run(t), OutcomeRefused)
	})
	t.Run("the early failure", func(t *testing.T) {
		r := newRunFixture(t)
		t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
		check(t, r.run(t), OutcomeRefused)
	})
	t.Run("a record from 0.4 has no field", func(t *testing.T) {
		var rep Report
		if err := json.Unmarshal([]byte(`{"outcome":"complete","archiveChecked":true}`), &rep); err != nil || rep.PublicKeySHA256 != "" {
			t.Fatalf("got %+v, %v", rep, err)
		}
		b, _ := json.Marshal(rep)
		if strings.Contains(string(b), "publicKeySha256") {
			t.Errorf("an empty key is written: %s", b)
		}
	})
}

func TestWriteTextPipTarget(t *testing.T) {
	rep := Report{
		Outcome: OutcomeComplete, ImportVersion: "0.7.0", Ecosystem: "pip",
		Archive:     ArchiveInfo{File: "packages_pip.tar.gz"},
		ToolVersion: "0.7.0", AnalysisID: "20261120T091500Z",
		Target:   TargetInfo{OS: "linux", CPU: "x86_64", Python: "3.11.2", Glibc: "2.28"},
		Nexus:    NexusInfo{URL: "https://nexus.example:8443", Repository: "pypi-hosted"},
		Counts:   Counts{Published: 1},
		Packages: []Result{{Name: "six", Version: "1.16.0", File: "six-1.16.0-py2.py3-none-any.whl", State: Published}},
	}
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	want := "\nmanifest: sealift 0.7.0, analysis 20261120T091500Z, target linux x86_64, python 3.11.2, glibc 2.28\n"
	if !strings.Contains("\n"+text.String(), want) {
		t.Errorf("text has no line %q:\n%s", strings.TrimSpace(want), text.String())
	}
	for _, npmOnly := range []string{"node ", "pnpm "} {
		if strings.Contains(text.String(), npmOnly) {
			t.Errorf("a pip report prints %q:\n%s", npmOnly, text.String())
		}
	}
	if !strings.Contains(text.String(), "\nsix@1.16.0 published six-1.16.0-py2.py3-none-any.whl\n") {
		t.Errorf("text has no wheel line:\n%s", text.String())
	}
}

func TestReportJSONKeysByEcosystem(t *testing.T) {
	pipKeys := []string{`"ecosystem":`, `"python":`, `"glibc":`}
	t.Run("npm report has no pip key", func(t *testing.T) {
		r := newRunFixture(t)
		r.serveUploads()
		rep := r.run(t)
		if rep.Outcome != OutcomeComplete {
			t.Fatalf("outcome %q (%s)", rep.Outcome, rep.Reason)
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		// "glibc" alone would match the npm value of libc.
		for _, k := range pipKeys {
			if bytes.Contains(b, []byte(k)) {
				t.Errorf("npm report holds %s: %s", k, b)
			}
		}
	})
	t.Run("pip report has every pip key", func(t *testing.T) {
		b, err := json.Marshal(Report{Ecosystem: "pip", Target: TargetInfo{OS: "linux", CPU: "x86_64", Python: "3.11.2", Glibc: "2.28"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{`"ecosystem":"pip"`, `"python":"3.11.2"`, `"glibc":"2.28"`} {
			if !bytes.Contains(b, []byte(k)) {
				t.Errorf("pip report lacks %s: %s", k, b)
			}
		}
	})
}
