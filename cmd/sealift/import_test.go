package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/npm"
)

const (
	importPassword = "test-password"
	importKey      = "test-key"
)

// nexusDouble answers the three endpoints the import uses and keeps what is
// uploaded under the path the import reads it back from.
type nexusDouble struct {
	srv    *httptest.Server
	mu     sync.Mutex
	files  map[string][]byte // by request path
	byFile map[string]string // upload file name to the path it is served at
	fail   bool
	hits   int
	held   chan struct{} // closed when an upload is held; nil means no hold
	freed  chan struct{} // the test closes it to let the held upload go
}

func newNexusDouble(t *testing.T, name, version string) *nexusDouble {
	t.Helper()
	n := &nexusDouble{files: map[string][]byte{}, byFile: map[string]string{npm.PackFileName(name, version): npm.TarballURL("/repository/npm-hosted", name, version)}}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.hits++
		switch {
		case r.URL.Path == "/service/rest/v1/repositories":
			_, _ = io.WriteString(w, `[{"name":"npm-hosted","format":"npm","type":"hosted"}]`)
		case r.Method == http.MethodPost:
			if n.fail {
				http.Error(w, "storage is full", http.StatusInternalServerError)
				return
			}
			mr, _ := r.MultipartReader()
			part, err := mr.NextPart()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			b, _ := io.ReadAll(part)
			if n.held != nil {
				n.mu.Unlock()
				close(n.held)
				<-n.freed
				n.mu.Lock()
			}
			n.files[n.byFile[part.FileName()]] = b
			w.WriteHeader(http.StatusNoContent)
		default:
			if b, ok := n.files[r.URL.Path]; ok {
				_, _ = w.Write(b)
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(n.srv.Close)
	return n
}

type importFixture struct {
	dir, settings, archive, manifest, report string
	nexus                                    *nexusDouble
}

func newImportFixture(t *testing.T) importFixture {
	t.Helper()
	dir := t.TempDir()
	nx := newNexusDouble(t, "left-pad", "1.3.0")
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("nexus-password", importPassword+"\n")
	write("signature-key", importKey+"\n")
	settings := write("settings.yaml", "nexus:\n  url: "+nx.srv.URL+"\n  repository: npm-hosted\n  user: sealift-import\n  passwordFile: nexus-password\nsignatureKeyFile: signature-key\n")

	body := "left body"
	sum := sha512.Sum512([]byte(body))
	var buf bytes.Buffer
	entries := []archive.Entry{
		{Name: "left-pad-1.3.0.tgz", Size: int64(len(body)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }},
		{Name: "signature.key", Size: int64(len(importKey)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(importKey)), nil }},
	}
	if err := archive.WriteTarGz(&buf, "out", entries); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buf.Bytes())
	doc, _ := json.Marshal(map[string]any{
		"formatVersion": 1, "toolVersion": "0.3.0", "analysisId": "A1", "createdAt": "2026-09-23T12:04:24Z",
		"target":  map[string]any{"os": "linux", "cpu": "x64", "libc": "glibc", "node": "22.17.1", "pnpmVer": "10.34.5"},
		"archive": map[string]any{"sha256": hex.EncodeToString(digest[:]), "size": buf.Len()},
		"packages": []any{map[string]any{
			"name": "left-pad", "version": "1.3.0", "file": "left-pad-1.3.0.tgz",
			"originalIntegrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]), "shippedSha512": hex.EncodeToString(sum[:]), "publishConfigStripped": false,
		}},
	})
	return importFixture{
		dir: dir, settings: settings, nexus: nx,
		archive:  write("packages_npm.tar.gz", buf.String()),
		manifest: write("manifest.json", string(doc)),
		report:   filepath.Join(dir, "report.json"),
	}
}

func (f importFixture) archiveSHA(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(f.archive)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func runCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = runImport(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestImportSubcommand(t *testing.T) {
	f := newImportFixture(t)
	code, out, errs := runCmd(t, "-settings", f.settings, "-report", f.report, f.archive)
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if first, _, _ := strings.Cut(out, "\n"); first != "import complete (unencrypted): 1 published, 0 present, 0 failed" {
		t.Errorf("first line = %q", first)
	}
	b, err := os.ReadFile(f.report)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Outcome       string
		ImportVersion string
		Packages      []struct{ Name, State string }
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Outcome != "complete" || rep.ImportVersion != jobs.ToolVersion || len(rep.Packages) != 1 || rep.Packages[0].State != "published" {
		t.Errorf("report = %s", b)
	}
	if got := f.nexus.files[npm.TarballURL("/repository/npm-hosted", "left-pad", "1.3.0")]; string(got) != "left body" {
		t.Errorf("nexus holds %q", got)
	}

	t.Run("manifest flag", func(t *testing.T) {
		moved := filepath.Join(t.TempDir(), "elsewhere.json")
		b, _ := os.ReadFile(f.manifest)
		_ = os.WriteFile(moved, b, 0o600)
		_ = os.Remove(f.manifest)
		code, out, errs := runCmd(t, "-settings", f.settings, "-manifest", moved, f.archive)
		if code != 0 || !strings.Contains(out, "1 present") {
			t.Errorf("exit %d, %s, %s", code, out, errs)
		}
	})
}

func TestImportExpectedSHA256(t *testing.T) {
	f := newImportFixture(t)
	sha := f.archiveSHA(t)
	for name, tc := range map[string]struct {
		sha  string
		code int
		want string
	}{
		"matching":        {sha, 0, "import complete"},
		"matching, upper": {strings.ToUpper(sha), 0, "import complete"},
		"different":       {strings.Repeat("0", 64), 3, "differs from the expected sha256"},
		"malformed":       {"abc", 2, "-sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runCmd(t, "-settings", f.settings, "-sha256", tc.sha, f.archive)
			if code != tc.code || !strings.Contains(out+errs, tc.want) {
				t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
			}
		})
	}
}

func TestImportExitCodes(t *testing.T) {
	for name, tc := range map[string]struct {
		setup  func(f importFixture) []string
		code   int
		stdout bool   // a report is printed
		want   string // in stdout or stderr
	}{
		"complete": {func(f importFixture) []string { return []string{"-settings", f.settings, f.archive} }, 0, true, "1 published"},
		"incomplete": {func(f importFixture) []string {
			f.nexus.fail = true
			return []string{"-settings", f.settings, f.archive}
		}, 1, true, "storage is full"},
		"refused": {func(f importFixture) []string {
			_ = os.WriteFile(filepath.Join(f.dir, "signature-key"), []byte("other-key\n"), 0o600)
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "signature.key differs from the expected value"},
		"no archive":      {func(f importFixture) []string { return []string{"-settings", f.settings} }, 2, false, "archive"},
		"two archives":    {func(f importFixture) []string { return []string{"-settings", f.settings, f.archive, f.archive} }, 2, false, "archive"},
		"no settings":     {func(f importFixture) []string { return []string{f.archive} }, 2, false, "-settings"},
		"unknown flag":    {func(f importFixture) []string { return []string{"-settings", f.settings, "-force", f.archive} }, 2, false, "force"},
		"archive missing": {func(f importFixture) []string { return []string{"-settings", f.settings, filepath.Join(f.dir, "none")} }, 2, false, "cannot open the archive"},
		"manifest missing": {func(f importFixture) []string {
			return []string{"-settings", f.settings, "-manifest", filepath.Join(f.dir, "none.json"), f.archive}
		}, 2, false, "cannot open the manifest"},
		"settings missing": {func(f importFixture) []string {
			return []string{"-settings", filepath.Join(f.dir, "none.yaml"), f.archive}
		}, 2, false, "settings file"},
		"settings invalid": {func(f importFixture) []string {
			_ = os.WriteFile(f.settings, []byte("insecure: true\n"), 0o600)
			return []string{"-settings", f.settings, f.archive}
		}, 2, false, "insecure"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newImportFixture(t)
			args := tc.setup(f)
			args = append([]string{"-report", f.report}, args...)
			code, out, errs := runCmd(t, args...)
			if code != tc.code || !strings.Contains(out+errs, tc.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
			}
			if tc.stdout != (out != "") {
				t.Errorf("stdout = %q", out)
			}
			if !tc.stdout {
				if strings.Count(errs, "\n") != 1 {
					t.Errorf("stderr must be one line: %q", errs)
				}
				if _, err := os.Stat(f.report); err == nil {
					t.Error("a usage or settings error wrote a report")
				}
			} else if _, err := os.Stat(f.report); err != nil {
				t.Errorf("no report: %v", err)
			}
		})
	}
}

func TestImportReportWriteFails(t *testing.T) {
	f := newImportFixture(t)
	bad := filepath.Join(f.dir, "no-such-dir", "report.json")
	code, out, errs := runCmd(t, "-settings", f.settings, "-report", bad, f.archive)
	if code != 1 || !strings.Contains(out, "import complete") || !strings.Contains(errs, "could not write the report") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

func TestSecretsNeverPrinted(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte("sealift-import:" + importPassword))
	for name, setup := range map[string]func(f importFixture){
		"complete":   func(importFixture) {},
		"incomplete": func(f importFixture) { f.nexus.fail = true },
		"refused": func(f importFixture) {
			_ = os.WriteFile(filepath.Join(f.dir, "signature-key"), []byte("other-key\n"), 0o600)
		},
		"unreadable password": func(f importFixture) { _ = os.Remove(filepath.Join(f.dir, "nexus-password")) },
		"usage":               func(importFixture) {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newImportFixture(t)
			setup(f)
			args := []string{"-settings", f.settings, "-report", f.report, f.archive}
			if name == "usage" {
				args = []string{"-settings", f.settings}
			}
			_, out, errs := runCmd(t, args...)
			rep, _ := os.ReadFile(f.report)
			all := out + "\n" + errs + "\n" + string(rep)
			for _, secret := range []string{importPassword, basic, importKey, "other-key", "Authorization"} {
				if strings.Contains(all, secret) {
					t.Errorf("output holds %q:\n%s", secret, all)
				}
			}
		})
	}
}

func TestImportStopsOnSignal(t *testing.T) {
	f := newImportFixture(t)
	f.nexus.held, f.nexus.freed = make(chan struct{}), make(chan struct{})
	// Registered after the double, so it runs first and frees the handler.
	t.Cleanup(func() { close(f.nexus.freed) })

	type result struct {
		code        int
		stdout, err string
	}
	done := make(chan result, 1)
	go func() {
		var out, errb bytes.Buffer
		code := runImport(context.Background(), []string{"-settings", f.settings, "-report", f.report, f.archive}, &out, &errb)
		done <- result{code, out.String(), errb.String()}
	}()
	<-f.nexus.held
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.code != 1 || res.err != "" {
		t.Fatalf("exit %d, stderr %q", res.code, res.err)
	}
	for _, want := range []string{"import incomplete", "0 published", "1 failed", "interrupted"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, res.stdout)
		}
	}
	b, err := os.ReadFile(f.report)
	if err != nil || !strings.Contains(string(b), `"reason": "interrupted"`) {
		t.Errorf("report %s, %v", b, err)
	}
}
