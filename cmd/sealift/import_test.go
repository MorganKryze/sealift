package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/npm"
)

const importPassword = "test-password"

// wrongSHA256 is a well-formed sha256 no test archive has.
const wrongSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

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
	dir, settings, archive, manifest, signature, report string
	nexus                                               *nexusDouble
	pub                                                 ed25519.PublicKey
	priv                                                ed25519.PrivateKey
}

// sign writes the signature file for the manifest's current bytes with the
// fixture's key, at path.
func (f importFixture) sign(t *testing.T, path string) {
	t.Helper()
	f.signWith(t, f.priv, path)
}

func (f importFixture) signWith(t *testing.T, priv ed25519.PrivateKey, path string) {
	t.Helper()
	data, err := os.ReadFile(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig, err := archive.SignatureFor(archive.PublicKeySHA256(pub), ed25519.Sign(priv, data))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, sig, 0o600); err != nil {
		t.Fatal(err)
	}
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
	pub, priv := newKeyPair(t)
	write("public-key.pem", archive.PublicKeyPEM(pub))
	settings := write("settings.yaml", "nexus:\n  url: "+nx.srv.URL+"\n  repository: npm-hosted\n  user: sealift-import\n  passwordFile: nexus-password\npublicKeyFile: public-key.pem\n")

	body := leftPadTarball(t)
	sum := sha512.Sum512([]byte(body))
	var buf bytes.Buffer
	entries := []archive.Entry{
		{Name: "left-pad-1.3.0.tgz", Size: int64(len(body)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }},
	}
	if err := archive.WriteTarGz(&buf, "out", entries); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buf.Bytes())
	doc, _ := json.Marshal(map[string]any{
		"formatVersion": 2, "toolVersion": "0.3.0", "analysisId": "A1", "createdAt": "2026-09-23T12:04:24Z",
		"target":  map[string]any{"os": "linux", "cpu": "x64", "libc": "glibc", "node": "22.17.1", "pnpmVer": "10.34.5"},
		"archive": map[string]any{"sha256": hex.EncodeToString(digest[:]), "size": buf.Len()},
		"packages": []any{map[string]any{
			"name": "left-pad", "version": "1.3.0", "file": "left-pad-1.3.0.tgz",
			"originalIntegrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]), "shippedSha512": hex.EncodeToString(sum[:]), "publishConfigStripped": false,
		}},
	})
	f := importFixture{
		dir: dir, settings: settings, nexus: nx, pub: pub, priv: priv,
		archive:  write("packages_npm.tar.gz", buf.String()),
		manifest: write("manifest.json", string(doc)),
		report:   filepath.Join(dir, "report.json"),
	}
	f.signature = f.manifest + ".sig"
	f.sign(t, f.signature)
	return f
}

// leftPadTarball returns a valid left-pad@1.3.0 package tarball.
func leftPadTarball(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range [][2]string{{"package/package.json", `{"name":"left-pad","version":"1.3.0"}`}, {"package/index.js", "left body"}} {
		if err := tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
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
	if got := f.nexus.files[npm.TarballURL("/repository/npm-hosted", "left-pad", "1.3.0")]; !bytes.Equal(got, []byte(leftPadTarball(t))) {
		t.Errorf("nexus holds %q", got)
	}

	t.Run("manifest flag", func(t *testing.T) {
		moved := filepath.Join(t.TempDir(), "elsewhere.json")
		b, _ := os.ReadFile(f.manifest)
		_ = os.WriteFile(moved, b, 0o600)
		_ = os.Rename(f.signature, moved+".sig")
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
		"different":       {wrongSHA256, 3, "differs from the expected sha256"},
		"malformed":       {"abc", 2, "-sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runCmd(t, "-settings", f.settings, "-sha256", tc.sha, f.archive)
			if code != tc.code || !strings.Contains(out+errs, tc.want) {
				t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
			}
		})
	}

	// The signature is checked whether or not a sha256 is given, and before
	// the archive's own digest is looked at.
	t.Run("an unsigned archive with the right sha256", func(t *testing.T) {
		f := newImportFixture(t)
		_ = os.Remove(f.signature)
		code, out, _ := runCmd(t, "-settings", f.settings, "-sha256", f.archiveSHA(t), f.archive)
		if code != 3 || !strings.Contains(out, "reason: "+archive.Unsigned("manifest.json.sig").Reason) {
			t.Errorf("with the sha256: exit %d, stdout %q", code, out)
		}
		code, out, _ = runCmd(t, "-settings", f.settings, f.archive)
		if code != 3 || !strings.Contains(out, "reason: "+archive.Unsigned("manifest.json.sig").Reason) {
			t.Errorf("without the sha256: exit %d, stdout %q", code, out)
		}
	})
	t.Run("a wrong sha256 on a changed manifest names the signature", func(t *testing.T) {
		f := newImportFixture(t)
		b, _ := os.ReadFile(f.manifest)
		_ = os.WriteFile(f.manifest, bytes.Replace(b, []byte(`"A1"`), []byte(`"A2"`), 1), 0o600)
		code, out, _ := runCmd(t, "-settings", f.settings, "-sha256", wrongSHA256, f.archive)
		if code != 3 || !strings.Contains(out, "the signature does not match the manifest") || strings.Contains(out, "expected sha256") {
			t.Errorf("exit %d, stdout %q", code, out)
		}
	})
}

func TestImportSignatureFlag(t *testing.T) {
	f := newImportFixture(t)
	elsewhere := filepath.Join(t.TempDir(), "carried.sig")
	if err := os.Rename(f.signature, elsewhere); err != nil {
		t.Fatal(err)
	}
	// The default names manifest.json.sig, which is gone.
	code, out, _ := runCmd(t, "-settings", f.settings, f.archive)
	if code != 3 || !strings.Contains(out, archive.Unsigned("manifest.json.sig").Reason) {
		t.Fatalf("default: exit %d, stdout %q", code, out)
	}
	// -signature names the file, and an absent one is reported under its own name.
	code, out, errs := runCmd(t, "-settings", f.settings, "-signature", elsewhere, f.archive)
	if code != 0 || errs != "" {
		t.Fatalf("-signature: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	code, out, _ = runCmd(t, "-settings", f.settings, "-signature", filepath.Join(f.dir, "none.sig"), f.archive)
	if code != 3 || !strings.Contains(out, archive.Unsigned("none.sig").Reason) {
		t.Errorf("absent -signature: exit %d, stdout %q", code, out)
	}
	// A manifest named by -manifest takes its own .sig by default.
	moved := filepath.Join(t.TempDir(), "elsewhere.json")
	b, _ := os.ReadFile(f.manifest)
	_ = os.WriteFile(moved, b, 0o600)
	_ = os.Rename(elsewhere, moved+".sig")
	if code, out, _ := runCmd(t, "-settings", f.settings, "-manifest", moved, f.archive); code != 0 {
		t.Errorf("-manifest default signature: exit %d, stdout %q", code, out)
	}
}

func TestImportLeavesTheSignatureUntouched(t *testing.T) {
	f := newImportFixture(t)
	before, _ := os.ReadFile(f.signature)
	infoBefore, _ := os.Stat(f.signature)
	if code, out, _ := runCmd(t, "-settings", f.settings, f.archive); code != 0 {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	after, _ := os.ReadFile(f.signature)
	infoAfter, _ := os.Stat(f.signature)
	if !bytes.Equal(before, after) || infoBefore.Mode() != infoAfter.Mode() || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Error("the signature file changed")
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
			return []string{"-settings", f.settings, "-sha256", wrongSHA256, f.archive}
		}, 3, true, "differs from the expected sha256"},
		"unsigned": {func(f importFixture) []string {
			_ = os.Remove(f.signature)
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, archive.Unsigned("manifest.json.sig").Reason},
		"unsigned, named by -signature": {func(f importFixture) []string {
			return []string{"-settings", f.settings, "-signature", filepath.Join(f.dir, "carried.sig"), f.archive}
		}, 3, true, archive.Unsigned("carried.sig").Reason},
		"signature larger than 4 KiB": {func(f importFixture) []string {
			_ = os.WriteFile(f.signature, bytes.Repeat([]byte(" "), archive.MaxSignatureSize+1), 0o600)
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "manifest.json.sig is not a signature this import reads: it is larger than 4096 bytes"},
		"signature not JSON": {func(f importFixture) []string {
			_ = os.WriteFile(f.signature, []byte("not json"), 0o600)
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "manifest.json.sig is not a signature this import reads: it is not a JSON object"},
		"signature algorithm": {func(f importFixture) []string {
			editSignature(t, f, func(d map[string]any) { d["algorithm"] = "rsa" })
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "manifest.json.sig is not a signature this import reads: its algorithm is not ed25519"},
		"signature key sha256 shape": {func(f importFixture) []string {
			editSignature(t, f, func(d map[string]any) { d["publicKeySha256"] = "ABC" })
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "manifest.json.sig is not a signature this import reads: its publicKeySha256 is not 64 lowercase hex digits"},
		"signature bytes": {func(f importFixture) []string {
			editSignature(t, f, func(d map[string]any) { d["signature"] = "AAAA" })
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "manifest.json.sig is not a signature this import reads: its signature is not base64 of exactly 64 bytes"},
		"another key": {func(f importFixture) []string {
			_, other := newKeyPair(t)
			f.signWith(t, other, f.signature)
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "the manifest is signed by another key, public key sha256 "},
		"one byte changed": {func(f importFixture) []string {
			b, _ := os.ReadFile(f.manifest)
			_ = os.WriteFile(f.manifest, bytes.Replace(b, []byte(`"A1"`), []byte(`"A2"`), 1), 0o600)
			return []string{"-settings", f.settings, f.archive}
		}, 3, true, "the signature does not match the manifest: manifest.json or manifest.json.sig changed after the export. Carry both again from the connected side"},
		"public key file missing": {func(f importFixture) []string {
			_ = os.Remove(filepath.Join(f.dir, "public-key.pem"))
			return []string{"-settings", f.settings, f.archive}
		}, 2, false, "publicKeyFile cannot be read"},
		"report named like the archive": {func(f importFixture) []string {
			return []string{"-settings", f.settings, "-report", f.archive, f.archive}
		}, 2, false, "-report names the archive"},
		"report named like the manifest": {func(f importFixture) []string {
			return []string{"-settings", f.settings, "-report", f.manifest, f.archive}
		}, 2, false, "-report names the manifest"},
		"report named like the signature": {func(f importFixture) []string {
			return []string{"-settings", f.settings, "-report", f.signature, f.archive}
		}, 2, false, "-report names the signature"},
		"report reaching the archive through a link": {func(f importFixture) []string {
			link := filepath.Join(f.dir, "link.json")
			if err := os.Symlink(f.archive, link); err != nil {
				t.Fatal(err)
			}
			return []string{"-settings", f.settings, "-report", link, f.archive}
		}, 2, false, "-report names the archive"},
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
			if !slices.Contains(args, "-report") {
				args = append([]string{"-report", f.report}, args...)
			}
			archiveBefore, _ := os.ReadFile(f.archive)
			code, out, errs := runCmd(t, args...)
			if code != tc.code || !strings.Contains(out+errs, tc.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
			}
			if after, _ := os.ReadFile(f.archive); !bytes.Equal(archiveBefore, after) {
				t.Error("the archive changed")
			}
			if tc.code == 3 && f.nexus.hits != 0 {
				t.Errorf("the nexus answered %d requests for a refused archive", f.nexus.hits)
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

// editSignature rewrites the fixture's signature file with edit applied to its fields.
func editSignature(t *testing.T, f importFixture, edit func(map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(f.signature)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(f.signature, out, 0o600); err != nil {
		t.Fatal(err)
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
			_, other := newKeyPair(t)
			f.signWith(t, other, f.signature)
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
			for _, secret := range []string{importPassword, basic, "Authorization"} {
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

func TestImportReportCarriesKinds(t *testing.T) {
	f := newImportFixture(t)
	f.nexus.files[npm.TarballURL("/repository/npm-hosted", "left-pad", "1.3.0")] = []byte("other bytes")
	code, out, errs := runCmd(t, "-settings", f.settings, "-report", f.report, f.archive)
	if code != 1 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	b, err := os.ReadFile(f.report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kind": "conflict"`, `"archiveChecked": true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("report lacks %s:\n%s", want, b)
		}
	}
	// The text output names the reason and does not print the kind.
	if !strings.Contains(out, "left-pad@1.3.0 failed left-pad-1.3.0.tgz: nexus holds this version with other bytes") || strings.Contains(out, "conflict") || strings.Contains(out, "archiveChecked") {
		t.Errorf("text output changed:\n%s", out)
	}

	// A refused archive is reported as not checked, with no kind.
	code, _, _ = runCmd(t, "-settings", f.settings, "-report", f.report, "-sha256", wrongSHA256, f.archive)
	b, _ = os.ReadFile(f.report)
	if code != 3 || !strings.Contains(string(b), `"archiveChecked": false`) || strings.Contains(string(b), `"kind"`) {
		t.Errorf("exit %d, refused report:\n%s", code, b)
	}
}
