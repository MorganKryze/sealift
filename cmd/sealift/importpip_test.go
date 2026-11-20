package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importtest"
)

const (
	pipRepository = "pypi-hosted"
	pipUser       = "sealift-pip"
	pipPassword   = "pip-test-password"
)

// pipImport is a signed pip archive in its own folder, with settings that
// trust its key and name a pip repository.
type pipImport struct {
	dir, settings, report string
	files                 importtest.PipFiles
	pub                   ed25519.PublicKey
	priv                  ed25519.PrivateKey
}

func newPipImport(t *testing.T, n *importtest.PyPINexus, wheels ...importtest.WheelFile) pipImport {
	t.Helper()
	dir := t.TempDir()
	pub, priv := newKeyPair(t)
	p := pipImport{dir: dir, report: filepath.Join(dir, "report.json"), pub: pub, priv: priv}
	p.files = importtest.PipArchive(t, dir, priv, wheels...)
	for name, content := range map[string]string{
		"nexus-password": importPassword + "\n",
		"pip-password":   pipPassword + "\n",
		"public-key.pem": archive.PublicKeyPEM(pub),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p.settings = filepath.Join(dir, "settings.yaml")
	p.pointAt(t, n)
	return p
}

// pointAt rewrites the settings to publish to n.
func (p pipImport) pointAt(t *testing.T, n *importtest.PyPINexus) {
	t.Helper()
	writePipSettings(t, p.settings, n.URL.String())
}

func writePipSettings(t *testing.T, path, nexusURL string) {
	t.Helper()
	s := "nexus:\n  url: " + nexusURL + "\n  repository: npm-hosted\n  user: sealift-import\n  passwordFile: nexus-password\n" +
		"  pip:\n    repository: " + pipRepository + "\n    user: " + pipUser + "\n    passwordFile: pip-password\n" +
		"publicKeyFile: public-key.pem\n"
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (p pipImport) run(t *testing.T) (code int, out, errs string) {
	t.Helper()
	return runCmd(t, "-settings", p.settings, "-report", p.report, p.files.Archive)
}

type pipReport struct {
	Outcome   string
	Reason    string
	Ecosystem string
	Nexus     struct{ Repository string }
	Packages  []struct{ Name, State, Kind, Reason string }
}

func (p pipImport) readReport(t *testing.T) pipReport {
	t.Helper()
	b, err := os.ReadFile(p.report)
	if err != nil {
		t.Fatal(err)
	}
	var rep pipReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// states lists each package as "<name> <state> <kind>".
func (r pipReport) states() []string {
	out := make([]string, len(r.Packages))
	for i, p := range r.Packages {
		out[i] = strings.TrimSpace(p.Name + " " + p.State + " " + p.Kind)
	}
	return out
}

func pipWheels(t *testing.T) []importtest.WheelFile {
	return []importtest.WheelFile{
		importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any"),
		importtest.Wheel(t, "idna", "3.6", "py3-none-any"),
	}
}

func TestImportPipArchiveExitCodes(t *testing.T) {
	t.Run("published, then present on a second run", func(t *testing.T) {
		n := importtest.NewPyPINexus(t, pipRepository)
		p := newPipImport(t, n, pipWheels(t)...)
		code, out, errs := p.run(t)
		rep := p.readReport(t)
		if code != 0 || !slices.Equal(rep.states(), []string{"six published", "idna published"}) || n.Uploads() != 2 {
			t.Fatalf("exit %d, states %v, uploads %d, stdout %q, stderr %q", code, rep.states(), n.Uploads(), out, errs)
		}
		if rep.Ecosystem != "pip" || rep.Nexus.Repository != pipRepository {
			t.Errorf("ecosystem %q, repository %q", rep.Ecosystem, rep.Nexus.Repository)
		}
		if !strings.Contains(out, "target linux x86_64, python 3.11.2, glibc 2.28\n") {
			t.Errorf("stdout has no pip target:\n%s", out)
		}

		code, out, _ = p.run(t)
		rep = p.readReport(t)
		if code != 0 || !slices.Equal(rep.states(), []string{"six present", "idna present"}) || n.Uploads() != 2 {
			t.Errorf("second run: exit %d, states %v, uploads %d:\n%s", code, rep.states(), n.Uploads(), out)
		}
	})

	t.Run("a planted conflict, then the missing wheel alone", func(t *testing.T) {
		wheels := pipWheels(t)
		other := importtest.Wheel(t, "idna", "3.6", "py3-none-any", importtest.Entry{Name: "idna/extra.py", Body: []byte("x = 1\n")})
		n := importtest.NewPyPINexus(t, pipRepository)
		n.Put("idna", wheels[1].File, other.Body)
		p := newPipImport(t, n, wheels...)
		code, out, _ := p.run(t)
		rep := p.readReport(t)
		if code != 1 || !slices.Equal(rep.states(), []string{"six published", "idna failed conflict"}) || n.Uploads() != 1 {
			t.Fatalf("exit %d, states %v, uploads %d:\n%s", code, rep.states(), n.Uploads(), out)
		}
		if !strings.HasPrefix(rep.Packages[1].Reason, "nexus holds this file with other bytes: ") {
			t.Errorf("conflict reason %q", rep.Packages[1].Reason)
		}

		// The fake cannot delete a file, so the plant's removal is a Nexus
		// that holds only what the first run published.
		cleared := importtest.NewPyPINexus(t, pipRepository)
		cleared.Put("six", wheels[0].File, wheels[0].Body)
		p.pointAt(t, cleared)
		code, out, _ = p.run(t)
		rep = p.readReport(t)
		if code != 0 || !slices.Equal(rep.states(), []string{"six present", "idna published"}) || cleared.Uploads() != 1 {
			t.Errorf("third run: exit %d, states %v, uploads %d:\n%s", code, rep.states(), cleared.Uploads(), out)
		}
	})

	t.Run("a wheel whose METADATA names another version", func(t *testing.T) {
		newer := importtest.Wheel(t, "six", "1.17.0", "py2.py3-none-any")
		wheels := pipWheels(t)
		wheels[0] = importtest.WheelFile{Name: "six", Version: "1.16.0", File: "six-1.16.0-py2.py3-none-any.whl", Body: newer.Body}
		n := importtest.NewPyPINexus(t, pipRepository)
		p := newPipImport(t, n, wheels...)
		code, out, _ := p.run(t)
		rep := p.readReport(t)
		if code != 1 || !slices.Equal(rep.states(), []string{"six failed mismatch", "idna published"}) || n.Uploads() != 1 {
			t.Fatalf("exit %d, states %v, uploads %d:\n%s", code, rep.states(), n.Uploads(), out)
		}
		if want := `the wheel's METADATA says "six" "1.17.0", the manifest says six 1.16.0`; rep.Packages[0].Reason != want {
			t.Errorf("mismatch reason %q, want %q", rep.Packages[0].Reason, want)
		}
	})

	for name, tc := range map[string]struct {
		setup func(t *testing.T, n *importtest.PyPINexus, p pipImport)
		want  string
		nexus bool // the repository list was read before the refusal
	}{
		"no pip section": {
			setup: func(t *testing.T, n *importtest.PyPINexus, p pipImport) {
				s := "nexus:\n  url: " + n.URL.String() + "\n  repository: npm-hosted\n  user: sealift-import\n  passwordFile: nexus-password\npublicKeyFile: public-key.pem\n"
				if err := os.WriteFile(p.settings, []byte(s), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "reason: the settings name no pip repository: set nexus.pip.repository\n",
		},
		"pip repository listed as npm hosted": {
			setup: func(_ *testing.T, n *importtest.PyPINexus, _ pipImport) { n.SetRepository("npm", "hosted") },
			want:  `reason: nexus repository "pypi-hosted" is npm hosted, not pypi hosted` + "\n", nexus: true,
		},
		"signature by another key": {
			setup: func(t *testing.T, _ *importtest.PyPINexus, p pipImport) {
				_, other := newKeyPair(t)
				importtest.EditManifest(t, p.files, other, func(map[string]any) {})
			},
			want: "reason: the manifest is signed by another key, public key sha256 ",
		},
		"one byte changed in the archive": {
			setup: func(t *testing.T, _ *importtest.PyPINexus, p pipImport) {
				b, err := os.ReadFile(p.files.Archive)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)/2] ^= 0xff
				if err := os.WriteFile(p.files.Archive, b, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: " differs from the manifest's ", nexus: true,
		},
		"an entry the manifest does not list": {
			setup: func(t *testing.T, _ *importtest.PyPINexus, p pipImport) {
				importtest.EditManifest(t, p.files, p.priv, func(m map[string]any) {
					m["packages"] = m["packages"].([]any)[:1]
				})
			},
			want: "reason: out/idna-3.6-py3-none-any.whl is not listed in the manifest\n", nexus: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, pipRepository)
			p := newPipImport(t, n, pipWheels(t)...)
			tc.setup(t, n, p)
			code, out, errs := p.run(t)
			if code != 3 || !strings.Contains(out, tc.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q, want %q", code, out, errs, tc.want)
			}
			if rep := p.readReport(t); rep.Outcome != "refused" || len(rep.Packages) != 0 {
				t.Errorf("report %+v", rep)
			}
			var want []string
			if tc.nexus {
				want = []string{"GET /service/rest/v1/repositories"}
			}
			if got := n.Requests(); !slices.Equal(got, want) {
				t.Errorf("nexus requests %v, want %v", got, want)
			}
		})
	}

	t.Run("an npm archive with the same settings", func(t *testing.T) {
		f := newImportFixture(t)
		if err := os.WriteFile(filepath.Join(f.dir, "pip-password"), []byte(pipPassword+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writePipSettings(t, f.settings, f.nexus.srv.URL)
		code, out, errs := runCmd(t, "-settings", f.settings, "-report", f.report, f.archive)
		if code != 0 || !strings.HasPrefix(out, "import complete (unencrypted): 1 published, 0 present, 0 failed\n") {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
		}
		b, err := os.ReadFile(f.report)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{`"ecosystem":`, `"python":`, `"glibc":`} {
			if strings.Contains(string(b), key) {
				t.Errorf("an npm report holds %s:\n%s", key, b)
			}
		}
		if !strings.Contains(string(b), `"repository": "npm-hosted"`) {
			t.Errorf("an npm import does not publish to the npm repository:\n%s", b)
		}
	})
}

func TestPipImportPrintsNoSecret(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte(pipUser + ":" + pipPassword))
	for name, setup := range map[string]func(t *testing.T, n *importtest.PyPINexus, p pipImport){
		"complete": func(*testing.T, *importtest.PyPINexus, pipImport) {},
		"nexus refuses the credentials": func(_ *testing.T, n *importtest.PyPINexus, _ pipImport) {
			n.SetStatus("/service/rest/v1/repositories", http.StatusUnauthorized)
		},
		"upload refused": func(_ *testing.T, n *importtest.PyPINexus, _ pipImport) {
			n.SetStatus("/service/rest/v1/components", http.StatusForbidden)
		},
		"refused archive": func(t *testing.T, _ *importtest.PyPINexus, p pipImport) {
			_, other := newKeyPair(t)
			importtest.EditManifest(t, p.files, other, func(map[string]any) {})
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, pipRepository)
			p := newPipImport(t, n, pipWheels(t)...)
			setup(t, n, p)
			_, out, errs := p.run(t)
			rep, err := os.ReadFile(p.report)
			if err != nil {
				t.Fatal(err)
			}
			all := out + "\n" + errs + "\n" + string(rep)
			for _, secret := range []string{pipPassword, importPassword, basic, "Authorization"} {
				if strings.Contains(all, secret) {
					t.Errorf("output holds %q:\n%s", secret, all)
				}
			}
		})
	}
}
