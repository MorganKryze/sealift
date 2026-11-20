package importtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"os"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/pip"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// checkPipArchive reads f as the import does and fails t at the first check
// it does not pass: signature, ecosystem, manifest, archive, then each wheel.
func checkPipArchive(t *testing.T, f PipFiles, pub ed25519.PublicKey) (archive.PipManifest, []archive.CheckedWheel) {
	t.Helper()
	data := readFile(t, f.Manifest)
	if err := archive.CheckSignature(data, readFile(t, f.Signature), pub); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	eco, err := archive.ManifestEcosystem(data)
	if err != nil || eco != archive.Pip {
		t.Fatalf("ManifestEcosystem = %q, %v; want pip", eco, err)
	}
	m, err := archive.ParsePipManifest(data)
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	r, err := os.Open(f.Archive)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	checked, err := archive.VerifyPip(r, m, archive.VerifyOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("VerifyPip: %v", err)
	}
	for _, c := range checked {
		w, err := os.Open(c.Path)
		if err != nil {
			t.Fatal(err)
		}
		st, err := w.Stat()
		if err != nil {
			t.Fatal(err)
		}
		info, err := pip.InspectWheel(w, st.Size(), pip.WheelLimits{})
		_ = w.Close()
		if err != nil {
			t.Fatalf("InspectWheel(%s): %v", c.Wheel.File, err)
		}
		if pip.Normalize(info.Name) != c.Wheel.Name || !pip.SameVersion(info.Version, c.Wheel.Version) {
			t.Errorf("%s says it is %s %s, the manifest says %s %s", c.Wheel.File, info.Name, info.Version, c.Wheel.Name, c.Wheel.Version)
		}
	}
	return m, checked
}

func TestPipArchiveMeetsTheFormat(t *testing.T) {
	pub, key := newKey(t)
	wheels := []WheelFile{
		Wheel(t, "Demo.Pkg", "1.0", "py3-none-any"),
		Wheel(t, "MarkupSafe", "3.0.2", "cp311-cp311-manylinux_2_17_x86_64",
			Entry{Name: "markupsafe/_speedups.cpython-311-x86_64-linux-gnu.so", Body: []byte("\x7fELF\x02\x01\x01\x00")}),
	}
	if w := wheels[0]; w.Name != "demo-pkg" || w.Version != "1.0" || w.File != "demo_pkg-1.0-py3-none-any.whl" {
		t.Fatalf("Wheel gave %s %s in %s", w.Name, w.Version, w.File)
	}
	f := PipArchive(t, t.TempDir(), key, wheels...)

	data := readFile(t, f.Manifest)
	if _, err := archive.ParseManifest(data); err == nil {
		t.Error("the npm reader accepts the pip manifest")
	}
	m, checked := checkPipArchive(t, f, pub)
	if m.FormatVersion != 3 || m.Target != (archive.PipTarget{Python: "3.11.2", OS: "linux", CPU: "x86_64", Glibc: "2.28", UvVer: "0.13.7"}) {
		t.Errorf("manifest format %d, target %+v", m.FormatVersion, m.Target)
	}
	if len(checked) != len(wheels) {
		t.Fatalf("VerifyPip returned %d wheels, want %d", len(checked), len(wheels))
	}
	for i, c := range checked {
		w := wheels[i]
		sum := sha512.Sum512(w.Body)
		if c.Wheel.File != w.File || c.Wheel.Name != w.Name || !bytes.Equal(c.SHA512, sum[:]) {
			t.Errorf("wheel %d: %s %s with sha512 %x, want %s %s with %x", i, c.Wheel.Name, c.Wheel.File, c.SHA512, w.Name, w.File, sum)
		}
		if !bytes.Equal(readFile(t, c.Path), w.Body) {
			t.Errorf("%s: the archive carries other bytes", w.File)
		}
	}

	EditManifest(t, f, key, func(doc map[string]any) {
		doc["packages"].([]any)[0].(map[string]any)["version"] = "1.0.0"
	})
	edited, _ := checkPipArchive(t, f, pub)
	if edited.Packages[0].Version != "1.0.0" {
		t.Errorf("edited version = %s, want 1.0.0", edited.Packages[0].Version)
	}
	other, _ := newKey(t)
	if err := archive.CheckSignature(readFile(t, f.Manifest), readFile(t, f.Signature), other); err == nil {
		t.Error("another key verifies the edited manifest")
	}
}
