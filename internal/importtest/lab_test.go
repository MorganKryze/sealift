package importtest

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/pip"
)

// TestPackLabPipArchive packs the wheels of SEALIFT_LAB_PIP_WHEELS into a pip
// archive in SEALIFT_LAB_PIP_OUT, signed with a key made for this run, beside
// public-key.pem. The private key is never written.
func TestPackLabPipArchive(t *testing.T) {
	src, out := os.Getenv("SEALIFT_LAB_PIP_WHEELS"), os.Getenv("SEALIFT_LAB_PIP_OUT")
	if src == "" || out == "" {
		t.Skip("set SEALIFT_LAB_PIP_WHEELS to a directory of .whl files and SEALIFT_LAB_PIP_OUT to pack a lab archive")
	}
	files, err := filepath.Glob(filepath.Join(src, "*.whl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("%s holds no .whl file", src)
	}
	sort.Strings(files)
	var wheels []WheelFile
	for _, path := range files {
		body := readFile(t, path)
		info, err := pip.InspectWheel(bytes.NewReader(body), int64(len(body)), pip.WheelLimits{})
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		wheels = append(wheels, WheelFile{Name: pip.Normalize(info.Name), Version: info.Version, File: filepath.Base(path), Body: body})
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, key := newKey(t)
	f := PipArchive(t, out, key, wheels...)
	if err := os.WriteFile(filepath.Join(out, "public-key.pem"), []byte(archive.PublicKeyPEM(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	checkPipArchive(t, f, pub)
	t.Logf("packed %d wheels into %s, public key sha256 %s", len(wheels), out, archive.PublicKeySHA256(pub))
}
