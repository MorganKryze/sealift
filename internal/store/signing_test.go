package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
)

func keyPath(root string) string { return filepath.Join(root, "private", "signing-key.pem") }

// leaks lists every form the private key's bytes could take in a text.
func leaks(t *testing.T, root string) []string {
	t.Helper()
	data, err := os.ReadFile(keyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", keyPath(root))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	seed := parsed.(ed25519.PrivateKey).Seed()
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	return []string{
		string(seed),
		hex.EncodeToString(seed),
		strings.ToUpper(hex.EncodeToString(seed)),
		base64.StdEncoding.EncodeToString(seed),
		base64.URLEncoding.EncodeToString(seed),
		body[24:56],
		"PRIVATE KEY",
		// What %d prints for the bytes of a struct field.
		strings.Trim(fmt.Sprintf("%d", seed), "[]"),
	}
}

func TestOpenGeneratesASigningKey(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := s.SigningKey()
	info, err := os.Stat(keyPath(root))
	if err != nil {
		t.Fatalf("the key file was not written: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %o, want 600", got)
	}
	if !strings.HasPrefix(key.PublicPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("PublicPEM = %q, want a PUBLIC KEY block", key.PublicPEM)
	}
	if len(key.PublicKeySHA256) != 64 {
		t.Errorf("PublicKeySHA256 = %q, want 64 hex digits", key.PublicKeySHA256)
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, "private", ".signing-key.pem.tmp-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}

	// A second start on the same volume keeps the key.
	again, err := Open(root)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if got := again.SigningKey(); got.PublicKeySHA256 != key.PublicKeySHA256 || got.PublicPEM != key.PublicPEM {
		t.Errorf("a restart changed the key: %s, want %s", got.PublicKeySHA256, key.PublicKeySHA256)
	}
}

func TestOpenRefusesADamagedSigningKey(t *testing.T) {
	ecdsaPEM := mustECDSAPKCS8(t)
	rows := []struct {
		name    string
		prepare func(t *testing.T, path string)
		problem string
	}{
		{"unreadable", func(t *testing.T, path string) {
			// A directory where the file should be: reading it fails.
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "cannot be read"},
		{"empty", func(t *testing.T, path string) { write(t, path, nil) }, "is not a PEM private key"},
		{"not PEM", func(t *testing.T, path string) { write(t, path, []byte("hello")) }, "is not a PEM private key"},
		{"a public key", func(t *testing.T, path string) {
			write(t, path, []byte(archive.PublicKeyPEM(ed25519PublicKey(t))))
		}, "is not a PEM private key"},
		{"damaged body", func(t *testing.T, path string) {
			write(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")}))
		}, "is not a PEM private key"},
		{"another algorithm", func(t *testing.T, path string) { write(t, path, ecdsaPEM) }, "is not an Ed25519 key"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "private"), 0o700); err != nil {
				t.Fatal(err)
			}
			path := keyPath(root)
			row.prepare(t, path)
			before := snapshot(t, path)

			_, err := Open(root)
			if err == nil {
				t.Fatal("Open succeeded on a damaged key file")
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name %s", err, path)
			}
			if !strings.Contains(err.Error(), row.problem) {
				t.Errorf("error %q does not say %q", err, row.problem)
			}
			if after := snapshot(t, path); after != before {
				t.Errorf("the key file changed: %q, was %q", after, before)
			}
		})
	}
}

func TestOpenRefusesAKeyFileItCannotWriteBeside(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "private"), 0o500); err != nil {
		t.Fatal(err)
	}
	_, err := Open(root)
	if err == nil {
		t.Fatal("Open succeeded without being able to write a key")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Errorf("error %q does not name the private directory", err)
	}
}

func TestPrivateDirModes(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(root, "private"): 0o700,
		keyPath(root):                  0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestSigningKeyNeverPrints(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	key := s.SigningKey()
	forbidden := leaks(t, root)

	outputs := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q", "%T %v"} {
		outputs[verb] = fmt.Sprintf(verb, key)
		outputs["ptr "+verb] = fmt.Sprintf(verb, &key)
	}
	type holder struct {
		Name  string
		Store *Store
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		outputs["store "+verb] = fmt.Sprintf(verb, s)
		outputs["holder "+verb] = fmt.Sprintf(verb, holder{Name: "h", Store: s})
	}
	type job struct {
		name string
		key  SigningKey
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		outputs["job "+verb] = fmt.Sprintf(verb, job{name: "j", key: key})
		outputs["ptr job "+verb] = fmt.Sprintf(verb, &job{name: "j", key: key})
	}
	outputs["Sprint"] = fmt.Sprint(key, []SigningKey{key}, map[string]SigningKey{"k": key})
	blob, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	outputs["json"] = string(blob)
	for name, handler := range map[string]func(*bytes.Buffer) slog.Handler{
		"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(handler(&buf)).Info("key", "key", key, "pointer", &key, "group", slog.GroupValue(slog.Any("k", key)))
		outputs[name] = buf.String()
	}

	for name, out := range outputs {
		for _, bad := range forbidden {
			if strings.Contains(out, bad) {
				t.Errorf("%s output holds a form of the private key (%d bytes matched)", name, len(bad))
			}
		}
	}
	for _, name := range []string{"%v", "%s", "%d", "%x"} {
		if !strings.Contains(outputs[name], key.PublicKeySHA256) {
			t.Errorf("%s output %q does not name the public sha256", name, outputs[name])
		}
	}
}

func TestReplaceSigningKeyWritesANewPairAndReturnsTheReplacedSha(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	old := s.SigningKey()
	oldBytes := snapshot(t, keyPath(root))

	got, replaced, err := ReplaceSigningKey(root, os.Getuid())
	if err != nil {
		t.Fatalf("ReplaceSigningKey: %v", err)
	}
	if got.PublicKeySHA256 == old.PublicKeySHA256 || got.PublicPEM == old.PublicPEM {
		t.Error("the replacement gave the same public key")
	}
	if replaced != old.PublicKeySHA256 {
		t.Errorf("replaced = %s, want the old key's %s", replaced, old.PublicKeySHA256)
	}
	if snapshot(t, keyPath(root)) == oldBytes {
		t.Error("the key file still holds the old key")
	}
	info, err := os.Stat(keyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 600", info.Mode().Perm())
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, "private", ".signing-key.pem.tmp-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.SigningKey().PublicKeySHA256 != got.PublicKeySHA256 {
		t.Error("a restart after a replacement loaded another key")
	}
}

func TestReplaceSigningKeyRefusesAVolumeWithNoKey(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := ReplaceSigningKey(root, os.Getuid())
	if err == nil {
		t.Fatal("ReplaceSigningKey wrote a key on a volume that held none")
	}
	if !strings.Contains(err.Error(), keyPath(root)) || !strings.Contains(err.Error(), "no signing key") {
		t.Errorf("error %q does not say no signing key is at %s", err, keyPath(root))
	}
	if _, err := os.Stat(keyPath(root)); !os.IsNotExist(err) {
		t.Errorf("a key file appeared: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "private"))
	if err != nil || len(entries) != 0 {
		t.Errorf("private/ holds %v, %v, want nothing", entries, err)
	}
}

func TestReplaceSigningKeyRefusesAnotherOwner(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, keyPath(root))

	_, _, err := ReplaceSigningKey(root, os.Getuid()+1)
	if err == nil {
		t.Fatal("ReplaceSigningKey replaced a key another user owns")
	}
	owner := fmt.Sprintf("belongs to uid %d", os.Getuid())
	if !strings.Contains(err.Error(), keyPath(root)) || !strings.Contains(err.Error(), owner) {
		t.Errorf("error %q does not name the file and say it %s", err, owner)
	}
	if snapshot(t, keyPath(root)) != before {
		t.Error("the key file changed")
	}
}

func TestReplaceSigningKeyLeavesTheOldKeyWholeOnAWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	root := t.TempDir()
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	oldBytes := snapshot(t, keyPath(root))
	private := filepath.Join(root, "private")
	if err := os.Chmod(private, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })

	if _, _, err := ReplaceSigningKey(root, os.Getuid()); err == nil {
		t.Fatal("ReplaceSigningKey succeeded in a read-only directory")
	} else if !strings.Contains(err.Error(), "private") {
		t.Errorf("error %q does not name the directory", err)
	}
	if snapshot(t, keyPath(root)) != oldBytes {
		t.Error("the key file changed after a failed write")
	}
}

func TestARunningStoreTakesTheReplacedKey(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	old := s.SigningKey()
	replacement, _, err := ReplaceSigningKey(root, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	now := s.SigningKey()
	if now.PublicKeySHA256 != replacement.PublicKeySHA256 || now.PublicPEM != replacement.PublicPEM {
		t.Fatalf("SigningKey() = %s, want the replacement %s (was %s)", now.PublicKeySHA256, replacement.PublicKeySHA256, old.PublicKeySHA256)
	}
	if err := now.Err(); err != nil {
		t.Fatalf("Err() = %v on a key that reads", err)
	}
	manifest := []byte("{}")
	file, err := now.SignManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.CheckSignature(manifest, file, publicKeyOf(t, replacement)); err != nil {
		t.Errorf("the signature does not verify with the replacement: %v", err)
	}
}

func TestARunningStoreSignsNothingWithAKeyFileThatDoesNotRead(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.SigningKey()
	write(t, keyPath(root), []byte("not a key"))

	key := s.SigningKey()
	if err := key.Err(); err == nil || !strings.Contains(err.Error(), keyPath(root)) {
		t.Errorf("Err() = %v, want an error naming %s", err, keyPath(root))
	}
	if _, err := key.SignManifest([]byte("{}")); err == nil {
		t.Error("a key file that does not read signed a manifest")
	} else if !strings.Contains(err.Error(), keyPath(root)) {
		t.Errorf("SignManifest error %q does not name the file", err)
	}
	if key.PublicKeySHA256 != "" || key.PublicPEM != "" {
		t.Errorf("public fields = %q, %q, want empty", key.PublicKeySHA256, key.PublicPEM)
	}
}

func TestARunningStoreTakesTheKeyBackWhenTheFileReadsAgain(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	good := snapshot(t, keyPath(root))
	want := s.SigningKey()
	write(t, keyPath(root), []byte("not a key"))
	if s.SigningKey().Err() == nil {
		t.Fatal("the damaged file was not noticed")
	}
	write(t, keyPath(root), []byte(good))

	got := s.SigningKey()
	if err := got.Err(); err != nil {
		t.Fatalf("Err() = %v after the file read again", err)
	}
	if got.PublicKeySHA256 != want.PublicKeySHA256 {
		t.Errorf("SigningKey() = %s, want %s", got.PublicKeySHA256, want.PublicKeySHA256)
	}
	if _, err := got.SignManifest([]byte("{}")); err != nil {
		t.Errorf("SignManifest: %v", err)
	}
}

func TestSigningKeyIsSafeForConcurrentUse(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			if _, _, err := ReplaceSigningKey(root, os.Getuid()); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 200 {
		if k := s.SigningKey(); len(k.PublicKeySHA256) != 64 || k.Err() != nil {
			t.Fatalf("a torn read: %q, %v", k.PublicKeySHA256, k.Err())
		}
	}
	<-done
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// snapshot returns a file's bytes, or a marker for a directory.
func snapshot(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		return "<dir>"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func ed25519PublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// mustECDSAPKCS8 returns a valid PKCS#8 PEM private key of another algorithm.
func mustECDSAPKCS8(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func publicKeyOf(t *testing.T, k SigningKey) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(k.PublicPEM))
	if block == nil {
		t.Fatal("the public PEM does not decode")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(ed25519.PublicKey)
}

func TestSignManifest(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := s.SigningKey()
	manifest := []byte("{\n  \"formatVersion\": 1\n}")
	file, err := key.SignManifest(manifest)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if err := archive.CheckSignature(manifest, file, publicKeyOf(t, key)); err != nil {
		t.Errorf("the file does not verify with the key's public half: %v", err)
	}
	var doc struct {
		Algorithm       string `json:"algorithm"`
		PublicKeySha256 string `json:"publicKeySha256"`
	}
	if err := json.Unmarshal(file, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Algorithm != "ed25519" || doc.PublicKeySha256 != key.PublicKeySHA256 {
		t.Errorf("file names %+v, want ed25519 and %s", doc, key.PublicKeySHA256)
	}
	for _, leak := range leaks(t, s.root) {
		if bytes.Contains(file, []byte(leak)) {
			t.Errorf("the signature file holds %q", leak)
		}
	}
}

func TestSignManifestRefusesAKeyWithNoPrivateHalf(t *testing.T) {
	if _, err := (SigningKey{}).SignManifest([]byte("x")); err == nil {
		t.Fatal("a zero SigningKey signed")
	}
}

func TestWriteFile(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json.sig")
	for _, content := range []string{"first", "second"} {
		if err := s.WriteFile(path, []byte(content)); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("file = %q, %v, want %q", got, err, content)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o664 {
		t.Errorf("mode = %v, want 0664", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries after the writes, want only the file", len(entries))
	}
}

// pemOfNewKey returns a fresh Ed25519 key's PEM and its public sha256.
func pemOfNewKey(t *testing.T) ([]byte, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), archive.PublicKeySHA256(pub)
}

func TestARunningStoreNoticesAnInPlaceRewriteWithTheSameMtime(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.SigningKey()
	info, err := os.Stat(keyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	data, sha := pemOfNewKey(t)
	if int64(len(data)) != info.Size() {
		t.Fatalf("the new key runs %d bytes, the old %d: the test needs the same size", len(data), info.Size())
	}
	f, err := os.OpenFile(keyPath(root), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath(root), info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}

	if got := s.SigningKey(); got.Err() != nil || got.PublicKeySHA256 != sha {
		t.Errorf("SigningKey() = %s (err %v), want the rewritten key %s", got.PublicKeySHA256, got.Err(), sha)
	}
}
