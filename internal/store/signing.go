package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/MorganKryze/sealift/archive"
)

// signingKeyFile is the private key's name inside private/.
const signingKeyFile = "signing-key.pem"

// SigningKey is the Ed25519 key pair that signs exports. The private half is
// unexported and every way of printing the value names only the public sha256,
// so no log line, error or encoded answer can carry it.
type SigningKey struct {
	PublicPEM       string
	PublicKeySHA256 string

	// private is a pointer to a pointer to the key. A bad verb on a struct
	// that holds this value makes fmt print the field again at depth 0 and
	// dereference one pointer level; the second level stays an address.
	private **ed25519.PrivateKey

	// err names the key file when it does not read; such a key signs nothing.
	err error
}

// Err names the key file when it changed into one that does not read; such a
// key signs nothing.
func (k SigningKey) Err() error { return k.err }

// String names the key by its public key sha256.
func (k SigningKey) String() string {
	return "signing key, public key sha256 " + k.PublicKeySHA256
}

// GoString keeps %#v from printing the private field.
func (k SigningKey) GoString() string { return k.String() }

// Format keeps every verb, %d and %x included, from reaching the private field.
func (k SigningKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

// SignManifest returns the bytes of manifest.json.sig for manifest: a pure
// Ed25519 signature naming this key's public key sha256. It signs nothing
// else, so the key has one use.
func (k SigningKey) SignManifest(manifest []byte) ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	if k.private == nil || *k.private == nil {
		return nil, errors.New("store: this signing key has no private half")
	}
	return archive.SignatureFor(k.PublicKeySHA256, ed25519.Sign(**k.private, manifest))
}

func newSigningKey(priv ed25519.PrivateKey) SigningKey {
	pub := priv.Public().(ed25519.PublicKey)
	p := &priv
	return SigningKey{
		PublicPEM:       archive.PublicKeyPEM(pub),
		PublicKeySHA256: archive.PublicKeySHA256(pub),
		private:         &p,
	}
}

// keyStamp is the sha256 of the key file's bytes, which SigningKey compares
// to notice that the file changed. A digest, so printing a Store never
// prints the file.
type keyStamp [sha256.Size]byte

// SigningKey reads private/signing-key.pem again and parses it when its
// bytes changed, so a key replaced while the server runs signs the next
// export, an in-place rewrite included. A file that does not read gives a
// key whose Err names the file. Safe for concurrent use.
func (s *Store) SigningKey() SigningKey {
	path := s.signingKeyPath()
	data, err := readKeyFile(path)
	stamp := keyStamp(sha256.Sum256(data))
	if err == nil {
		s.mu.RLock()
		if s.keyRead && stamp == s.keyStamp {
			key := *s.signing
			s.mu.RUnlock()
			return key
		}
		s.mu.RUnlock()
	}

	var key SigningKey
	if err == nil {
		key, err = parseSigningKey(path, data)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		key = SigningKey{err: err}
	}
	s.signing, s.keyStamp, s.keyRead = &key, stamp, err == nil
	return key
}

// ReplaceSigningKey writes a new Ed25519 pair over root/private/signing-key.pem
// through a temporary file and a rename, and returns it with the replaced
// key's public sha256. It writes nothing when the file is missing or when uid
// does not own it.
func ReplaceSigningKey(root string, uid int) (key SigningKey, replaced string, err error) {
	path := filepath.Join(root, "private", signingKeyFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return SigningKey{}, "", fmt.Errorf("store: no signing key at %s: check the data volume", path)
	}
	if err != nil {
		return SigningKey{}, "", fmt.Errorf("store: signing key %s cannot be read: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return SigningKey{}, "", fmt.Errorf("store: signing key %s is not a regular file", path)
	}
	// A key written by another user, root through an exec included, is one
	// the server may not be able to read.
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != uid {
		return SigningKey{}, "", fmt.Errorf("store: signing key %s belongs to uid %d: run this command as that user, not as uid %d", path, sys.Uid, uid)
	}
	old, _, err := readSigningKey(path)
	if err != nil {
		return SigningKey{}, "", err
	}
	key, err = generateSigningKey(path)
	if err != nil {
		return SigningKey{}, "", err
	}
	return key, old.PublicKeySHA256, nil
}

func (s *Store) signingKeyPath() string {
	return filepath.Join(s.root, "private", signingKeyFile)
}

// loadSigningKey reads the key file, or generates and writes a key when there
// is none. A file that exists but cannot be used stops the start and is never
// replaced: a silent new key would break the import side's trust with no
// notice.
func loadSigningKey(path string) (SigningKey, keyStamp, error) {
	key, stamp, err := readSigningKey(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, err = generateSigningKey(path); err != nil {
			return SigningKey{}, keyStamp{}, err
		}
		return readSigningKey(path)
	}
	return key, stamp, err
}

// readSigningKey reads and parses the key file, and returns the stamp of
// what it read. Its errors name the file and never its content.
func readSigningKey(path string) (SigningKey, keyStamp, error) {
	data, err := readKeyFile(path)
	if err != nil {
		return SigningKey{}, keyStamp{}, err
	}
	key, err := parseSigningKey(path, data)
	if err != nil {
		return SigningKey{}, keyStamp{}, err
	}
	return key, keyStamp(sha256.Sum256(data)), nil
}

// readKeyFile returns the key file's bytes.
func readKeyFile(path string) ([]byte, error) {
	// O_NONBLOCK keeps a named pipe at the path from blocking the open;
	// the regular-file check then refuses it, a device too.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("store: signing key %s cannot be read: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("store: signing key %s cannot be read: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("store: signing key %s is not a regular file", path)
	}
	// A PEM Ed25519 key runs 119 bytes.
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("store: signing key %s cannot be read: %w", path, err)
	}
	return data, nil
}

// parseSigningKey parses the bytes of the key file at path.
func parseSigningKey(path string, data []byte) (SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return SigningKey{}, fmt.Errorf("store: signing key %s is not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return SigningKey{}, fmt.Errorf("store: signing key %s is not a PEM private key", path)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return SigningKey{}, fmt.Errorf("store: signing key %s is not an Ed25519 key", path)
	}
	return newSigningKey(priv), nil
}

func generateSigningKey(path string) (SigningKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, fmt.Errorf("store: generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return SigningKey{}, fmt.Errorf("store: encode signing key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atomicWriteFile(path, data, settingsMode); err != nil {
		return SigningKey{}, fmt.Errorf("store: write signing key: %w", err)
	}
	return newSigningKey(priv), nil
}
