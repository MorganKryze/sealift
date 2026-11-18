package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
}

// String names the key by its public key sha256.
func (k SigningKey) String() string {
	return "signing key, public key sha256 " + k.PublicKeySHA256
}

// GoString keeps %#v from printing the private field.
func (k SigningKey) GoString() string { return k.String() }

// Format keeps every verb, %d and %x included, from reaching the private field.
func (k SigningKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

func newSigningKey(priv ed25519.PrivateKey) SigningKey {
	pub := priv.Public().(ed25519.PublicKey)
	p := &priv
	return SigningKey{
		PublicPEM:       archive.PublicKeyPEM(pub),
		PublicKeySHA256: archive.PublicKeySHA256(pub),
		private:         &p,
	}
}

// SigningKey returns the key in use. Safe for concurrent use.
func (s *Store) SigningKey() SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.signing
}

// RegenerateSigningKey replaces the key pair with a new one, through a
// temporary file and a rename. The old key stays on disk and in use when the
// write fails.
func (s *Store) RegenerateSigningKey() (SigningKey, error) {
	s.regenerating.Lock()
	defer s.regenerating.Unlock()

	key, err := generateSigningKey(s.signingKeyPath())
	if err != nil {
		return SigningKey{}, err
	}
	s.mu.Lock()
	s.signing = &key
	s.mu.Unlock()
	return key, nil
}

func (s *Store) signingKeyPath() string {
	return filepath.Join(s.root, "private", signingKeyFile)
}

// loadSigningKey reads the key file, or generates and writes a key when there
// is none. A file that exists but cannot be used stops the start and is never
// replaced: a silent new key would break the import side's trust with no
// notice.
func loadSigningKey(path string) (SigningKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generateSigningKey(path)
	}
	if err != nil {
		return SigningKey{}, fmt.Errorf("store: signing key %s cannot be read: %w", path, err)
	}
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
