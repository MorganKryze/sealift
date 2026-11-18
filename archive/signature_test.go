package archive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

// rfc8032Seed is the seed of RFC 8032 section 7.1 test 1, a public vector.
const rfc8032Seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func rfc8032Key(t *testing.T) ed25519.PublicKey {
	t.Helper()
	seed, err := hex.DecodeString(rfc8032Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func TestPublicKeyPEM(t *testing.T) {
	pub := rfc8032Key(t)
	got := PublicKeyPEM(pub)
	if !strings.HasPrefix(got, "-----BEGIN PUBLIC KEY-----\n") || !strings.HasSuffix(got, "-----END PUBLIC KEY-----\n") {
		t.Fatalf("PublicKeyPEM = %q, want one PUBLIC KEY block ending in a newline", got)
	}
	block, rest := pem.Decode([]byte(got))
	if block == nil || len(rest) != 0 {
		t.Fatalf("PublicKeyPEM does not decode as one block: %q", got)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if !pub.Equal(parsed) {
		t.Errorf("the PEM holds another key than the one given")
	}
}

func TestPublicKeySHA256(t *testing.T) {
	pub := rfc8032Key(t)
	// The sha256 of the DER SubjectPublicKeyInfo, the value
	// `openssl pkey -pubin -outform DER | sha256sum` prints for this key.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])
	got := PublicKeySHA256(pub)
	if got != want {
		t.Errorf("PublicKeySHA256 = %s, want %s", got, want)
	}
	if len(got) != 64 || got != strings.ToLower(got) {
		t.Errorf("PublicKeySHA256 = %q, want 64 lowercase hex digits", got)
	}
	// The DER of an Ed25519 key is a fixed 12-byte header and the 32-byte key.
	if len(der) != 44 || hex.EncodeToString(der[12:]) != hex.EncodeToString(pub) {
		t.Errorf("DER = %x, want the SubjectPublicKeyInfo header then the key", der)
	}
}

func TestPublicKeyEncodingsIgnoreLineEndings(t *testing.T) {
	pub := rfc8032Key(t)
	crlf := strings.ReplaceAll(PublicKeyPEM(pub), "\n", "\r\n")
	block, _ := pem.Decode([]byte(crlf))
	if block == nil {
		t.Fatal("a CRLF PEM does not decode")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != PublicKeySHA256(pub) {
		t.Error("a CRLF in transit changed the fingerprint")
	}
}
