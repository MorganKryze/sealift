package archive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

// PublicKeySHA256 returns the lowercase hex sha256 of pub's DER
// SubjectPublicKeyInfo encoding, the fingerprint both sides show.
func PublicKeySHA256(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKeyDER(pub))
	return hex.EncodeToString(sum[:])
}

// PublicKeyPEM returns pub as one PKIX "PUBLIC KEY" PEM block.
func PublicKeyPEM(pub ed25519.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER(pub)}))
}

// publicKeyDER panics on an error because x509.MarshalPKIXPublicKey fails only
// for a key type it does not know, and an Ed25519 key is one it knows.
func publicKeyDER(pub ed25519.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("archive: marshal ed25519 public key: " + err.Error())
	}
	return der
}
