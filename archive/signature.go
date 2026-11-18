package archive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
)

// SignatureFile is the name of the file that carries a manifest's signature,
// beside manifest.json.
const SignatureFile = "manifest.json.sig"

// MaxSignatureSize bounds the signature file an import reads.
const MaxSignatureSize = 4 << 10

const signatureAlgorithm = "ed25519"

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// signatureDoc fixes the field order of the file SignatureFor writes.
type signatureDoc struct {
	Algorithm       string `json:"algorithm"`
	PublicKeySha256 string `json:"publicKeySha256"`
	Signature       string `json:"signature"`
}

// SignatureFor returns the bytes of the signature file for a pure Ed25519
// signature of a manifest, made by the key whose public key sha256 is given.
func SignatureFor(publicKeySHA256 string, sig []byte) ([]byte, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("archive: a signature is %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	out, err := json.MarshalIndent(signatureDoc{
		Algorithm:       signatureAlgorithm,
		PublicKeySha256: publicKeySHA256,
		Signature:       base64.StdEncoding.EncodeToString(sig),
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("archive: encode signature file: %w", err)
	}
	return append(out, '\n'), nil
}

// CheckSignature verifies manifest against the signature file with the
// trusted key and no other. The public key sha256 the file names only picks
// the wording of the refusal. Every refusal is a *Refusal that never quotes
// the file.
func CheckSignature(manifest, sigFile []byte, trusted ed25519.PublicKey) error {
	if len(trusted) != ed25519.PublicKeySize {
		return errors.New("archive: the trusted key is not an Ed25519 public key")
	}
	if len(sigFile) > MaxSignatureSize {
		return unreadable("it is larger than %d bytes", MaxSignatureSize)
	}
	var fields map[string]any
	if err := json.Unmarshal(sigFile, &fields); err != nil || fields == nil {
		return unreadable("it is not a JSON object")
	}
	if alg, _ := fields["algorithm"].(string); alg != signatureAlgorithm {
		return unreadable("its algorithm is not ed25519")
	}
	named, _ := fields["publicKeySha256"].(string)
	if !sha256Hex.MatchString(named) {
		return unreadable("its publicKeySha256 is not 64 lowercase hex digits")
	}
	encoded, _ := fields["signature"].(string)
	sig, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return unreadable("its signature is not base64 of exactly 64 bytes")
	}

	if ed25519.Verify(trusted, manifest, sig) {
		return nil
	}
	if want := PublicKeySHA256(trusted); named != want {
		return refuse("the manifest is signed by another key, public key sha256 %s; this import trusts %s. "+
			"If the connected side regenerated its key, carry its new public key here; otherwise export the archive again", named, want)
	}
	return refuse("the signature does not match the manifest: manifest.json or manifest.json.sig changed after the export. " +
		"Carry both again from the connected side")
}

func unreadable(problem string, args ...any) *Refusal {
	return refuse("%s is not a signature this import reads: %s", SignatureFile, fmt.Sprintf(problem, args...))
}

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
