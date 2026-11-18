package archive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// RFC 8032 section 7.1, tests 1 and 2: public vectors for pure Ed25519.
var rfc8032Vectors = []struct {
	name, seed, message, signature string
}{
	{
		"test 1, the empty message", rfc8032Seed, "",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	},
	{
		"test 2, one byte", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	},
}

type fileFields struct {
	Algorithm       string `json:"algorithm"`
	PublicKeySha256 string `json:"publicKeySha256"`
	Signature       string `json:"signature"`
}

func TestSignatureForIsPureEd25519(t *testing.T) {
	for _, v := range rfc8032Vectors {
		t.Run(v.name, func(t *testing.T) {
			seed, _ := hex.DecodeString(v.seed)
			msg, _ := hex.DecodeString(v.message)
			priv := ed25519.NewKeyFromSeed(seed)
			pub := priv.Public().(ed25519.PublicKey)
			file, err := SignatureFor(PublicKeySHA256(pub), ed25519.Sign(priv, msg))
			if err != nil {
				t.Fatalf("SignatureFor: %v", err)
			}
			var doc fileFields
			if err := json.Unmarshal(file, &doc); err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(doc.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(raw); got != v.signature {
				t.Errorf("signature = %s, want the RFC's %s", got, v.signature)
			}
			if err := CheckSignature(msg, file, pub); err != nil {
				t.Errorf("CheckSignature on the RFC vector: %v", err)
			}
		})
	}
}

func TestSignatureFor(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 64)
	sha := strings.Repeat("ab", 32)
	file, err := SignatureFor(sha, sig)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"algorithm\": \"ed25519\",\n  \"publicKeySha256\": \"" + sha + "\",\n  \"signature\": \"" +
		base64.StdEncoding.EncodeToString(sig) + "\"\n}\n"
	if string(file) != want {
		t.Errorf("file = %q, want %q", file, want)
	}
	if len(file) > MaxSignatureSize {
		t.Errorf("file is %d bytes, over %d", len(file), MaxSignatureSize)
	}
	for _, n := range []int{0, 63, 65} {
		if _, err := SignatureFor(sha, make([]byte, n)); err == nil {
			t.Errorf("SignatureFor accepted a %d-byte signature", n)
		}
	}
}

func signedFixture(t *testing.T) (manifest, file []byte, priv ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest = []byte("{\"formatVersion\": 2}\n")
	file, err = SignatureFor(PublicKeySHA256(priv.Public().(ed25519.PublicKey)), ed25519.Sign(priv, manifest))
	if err != nil {
		t.Fatal(err)
	}
	return manifest, file, priv
}

func withDoc(t *testing.T, file []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(file, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCheckSignature(t *testing.T) {
	manifest, file, priv := signedFixture(t)
	pub := priv.Public().(ed25519.PublicKey)
	if err := CheckSignature(manifest, file, pub); err != nil {
		t.Fatalf("a valid signature: %v", err)
	}
	if err := CheckSignature(manifest, withDoc(t, file, func(m map[string]any) { m["future"] = "ignored" }), pub); err != nil {
		t.Errorf("an unknown field must be ignored: %v", err)
	}

	_, other, _ := ed25519.GenerateKey(nil)
	otherSha := PublicKeySHA256(other.Public().(ed25519.PublicKey))
	trusted := PublicKeySHA256(pub)
	otherFile, err := SignatureFor(otherSha, ed25519.Sign(other, manifest))
	if err != nil {
		t.Fatal(err)
	}
	flippedManifest := append([]byte{}, manifest...)
	flippedManifest[3] ^= 1
	flippedSig := withDoc(t, file, func(m map[string]any) {
		raw, _ := base64.StdEncoding.DecodeString(m["signature"].(string))
		raw[0] ^= 1
		m["signature"] = base64.StdEncoding.EncodeToString(raw)
	})
	const read = "manifest.json.sig is not a signature this import reads: "
	tests := []struct {
		name     string
		manifest []byte
		file     []byte
		reason   string
	}{
		{"too large", manifest, append(bytes.Repeat([]byte(" "), MaxSignatureSize), file...), read + "it is larger than 4096 bytes"},
		{"not JSON", manifest, []byte("secret-looking text"), read + "it is not a JSON object"},
		{"a JSON array", manifest, []byte(`["x"]`), read + "it is not a JSON object"},
		{"JSON null", manifest, []byte(`null`), read + "it is not a JSON object"},
		{"wrong algorithm", manifest, withDoc(t, file, func(m map[string]any) { m["algorithm"] = "rsa-leak-me" }), read + "its algorithm is not ed25519"},
		{"algorithm missing", manifest, withDoc(t, file, func(m map[string]any) { delete(m, "algorithm") }), read + "its algorithm is not ed25519"},
		{"sha256 in capitals", manifest, withDoc(t, file, func(m map[string]any) { m["publicKeySha256"] = strings.ToUpper(trusted) }), read + "its publicKeySha256 is not 64 lowercase hex digits"},
		{"sha256 with a suffix", manifest, withDoc(t, file, func(m map[string]any) { m["publicKeySha256"] = trusted + " extra text" }), read + "its publicKeySha256 is not 64 lowercase hex digits"},
		{"sha256 with a prefix", manifest, withDoc(t, file, func(m map[string]any) { m["publicKeySha256"] = "extra text " + trusted }), read + "its publicKeySha256 is not 64 lowercase hex digits"},
		{"sha256 65 digits", manifest, withDoc(t, file, func(m map[string]any) { m["publicKeySha256"] = trusted + "0" }), read + "its publicKeySha256 is not 64 lowercase hex digits"},
		{"sha256 too short", manifest, withDoc(t, file, func(m map[string]any) { m["publicKeySha256"] = trusted[:63] }), read + "its publicKeySha256 is not 64 lowercase hex digits"},
		{"sha256 not a string", manifest, withDoc(t, file, func(m map[string]any) { m["publicKeySha256"] = 12 }), read + "its publicKeySha256 is not 64 lowercase hex digits"},
		{"signature not base64", manifest, withDoc(t, file, func(m map[string]any) { m["signature"] = "!!not base64!!" }), read + "its signature is not base64 of exactly 64 bytes"},
		{"signature 63 bytes", manifest, withDoc(t, file, func(m map[string]any) { m["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 63)) }), read + "its signature is not base64 of exactly 64 bytes"},
		{"signature without padding", manifest, withDoc(t, file, func(m map[string]any) {
			m["signature"] = strings.TrimRight(m["signature"].(string), "=")
		}), read + "its signature is not base64 of exactly 64 bytes"},
		{"another key", manifest, otherFile, "the manifest is signed by another key, public key sha256 " + otherSha +
			"; this import trusts " + trusted + ". If the connected side regenerated its key, carry its new public key here; otherwise export the archive again"},
		{"a byte of the manifest changed", flippedManifest, file, "the signature does not match the manifest: manifest.json or manifest.json.sig changed after the export. Carry both again from the connected side"},
		{"a byte of the signature changed", manifest, flippedSig, "the signature does not match the manifest: manifest.json or manifest.json.sig changed after the export. Carry both again from the connected side"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSignature(tt.manifest, tt.file, pub)
			var r *Refusal
			if !errors.As(err, &r) {
				t.Fatalf("err = %v, want a *Refusal", err)
			}
			if r.Reason != tt.reason {
				t.Errorf("reason = %q, want %q", r.Reason, tt.reason)
			}
			for _, leak := range []string{"secret-looking", "rsa-leak-me", "!!not base64!!"} {
				if strings.Contains(r.Reason, leak) {
					t.Errorf("reason quotes the file: %q", r.Reason)
				}
			}
		})
	}
}

func TestCheckSignatureTrustsOnlyTheConfiguredKey(t *testing.T) {
	manifest, _, _ := signedFixture(t)
	_, trustedPriv, _ := ed25519.GenerateKey(nil)
	trusted := trustedPriv.Public().(ed25519.PublicKey)
	_, forger, _ := ed25519.GenerateKey(nil)

	// The forger names the trusted key's sha256 and signs with its own key:
	// the file's claim picks the wording, never the verdict.
	forged, err := SignatureFor(PublicKeySHA256(trusted), ed25519.Sign(forger, manifest))
	if err != nil {
		t.Fatal(err)
	}
	err = CheckSignature(manifest, forged, trusted)
	var r *Refusal
	if !errors.As(err, &r) || !strings.HasPrefix(r.Reason, "the signature does not match the manifest") {
		t.Fatalf("a forged file naming the trusted key = %v, want the mismatch refusal", err)
	}

	// The forger names its own key: still refused, with the other-key wording.
	named, err := SignatureFor(PublicKeySHA256(forger.Public().(ed25519.PublicKey)), ed25519.Sign(forger, manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSignature(manifest, named, trusted); err == nil {
		t.Fatal("a signature by the key the file names was accepted")
	}
}
