package token

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://idp.test/realms/lab"
	testAudience = "sealift"
)

var epoch = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

func mustKey[K any](gen func() (K, error)) func() K {
	return sync.OnceValue(func() K {
		k, err := gen()
		if err != nil {
			panic(err)
		}
		return k
	})
}

// Keys are generated on first use and shared by the tests of one run.
var (
	rsaKey      = mustKey(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })
	otherRSAKey = mustKey(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })
	smallRSAKey = mustKey(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 1024) })
	p256Key     = mustKey(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
	p384Key     = mustKey(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) })
	p521Key     = mustKey(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) })
)

var allAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// signer is one algorithm with the key that signs for it.
type signer struct {
	alg  string
	key  crypto.Signer
	hash crypto.Hash
	pss  bool
	size int // bytes of r and s for ES
}

func signerFor(alg string) signer {
	hashes := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}
	s := signer{alg: alg, hash: hashes[alg[2:]]}
	switch alg[:2] {
	case "RS":
		s.key = rsaKey()
	case "PS":
		s.key, s.pss = rsaKey(), true
	default:
		switch alg {
		case "ES256":
			s.key, s.size = p256Key(), 32
		case "ES384":
			s.key, s.size = p384Key(), 48
		default:
			s.key, s.size = p521Key(), 66
		}
	}
	return s
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s signer) sign(input string) []byte {
	h := s.hash.New()
	h.Write([]byte(input))
	digest := h.Sum(nil)
	var opts crypto.SignerOpts = s.hash
	if s.pss {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: s.hash}
	}
	sig, err := s.key.Sign(rand.Reader, digest, opts)
	if err != nil {
		panic(err)
	}
	if s.size == 0 {
		return sig
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		panic(err)
	}
	out := make([]byte, 2*s.size)
	rs.R.FillBytes(out[:s.size])
	rs.S.FillBytes(out[s.size:])
	return out
}

func (s signer) jwk(kid string) map[string]any {
	switch k := s.key.Public().(type) {
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "kid": kid, "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			panic(err)
		}
		return map[string]any{"kty": "EC", "kid": kid, "crv": k.Curve.Params().Name, "x": b64(point[1 : 1+s.size]), "y": b64(point[1+s.size:])}
	}
	panic("unknown key")
}

func jsonB64(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b64(b)
}

// minter builds tokens against a clock.
type minter struct{ clock *clock }

func (m minter) claims(over map[string]any) map[string]any {
	c := map[string]any{
		"iss":                testIssuer,
		"aud":                testAudience,
		"exp":                m.clock.Now().Add(5 * time.Minute).Unix(),
		"preferred_username": "alice",
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// mint signs a token with the header {"alg", "kid"} plus extra header fields.
func (m minter) mint(s signer, kid string, claims map[string]any, extra map[string]any) string {
	header := map[string]any{"alg": s.alg}
	if kid != "" {
		header["kid"] = kid
	}
	for k, v := range extra {
		header[k] = v
	}
	input := jsonB64(header) + "." + jsonB64(m.claims(claims))
	return input + "." + b64(s.sign(input))
}

// hs256 signs with an HMAC keyed by the given bytes, the confusion attack.
func (m minter) hs256(kid string, secret []byte) string {
	input := jsonB64(map[string]any{"alg": "HS256", "kid": kid}) + "." + jsonB64(m.claims(nil))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + b64(mac.Sum(nil))
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: epoch} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// keySetServer serves a key set and counts the requests it gets.
type keySetServer struct {
	*httptest.Server
	mu      sync.Mutex
	body    []byte
	status  int
	fetches atomic.Int32
	strays  atomic.Int32 // requests to the redirect target
}

func newKeySetServer(t *testing.T, tls bool) *keySetServer {
	t.Helper()
	s := &keySetServer{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) {
		s.fetches.Add(1)
		s.mu.Lock()
		body, status := s.body, s.status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		http.Redirect(w, r, "/stray", http.StatusFound)
	})
	mux.HandleFunc("/stray", func(w http.ResponseWriter, _ *http.Request) {
		s.strays.Add(1)
		_, _ = w.Write(s.snapshot())
	})
	if tls {
		s.Server = httptest.NewTLSServer(mux)
	} else {
		s.Server = httptest.NewServer(mux)
	}
	t.Cleanup(s.Close)
	return s
}

func (s *keySetServer) snapshot() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body
}

func (s *keySetServer) set(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

// publish serves a key set holding the given keys by id.
func (s *keySetServer) publish(keys ...map[string]any) {
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err)
	}
	s.set(http.StatusOK, b)
}

func (s *keySetServer) url(path string) *url.URL {
	u, err := url.Parse(s.URL + path)
	if err != nil {
		panic(err)
	}
	return u
}

// env is a verifier over a key set server with a settable clock.
type env struct {
	srv   *keySetServer
	clock *clock
	ver   *Verifier
	mint  minter
}

// newEnv publishes "rs" (RSA), "es" (P-256) and the other keys given.
func newEnv(t *testing.T, extra ...map[string]any) *env {
	t.Helper()
	e := &env{srv: newKeySetServer(t, false), clock: newClock()}
	e.mint = minter{clock: e.clock}
	e.srv.publish(append([]map[string]any{signerFor("RS256").jwk("rs"), signerFor("ES256").jwk("es")}, extra...)...)
	e.ver = e.verifier(t, "/certs", "")
	return e
}

func (e *env) verifier(t *testing.T, path, caFile string) *Verifier {
	t.Helper()
	v, err := New(Config{KeySetURL: e.srv.url(path), Issuer: testIssuer, Audience: testAudience, CAFile: caFile, Now: e.clock.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func certFile(t *testing.T, s *httptest.Server) string {
	t.Helper()
	der := s.Certificate().Raw
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func padTo(n int, body []byte) []byte {
	return append(body, bytes.Repeat([]byte(" "), n-len(body))...)
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
