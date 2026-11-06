package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	// MaxKeySetBytes caps a key set response.
	MaxKeySetBytes = 1 << 20

	maxKeys        = 100              // keys read from one key set
	minRSABits     = 2048             // smaller RSA moduli are skipped
	maxRSABits     = 8192             // larger RSA moduli are skipped
	maxRSAExponent = 1<<31 - 1        // larger public exponents are skipped
	keySetTimeout  = 10 * time.Second // one fetch, connect to last byte
	keySetTTL      = 5 * time.Minute  // age at which the next token refetches the set
	refetchEvery   = 30 * time.Second // minimum gap between two fetch attempts
	keySetStale    = time.Hour        // age at which a held set is dropped
)

// publicKey is one usable key of the realm.
type publicKey struct {
	kty string // "RSA" or "EC"
	alg string // the JWK's alg, empty when it names none
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
}

// keySet caches the realm's keys behind one mutex, so no request fetches on its own.
type keySet struct {
	client *http.Client
	url    string
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]publicKey
	have      bool
	fetchedAt time.Time // when the held set arrived
	attemptAt time.Time // when the last fetch started, successful or not
}

// lookup returns the key for kid. It fetches the set on first use and every
// keySetTTL, and again for an unknown kid at most once per refetchEvery.
func (s *keySet) lookup(ctx context.Context, kid string) (publicKey, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.have && now.Sub(s.fetchedAt) >= keySetStale {
		s.have, s.keys = false, nil
	}
	attempted := false
	if !s.have || now.Sub(s.fetchedAt) >= keySetTTL {
		var err error
		attempted, err = s.refresh(ctx, now)
		if !s.have {
			return publicKey{}, false, err
		}
	}
	if k, ok := s.keys[kid]; ok {
		return k, true, nil
	}
	if !attempted {
		_, err := s.refresh(ctx, now)
		if !s.have {
			return publicKey{}, false, err
		}
	}
	k, ok := s.keys[kid]
	return k, ok, nil
}

// refresh fetches the set unless an attempt started less than refetchEvery ago.
// A failure leaves the held set, if any, untouched.
func (s *keySet) refresh(ctx context.Context, now time.Time) (bool, error) {
	if !s.attemptAt.IsZero() && now.Sub(s.attemptAt) < refetchEvery {
		return false, &Unavailable{Reason: "the last fetch of the key set was under 30 seconds ago"}
	}
	s.attemptAt = now
	keys, err := s.fetch(ctx)
	if err != nil {
		return true, err
	}
	s.keys, s.have, s.fetchedAt = keys, true, now
	return true, nil
}

// fetch reads the key set. Its reasons never carry the transport's error text.
func (s *keySet) fetch(ctx context.Context) (map[string]publicKey, error) {
	// The fetch is shared by every caller and counts as an attempt, so one
	// caller hanging up must not fail it; the client's timeout bounds it.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodGet, s.url, nil)
	if err != nil {
		return nil, &Unavailable{Reason: "the request for the key set could not be built"}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &Unavailable{Reason: "the key set could not be reached"}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &Unavailable{Reason: fmt.Sprintf("the key set answered HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxKeySetBytes+1))
	if err != nil {
		return nil, &Unavailable{Reason: "the key set could not be read"}
	}
	if len(body) > MaxKeySetBytes {
		return nil, &Unavailable{Reason: fmt.Sprintf("the key set is larger than %d bytes", MaxKeySetBytes)}
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &Unavailable{Reason: "the key set is not a JSON key set"}
	}
	keys := make(map[string]publicKey)
	for _, raw := range doc.Keys[:min(len(doc.Keys), maxKeys)] {
		kid, k, ok := parseJWK(raw)
		if _, dup := keys[kid]; ok && !dup {
			keys[kid] = k
		}
	}
	return keys, nil
}

type jwk struct {
	Kty, Kid, Alg, Use string
	N, E, Crv, X, Y    string
}

// parseJWK reads one key and reports false for any key it will not use: no
// kid, a use other than sig, an unknown type, a weak RSA key or a bad EC point.
func parseJWK(raw json.RawMessage) (string, publicKey, bool) {
	var j jwk
	if err := json.Unmarshal(raw, &j); err != nil || j.Kid == "" || (j.Use != "" && j.Use != "sig") {
		return "", publicKey{}, false
	}
	k := publicKey{kty: j.Kty, alg: j.Alg}
	switch j.Kty {
	case "RSA":
		k.rsa = parseRSA(j)
		return j.Kid, k, k.rsa != nil
	case "EC":
		k.ec = parseEC(j)
		return j.Kid, k, k.ec != nil
	}
	return "", publicKey{}, false
}

func parseRSA(j jwk) *rsa.PublicKey {
	n, err1 := base64.RawURLEncoding.DecodeString(j.N)
	e, err2 := base64.RawURLEncoding.DecodeString(j.E)
	if err1 != nil || err2 != nil {
		return nil
	}
	mod, exp := new(big.Int).SetBytes(n), new(big.Int).SetBytes(e)
	if mod.BitLen() < minRSABits || mod.BitLen() > maxRSABits {
		return nil
	}
	if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > maxRSAExponent || exp.Bit(0) == 0 {
		return nil
	}
	return &rsa.PublicKey{N: mod, E: int(exp.Int64())}
}

func parseEC(j jwk) *ecdsa.PublicKey {
	curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
	curve, ok := curves[j.Crv]
	if !ok {
		return nil
	}
	x, err1 := base64.RawURLEncoding.DecodeString(j.X)
	y, err2 := base64.RawURLEncoding.DecodeString(j.Y)
	size := (curve.Params().BitSize + 7) / 8
	if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
		return nil
	}
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil
	}
	return pub
}
