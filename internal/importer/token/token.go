// Package token checks the access tokens a gateway forwards, against the
// signing keys of one realm. It imports nothing from sealift.
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// MaxTokenBytes caps a token before it is decoded.
	MaxTokenBytes = 16 << 10
	// Leeway is the clock tolerance on exp and nbf.
	Leeway = 60 * time.Second
)

// Config names the realm. Now nil means time.Now.
type Config struct {
	KeySetURL        *url.URL
	Issuer, Audience string
	CAFile           string
	Now              func() time.Time
}

// Claims are the payload of a checked token.
type Claims map[string]json.RawMessage

// String returns a claim that is a JSON string. It reports false when the claim is absent or of another type.
func (c Claims) String(name string) (string, bool) {
	var s string
	if err := json.Unmarshal(c[name], &s); err != nil {
		return "", false
	}
	return s, true
}

// Rejected means the token failed a check; the caller answers 401. Check names it.
type Rejected struct{ Check string }

func (r *Rejected) Error() string { return "token rejected: " + r.Check + " check failed" }

// Unavailable means the key set could not be had; the caller answers 503.
type Unavailable struct{ Reason string }

func (u *Unavailable) Error() string { return "key set unavailable: " + u.Reason }

// Verifier checks tokens against the realm's cached key set.
type Verifier struct {
	issuer, audience string
	now              func() time.Time
	keys             *keySet
}

// New builds a verifier. The key set client trusts the system roots plus
// CAFile, follows no redirect and uses no proxy.
func New(cfg Config) (*Verifier, error) {
	u := cfg.KeySetURL
	switch {
	case u == nil:
		return nil, errors.New("token: the key set URL is required")
	case u.User != nil:
		return nil, errors.New("token: the key set URL must not carry credentials")
	case (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return nil, errors.New("token: the key set URL must be an http or https URL with a host")
	case cfg.Issuer == "":
		return nil, errors.New("token: the issuer is required")
	case cfg.Audience == "":
		return nil, errors.New("token: the audience is required")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("token: reading CA file %s: %w", cfg.CAFile, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("token: CA file %s holds no certificate", cfg.CAFile)
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	client := &http.Client{
		Timeout:       keySetTimeout,
		Transport:     &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Verifier{
		issuer: cfg.Issuer, audience: cfg.Audience, now: now,
		keys: &keySet{client: client, url: u.String(), now: now},
	}, nil
}

type algorithm struct {
	kty   string
	hash  crypto.Hash
	pss   bool
	curve string // EC only
}

// algorithms is the allow-list: asymmetric only, each bound to a key type.
var algorithms = map[string]algorithm{
	"RS256": {kty: "RSA", hash: crypto.SHA256}, "RS384": {kty: "RSA", hash: crypto.SHA384}, "RS512": {kty: "RSA", hash: crypto.SHA512},
	"PS256": {kty: "RSA", hash: crypto.SHA256, pss: true}, "PS384": {kty: "RSA", hash: crypto.SHA384, pss: true}, "PS512": {kty: "RSA", hash: crypto.SHA512, pss: true},
	"ES256": {kty: "EC", hash: crypto.SHA256, curve: "P-256"}, "ES384": {kty: "EC", hash: crypto.SHA384, curve: "P-384"}, "ES512": {kty: "EC", hash: crypto.SHA512, curve: "P-521"},
}

func reject(check string) error { return &Rejected{Check: check} }

// Verify checks raw and returns its claims. The signature is checked before
// the payload is read. Errors are *Rejected or *Unavailable and never hold
// any part of the token.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if raw == "" {
		return nil, reject("absent")
	}
	parts := strings.Split(raw, ".")
	if len(raw) > MaxTokenBytes || len(parts) != 3 {
		return nil, reject("malformed")
	}
	headBytes, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[2])
	var head struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if err1 != nil || err2 != nil || json.Unmarshal(headBytes, &head) != nil || head.Crit != nil {
		return nil, reject("malformed")
	}
	alg, ok := algorithms[head.Alg]
	if !ok {
		return nil, reject("algorithm")
	}
	if head.Kid == "" {
		return nil, reject("key")
	}
	key, found, err := v.keys.lookup(ctx, head.Kid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, reject("key")
	}
	if key.kty != alg.kty || (key.alg != "" && key.alg != head.Alg) || (alg.curve != "" && key.ec.Curve.Params().Name != alg.curve) {
		return nil, reject("algorithm")
	}
	if !verifySignature(alg, key, parts[0]+"."+parts[1], sig) {
		return nil, reject("signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims Claims
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims == nil {
		return nil, reject("malformed")
	}
	if err := v.checkClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func verifySignature(alg algorithm, key publicKey, input string, sig []byte) bool {
	h := alg.hash.New()
	h.Write([]byte(input))
	digest := h.Sum(nil)
	switch {
	case alg.pss:
		return rsa.VerifyPSS(key.rsa, alg.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case alg.kty == "RSA":
		return rsa.VerifyPKCS1v15(key.rsa, alg.hash, digest, sig) == nil
	}
	size := (key.ec.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return false
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])})
	return err == nil && ecdsa.VerifyASN1(key.ec, digest, der)
}

func (v *Verifier) checkClaims(c Claims) error {
	if iss, ok := c.String("iss"); !ok || iss != v.issuer {
		return reject("issuer")
	}
	if !v.hasAudience(c["aud"]) {
		return reject("audience")
	}
	now := float64(v.now().UnixNano()) / 1e9
	exp, ok := number(c["exp"])
	if !ok || now > exp+Leeway.Seconds() {
		return reject("expiry")
	}
	if raw, present := c["nbf"]; present {
		nbf, ok := number(raw)
		if !ok || nbf-Leeway.Seconds() > now {
			return reject("not before")
		}
	}
	return nil
}

func (v *Verifier) hasAudience(raw json.RawMessage) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == v.audience
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, a := range many {
		if a == v.audience {
			return true
		}
	}
	return false
}

func number(raw json.RawMessage) (float64, bool) {
	var f float64
	return f, json.Unmarshal(raw, &f) == nil
}
