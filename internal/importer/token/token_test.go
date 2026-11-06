package token

import (
	"context"
	"errors"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVerifyAccepts(t *testing.T) {
	for _, alg := range allAlgs {
		t.Run(alg, func(t *testing.T) {
			s := signerFor(alg)
			e := newEnv(t, s.jwk("k-"+alg))
			claims, err := e.ver.Verify(context.Background(), e.mint.mint(s, "k-"+alg, nil, nil))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got, ok := claims.String("preferred_username"); !ok || got != "alice" {
				t.Fatalf("preferred_username = %q, %v", got, ok)
			}
		})
	}

	now := epoch
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"aud as an array", map[string]any{"aud": []string{"other", testAudience}}},
		{"exp 59 s past", map[string]any{"exp": now.Add(-59 * time.Second).Unix()}},
		{"nbf 59 s ahead", map[string]any{"nbf": now.Add(59 * time.Second).Unix()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if _, err := e.ver.Verify(context.Background(), e.mint.mint(signerFor("RS256"), "rs", tt.claims, nil)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	rs, es := signerFor("RS256"), signerFor("ES256")
	now := epoch
	tests := []struct {
		name  string
		extra []map[string]any
		token func(m minter) string
		check string
	}{
		{"absent", nil, func(minter) string { return "" }, "absent"},
		{"two parts", nil, func(minter) string { return "a.b" }, "malformed"},
		{"five parts", nil, func(minter) string { return "a.b.c.d.e" }, "malformed"},
		{"bad base64", nil, func(minter) string { return "!!!.e30.AA" }, "malformed"},
		{"header not JSON", nil, func(minter) string { return b64([]byte("nope")) + ".e30.AA" }, "malformed"},
		{"alg none", nil, func(minter) string {
			return jsonB64(map[string]any{"alg": "none", "kid": "rs"}) + "." + jsonB64(map[string]any{"iss": testIssuer}) + "."
		}, "algorithm"},
		{"HS256 keyed with the RSA public key", nil, func(m minter) string {
			return m.hs256("rs", rsaKey().N.Bytes())
		}, "algorithm"},
		{"RS256 header on an EC key", nil, func(m minter) string { return m.mint(es, "es", nil, map[string]any{"alg": "RS256"}) }, "algorithm"},
		{"JWK alg RS384 for an RS256 token", []map[string]any{withField(rs.jwk("pinned"), "alg", "RS384")}, func(m minter) string {
			return m.mint(rs, "pinned", nil, nil)
		}, "algorithm"},
		{"use enc", []map[string]any{withField(rs.jwk("enc"), "use", "enc")}, func(m minter) string { return m.mint(rs, "enc", nil, nil) }, "key"},
		{"crit set", nil, func(m minter) string { return m.mint(rs, "rs", nil, map[string]any{"crit": []string{"exp"}}) }, "malformed"},
		{"no kid", nil, func(m minter) string { return m.mint(rs, "", nil, nil) }, "key"},
		{"unknown kid", nil, func(m minter) string { return m.mint(rs, "ghost", nil, nil) }, "key"},
		{"bad signature", nil, func(m minter) string {
			parts := strings.Split(m.mint(rs, "rs", nil, nil), ".")
			parts[2] = b64(make([]byte, 256))
			return strings.Join(parts, ".")
		}, "signature"},
		{"another realm's key", nil, func(m minter) string {
			other := rs
			other.key = otherRSAKey()
			return m.mint(other, "rs", nil, nil)
		}, "signature"},
		{"iss other", nil, func(m minter) string { return m.mint(rs, "rs", map[string]any{"iss": "https://evil.test"}, nil) }, "issuer"},
		{"aud absent", nil, func(m minter) string { return m.mint(rs, "rs", map[string]any{"aud": nil}, nil) }, "audience"},
		{"aud other", nil, func(m minter) string { return m.mint(rs, "rs", map[string]any{"aud": "elsewhere"}, nil) }, "audience"},
		{"aud array without ours", nil, func(m minter) string { return m.mint(rs, "rs", map[string]any{"aud": []string{"a", "b"}}, nil) }, "audience"},
		{"exp absent", nil, func(m minter) string { return m.mint(rs, "rs", map[string]any{"exp": nil}, nil) }, "expiry"},
		{"exp not a number", nil, func(m minter) string { return m.mint(rs, "rs", map[string]any{"exp": "soon"}, nil) }, "expiry"},
		{"exp 61 s past", nil, func(m minter) string {
			return m.mint(rs, "rs", map[string]any{"exp": now.Add(-61 * time.Second).Unix()}, nil)
		}, "expiry"},
		{"nbf 61 s ahead", nil, func(m minter) string {
			return m.mint(rs, "rs", map[string]any{"nbf": now.Add(61 * time.Second).Unix()}, nil)
		}, "not before"},
		{"a long string of dots", nil, func(minter) string { return strings.Repeat(".", MaxTokenBytes+1) }, "malformed"},
		{"over 16 KiB", nil, func(m minter) string {
			return m.mint(rs, "rs", map[string]any{"pad": strings.Repeat("x", MaxTokenBytes)}, nil)
		}, "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.extra...)
			claims, err := e.ver.Verify(context.Background(), tt.token(e.mint))
			if claims != nil {
				t.Fatalf("claims returned with %v", err)
			}
			var rej *Rejected
			if !errors.As(err, &rej) {
				t.Fatalf("err = %v (%T), want *Rejected", err, err)
			}
			if rej.Check != tt.check {
				t.Fatalf("Check = %q, want %q", rej.Check, tt.check)
			}
		})
	}
}

func withField(m map[string]any, k string, v any) map[string]any {
	m[k] = v
	return m
}

func TestClaimsString(t *testing.T) {
	c := Claims{"s": []byte(`"alice"`), "n": []byte(`12`), "a": []byte(`["x"]`)}
	tests := []struct {
		name string
		want string
		ok   bool
	}{{"s", "alice", true}, {"n", "", false}, {"a", "", false}, {"missing", "", false}}
	for _, tt := range tests {
		got, ok := c.String(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Errorf("String(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNewRefuses(t *testing.T) {
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no URL", Config{Issuer: "i", Audience: "a"}, "key set URL"},
		{"userinfo", Config{KeySetURL: mustURL("http://bob:hunter2@idp.test/certs"), Issuer: "i", Audience: "a"}, "credentials"},
		{"scheme", Config{KeySetURL: mustURL("ftp://idp.test/certs"), Issuer: "i", Audience: "a"}, "http"},
		{"no issuer", Config{KeySetURL: mustURL("http://idp.test/certs"), Audience: "a"}, "issuer"},
		{"no audience", Config{KeySetURL: mustURL("http://idp.test/certs"), Issuer: "i"}, "audience"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "bob") {
				t.Fatalf("error echoes the userinfo: %v", err)
			}
		})
	}
}

func TestErrorsCarryNoToken(t *testing.T) {
	rs := signerFor("RS256")
	secret := "secret-claim-value"
	tests := []struct {
		name  string
		setup func(e *env)
		token func(m minter) string
	}{
		{"bad signature", nil, func(m minter) string {
			parts := strings.Split(m.mint(rs, "rs", map[string]any{"marker": secret}, nil), ".")
			parts[2] = b64(make([]byte, 256))
			return strings.Join(parts, ".")
		}},
		{"issuer", nil, func(m minter) string {
			return m.mint(rs, "rs", map[string]any{"iss": secret, "marker": secret}, nil)
		}},
		{"unknown kid", nil, func(m minter) string { return m.mint(rs, secret, nil, nil) }},
		{"unavailable", func(e *env) { e.srv.set(500, []byte("down")) }, func(m minter) string {
			return m.mint(rs, "rs", map[string]any{"marker": secret}, nil)
		}},
		{"malformed", nil, func(minter) string { return secret + ".x.y" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if tt.setup != nil {
				e.ver = e.verifier(t, "/certs", "")
				tt.setup(e)
			}
			raw := tt.token(e.mint)
			_, err := e.ver.Verify(context.Background(), raw)
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			needles := append(strings.Split(raw, "."), raw, secret)
			for _, n := range needles {
				if len(n) >= 6 && strings.Contains(msg, n) {
					t.Fatalf("error %q holds %q", msg, n)
				}
			}
		})
	}
}

func TestVerifyBoundsWhatItAllocates(t *testing.T) {
	e := newEnv(t)
	dots := strings.Repeat(".", 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := e.ver.Verify(context.Background(), dots)
	runtime.ReadMemStats(&after)
	var rej *Rejected
	if !errors.As(err, &rej) || rej.Check != "malformed" {
		t.Fatalf("err = %v, want a rejection on malformed", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > MaxTokenBytes {
		t.Fatalf("a 1 MiB token of dots allocated %d bytes, want at most %d", got, MaxTokenBytes)
	}
}
