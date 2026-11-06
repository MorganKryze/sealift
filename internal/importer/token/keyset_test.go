package token

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func verifyKid(e *env, kid string) error {
	_, err := e.ver.Verify(context.Background(), e.mint.mint(signerFor("RS256"), kid, nil, nil))
	return err
}

func wantKeyRejected(t *testing.T, err error) {
	t.Helper()
	var rej *Rejected
	if !errors.As(err, &rej) || rej.Check != "key" {
		t.Fatalf("err = %v, want a rejection on the key", err)
	}
}

func TestKeySetCache(t *testing.T) {
	t.Run("fetch on first use and every 5 minutes", func(t *testing.T) {
		e := newEnv(t)
		if n := e.srv.fetches.Load(); n != 0 {
			t.Fatalf("fetches before use = %d", n)
		}
		steps := []struct {
			advance time.Duration
			want    int32
		}{
			{0, 1},
			{4*time.Minute + 59*time.Second, 1},
			{time.Second, 2},
			{time.Minute, 2},
		}
		for _, s := range steps {
			e.clock.Advance(s.advance)
			if err := verifyKid(e, "rs"); err != nil {
				t.Fatal(err)
			}
			if n := e.srv.fetches.Load(); n != s.want {
				t.Fatalf("after +%v: fetches = %d, want %d", s.advance, n, s.want)
			}
		}
	})

	t.Run("an unknown kid refetches at most every 30 seconds", func(t *testing.T) {
		e := newEnv(t)
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Minute)
		wantKeyRejected(t, verifyKid(e, "late"))
		if n := e.srv.fetches.Load(); n != 2 {
			t.Fatalf("fetches after first unknown kid = %d, want 2", n)
		}
		e.clock.Advance(29 * time.Second)
		wantKeyRejected(t, verifyKid(e, "later"))
		if n := e.srv.fetches.Load(); n != 2 {
			t.Fatalf("fetches within 30 s = %d, want 2", n)
		}
		e.srv.publish(signerFor("RS256").jwk("rs"), signerFor("RS256").jwk("later"))
		e.clock.Advance(time.Second)
		if err := verifyKid(e, "later"); err != nil {
			t.Fatalf("a key published later: %v", err)
		}
		if n := e.srv.fetches.Load(); n != 3 {
			t.Fatalf("fetches after 30 s = %d, want 3", n)
		}
	})

	t.Run("a cancelled caller does not block the honest one", func(t *testing.T) {
		e := newEnv(t)
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.ver.Verify(cancelled, e.mint.mint(signerFor("RS256"), "ghost", nil, nil))
		wantKeyRejected(t, err)
		e.clock.Advance(10 * time.Second)
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatalf("honest token after a cancelled caller: %v", err)
		}
		if n := e.srv.fetches.Load(); n != 1 {
			t.Fatalf("fetches = %d, want 1", n)
		}
	})

	t.Run("a failed fetch keeps the old set for an hour", func(t *testing.T) {
		e := newEnv(t)
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatal(err)
		}
		e.srv.set(http.StatusInternalServerError, []byte("down"))
		e.clock.Advance(6 * time.Minute)
		for range 3 {
			if err := verifyKid(e, "rs"); err != nil {
				t.Fatalf("old set not kept: %v", err)
			}
		}
		if n := e.srv.fetches.Load(); n != 2 {
			t.Fatalf("a failing fetch was retried inside 30 s: fetches = %d", n)
		}
		e.clock.Advance(53*time.Minute + 59*time.Second)
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatalf("set dropped before the hour: %v", err)
		}
		e.clock.Advance(time.Second)
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable after the hour", err)
		}
	})
}

func TestKeySetUnavailable(t *testing.T) {
	t.Run("server error with no set held", func(t *testing.T) {
		e := newEnv(t)
		e.srv.set(http.StatusServiceUnavailable, []byte("down"))
		err := verifyKid(e, "rs")
		var un *Unavailable
		if !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
		if !strings.Contains(un.Error(), "key set") {
			t.Fatalf("message %q does not name the key set", un.Error())
		}
	})
	t.Run("server gone", func(t *testing.T) {
		e := newEnv(t)
		e.srv.Close()
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
	})
	t.Run("recovers once the server answers", func(t *testing.T) {
		e := newEnv(t)
		e.srv.set(http.StatusServiceUnavailable, nil)
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
		e.srv.publish(signerFor("RS256").jwk("rs"))
		e.clock.Advance(30 * time.Second)
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatalf("after recovery: %v", err)
		}
	})
}

func TestKeySetBounds(t *testing.T) {
	t.Run("body of 1 MiB plus one byte", func(t *testing.T) {
		e := newEnv(t)
		good := signerFor("RS256").jwk("rs")
		e.srv.publish(good)
		body := e.srv.snapshot()
		e.srv.set(http.StatusOK, padTo(MaxKeySetBytes+1, append([]byte(nil), body...)))
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
		e2 := newEnv(t)
		e2.srv.set(http.StatusOK, padTo(MaxKeySetBytes, append([]byte(nil), body...)))
		if err := verifyKid(e2, "rs"); err != nil {
			t.Fatalf("a body of exactly 1 MiB: %v", err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		e := newEnv(t)
		e.srv.set(http.StatusNotFound, e.srv.snapshot())
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		e := newEnv(t)
		e.ver = e.verifier(t, "/moved", "")
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
		if n := e.srv.strays.Load(); n != 0 {
			t.Fatalf("the redirect was followed %d times", n)
		}
	})
	t.Run("101 keys", func(t *testing.T) {
		e := newEnv(t)
		es := signerFor("ES256")
		keys := make([]map[string]any, 0, 101)
		for i := range 101 {
			keys = append(keys, es.jwk(fmt.Sprintf("k%d", i)))
		}
		e.srv.publish(keys...)
		if _, err := e.ver.Verify(context.Background(), e.mint.mint(es, "k99", nil, nil)); err != nil {
			t.Fatalf("100th key: %v", err)
		}
		_, err := e.ver.Verify(context.Background(), e.mint.mint(es, "k100", nil, nil))
		wantKeyRejected(t, err)
	})
	t.Run("unusable keys are skipped", func(t *testing.T) {
		small := signerFor("RS256")
		small.key = smallRSAKey()
		e := newEnv(t, small.jwk("small"))
		wantKeyRejected(t, func() error {
			_, err := e.ver.Verify(context.Background(), e.mint.mint(small, "small", nil, nil))
			return err
		}())
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatalf("a good key beside the skipped one: %v", err)
		}
	})
	t.Run("an RSA exponent past 2^31-1 is skipped", func(t *testing.T) {
		jwk := signerFor("RS256").jwk("bigexp")
		jwk["e"] = b64([]byte{1, 0, 0, 0, 1})
		e := newEnv(t, jwk)
		wantKeyRejected(t, verifyKid(e, "bigexp"))
	})
	t.Run("an EC point off the curve is skipped", func(t *testing.T) {
		jwk := signerFor("ES256").jwk("off")
		jwk["y"] = jwk["x"]
		e := newEnv(t, jwk)
		wantKeyRejected(t, func() error {
			_, err := e.ver.Verify(context.Background(), e.mint.mint(signerFor("ES256"), "off", nil, nil))
			return err
		}())
	})
}

func TestKeySetTLS(t *testing.T) {
	e := &env{srv: newKeySetServer(t, true), clock: newClock()}
	e.mint = minter{clock: e.clock}
	e.srv.publish(signerFor("RS256").jwk("rs"))

	t.Run("fails without the CA", func(t *testing.T) {
		e.ver = e.verifier(t, "/certs", "")
		var un *Unavailable
		if err := verifyKid(e, "rs"); !errors.As(err, &un) {
			t.Fatalf("err = %v, want *Unavailable", err)
		}
	})
	t.Run("passes with the certificate as CAFile", func(t *testing.T) {
		e.ver = e.verifier(t, "/certs", certFile(t, e.srv.Server))
		if err := verifyKid(e, "rs"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a missing CA file is an error naming it", func(t *testing.T) {
		missing := t.TempDir() + "/nope.pem"
		_, err := New(Config{KeySetURL: e.srv.url("/certs"), Issuer: testIssuer, Audience: testAudience, CAFile: missing})
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("err = %v, want it to name %s", err, missing)
		}
	})
	t.Run("a CA file with no certificate is an error", func(t *testing.T) {
		path := t.TempDir() + "/empty.pem"
		if err := writeFile(path, "not pem"); err != nil {
			t.Fatal(err)
		}
		_, err := New(Config{KeySetURL: e.srv.url("/certs"), Issuer: testIssuer, Audience: testAudience, CAFile: path})
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("err = %v, want it to name %s", err, path)
		}
	})
}
