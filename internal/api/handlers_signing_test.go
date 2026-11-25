package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
)

// privateKeyForms lists every form the private key's bytes could take in an answer.
func privateKeyForms(t *testing.T, h *Handlers) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.Store.Root(), "private", "signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block in the key file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	seed := parsed.(ed25519.PrivateKey).Seed()
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	return []string{
		"PRIVATE KEY",
		string(seed),
		hex.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(seed),
		base64.URLEncoding.EncodeToString(seed),
		body[24:56],
	}
}

func regenerate(t *testing.T, srv *httptest.Server) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/signing-key/regenerate", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func getSigningKey(t *testing.T, srv *httptest.Server) (int, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/api/signing-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, readBody(t, resp)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGetSigningKey(t *testing.T) {
	srv, h := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/signing-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got SigningKey
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := h.Store.SigningKey()
	if got.PublicKeyPem != want.PublicPEM || got.PublicKeySha256 != want.PublicKeySHA256 {
		t.Errorf("answer = %+v, want the store's key %s", got, want.PublicKeySHA256)
	}
	block, _ := pem.Decode([]byte(got.PublicKeyPem))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("publicKeyPem = %q, want a PUBLIC KEY block", got.PublicKeyPem)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKeySha256 != archive.PublicKeySHA256(pub.(ed25519.PublicKey)) {
		t.Error("publicKeySha256 is not the sha256 of the key's DER")
	}
}

func TestRegenerateRouteAnswersGoneNamingTheCommand(t *testing.T) {
	srv, h := newTestServer(t)
	keyFile := filepath.Join(h.Store.Root(), "private", "signing-key.pem")
	onDisk, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	status, before := getSigningKey(t, srv)
	if status != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", status, before)
	}

	resp := regenerate(t, srv)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want a problem", ct)
	}
	var p Problem
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.Detail == nil || !strings.Contains(*p.Detail, "sealift signing-key regenerate") {
		t.Errorf("body %q does not name the command", body)
	}
	if status, after := getSigningKey(t, srv); status != http.StatusOK || after != before {
		t.Errorf("GET after the POST = %d %q, want 200 %q", status, after, before)
	}
	if now, err := os.ReadFile(keyFile); err != nil || !bytes.Equal(now, onDisk) {
		t.Error("the POST changed the key file")
	}
}

func TestGetSigningKeyNamesTheFileWhenTheKeyDoesNotRead(t *testing.T) {
	srv, h := newTestServer(t)
	forms := privateKeyForms(t, h)
	keyFile := filepath.Join(h.Store.Root(), "private", "signing-key.pem")
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/api/signing-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want a problem", ct)
	}
	var p Problem
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.Detail == nil || !strings.Contains(*p.Detail, keyFile) {
		t.Errorf("body %q does not name %s", body, keyFile)
	}
	for _, bad := range forms {
		if strings.Contains(body, bad) {
			t.Error("the 500 Problem holds a form of the private key")
		}
	}
}

func TestAnswersNeverHoldThePrivateKey(t *testing.T) {
	srv, h := newTestServer(t)
	// Each answer is checked against the key in use when it was fetched.
	check := func(name, body string) {
		t.Helper()
		if body == "" {
			t.Errorf("%s answered nothing", name)
		}
		for _, bad := range privateKeyForms(t, h) {
			if strings.Contains(body, bad) {
				t.Errorf("%s holds a form of the private key", name)
			}
		}
	}
	get := func(name, path string) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		check(name, readBody(t, resp))
	}
	get("GET signing key", "/api/signing-key")
	get("GET settings", "/api/settings")
	check("410 Problem", readBody(t, regenerate(t, srv)))
	get("GET signing key after the 410", "/api/signing-key")
}
