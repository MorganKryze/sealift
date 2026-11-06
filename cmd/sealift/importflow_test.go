package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store/imports"
)

const (
	flowArchiveKey  = "packages/npm/a/packages_npm.tar.gz"
	flowManifestKey = "packages/npm/a/manifest.json"
	flowSecret      = "test-minio-secret"
)

// flowMinIO serves alice's two objects. When hold is set, the archive read
// sends one byte, signals gotArchive and blocks until its request ends.
type flowMinIO struct {
	srv                   *httptest.Server
	archive, manifest     []byte
	hold                  bool
	gotArchive            chan struct{}
	archiveETag, manifETg string
}

func newFlowMinIO(t *testing.T, f importFixture, hold bool) *flowMinIO {
	t.Helper()
	m := &flowMinIO{hold: hold, gotArchive: make(chan struct{}, 1), archiveETag: `"archive-etag"`, manifETg: `"manifest-etag"`}
	var err error
	if m.archive, err = os.ReadFile(f.archive); err != nil {
		t.Fatal(err)
	}
	if m.manifest, err = os.ReadFile(f.manifest); err != nil {
		t.Fatal(err)
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *flowMinIO) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("list-type") == "2" {
		_, _ = fmt.Fprintf(w, `<ListBucketResult><IsTruncated>false</IsTruncated>`+
			`<Contents><Key>%s</Key><LastModified>2026-11-06T10:00:00.000Z</LastModified><ETag>%s</ETag><Size>%d</Size></Contents>`+
			`<Contents><Key>%s</Key><LastModified>2026-11-06T10:00:00.000Z</LastModified><ETag>%s</ETag><Size>%d</Size></Contents></ListBucketResult>`,
			flowArchiveKey, "&#34;archive-etag&#34;", len(m.archive), flowManifestKey, "&#34;manifest-etag&#34;", len(m.manifest))
		return
	}
	var body []byte
	var etag string
	switch r.URL.Path {
	case "/user-alice/" + flowArchiveKey:
		body, etag = m.archive, m.archiveETag
	case "/user-alice/" + flowManifestKey:
		body, etag = m.manifest, m.manifETg
	default:
		http.NotFound(w, r)
		return
	}
	if im := r.Header.Get("If-Match"); im != "" && im != etag {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	if m.hold && etag == m.archiveETag {
		_, _ = w.Write(body[:1])
		w.(http.Flusher).Flush()
		m.gotArchive <- struct{}{}
		<-r.Context().Done()
		return
	}
	_, _ = w.Write(body)
}

// realm serves one RSA key set and mints tokens for it.
type realm struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newRealm(t *testing.T) *realm {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	set, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }))
	t.Cleanup(srv.Close)
	return &realm{srv: srv, key: key}
}

func (r *realm) token(t *testing.T, user string) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]any{"alg": "RS256", "kid": "k1"}) + "." + enc(map[string]any{
		"iss": "https://idp.example.internal/realms/lab", "aud": "sealift",
		"exp": time.Now().Add(10 * time.Minute).Unix(), "preferred_username": user,
	})
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// flowServer starts the import server over the fixture, the fake MinIO and the realm.
func flowServer(t *testing.T, f importFixture, m *flowMinIO, rl *realm) (*runningServer, string) {
	t.Helper()
	body, err := os.ReadFile(f.settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.settings, append(body, tokenSection(rl.srv.URL)...), 0o600); err != nil {
		t.Fatal(err)
	}
	withMinIO(t, f.settings, m.srv.URL)
	data := t.TempDir()
	return startServer(t, "-settings", f.settings, "-data", data, "-addr", "127.0.0.1:0"), data
}

func startFlowImport(t *testing.T, s *runningServer, token string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+s.addr+"/api/imports", strings.NewReader(`{"archive":"`+flowArchiveKey+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Access-Token", token)
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var imp struct{ ID string }
	if resp.StatusCode != http.StatusAccepted || json.Unmarshal(raw, &imp) != nil || imp.ID == "" {
		t.Fatalf("POST /api/imports = %d %s, want 202 with an id", resp.StatusCode, raw)
	}
	return imp.ID
}

func flowStore(t *testing.T, data string) *imports.Store {
	t.Helper()
	st, err := imports.Open(filepath.Join(data, "imports"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestImportServerRunsAnImport(t *testing.T) {
	f := newImportFixture(t)
	m := newFlowMinIO(t, f, false)
	rl := newRealm(t)
	s, data := flowServer(t, f, m, rl)
	token := rl.token(t, "alice")
	id := startFlowImport(t, s, token)

	st := flowStore(t, data)
	deadline := time.Now().Add(30 * time.Second)
	for {
		imp, err := st.Get("alice", id)
		if err != nil {
			t.Fatal(err)
		}
		if a := imp.Attempts[len(imp.Attempts)-1]; a.Status == imports.StatusEnded {
			if a.Outcome != "complete" || a.Report.Counts.Published != 1 {
				t.Fatalf("outcome %q, report %+v; want complete with 1 published", a.Outcome, a.Report)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the import never ended; stderr %s", s.stderr.String())
		}
		runtime.Gosched()
	}
	if code := s.stop(t); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, s.stderr.String())
	}

	seen := s.stderr.String()
	err := filepath.WalkDir(data, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		seen += string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{flowSecret, importPassword, importKey, token, "test-access-id"} {
		if strings.Contains(seen, secret) {
			t.Errorf("the log or a file under -data holds %q", secret)
		}
	}
	if !strings.Contains(seen, "import attempt ended") {
		t.Error("the end of the attempt was not logged: the scan proves little")
	}
}

func TestImportServerStopInterruptsTheRunningImport(t *testing.T) {
	f := newImportFixture(t)
	m := newFlowMinIO(t, f, true)
	rl := newRealm(t)
	s, data := flowServer(t, f, m, rl)
	id := startFlowImport(t, s, rl.token(t, "alice"))

	select {
	case <-m.gotArchive:
	case <-time.After(30 * time.Second):
		t.Fatalf("the archive was never read; stderr %s", s.stderr.String())
	}
	if code := s.stop(t); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, s.stderr.String())
	}
	imp, err := flowStore(t, data).Get("alice", id)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Outcome() != imports.OutcomeInterrupted {
		t.Errorf("outcome %q, want interrupted", imp.Outcome())
	}
}
