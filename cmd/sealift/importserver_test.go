package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/service"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

const serverKeySet = "https://idp.example.internal/realms/lab/protocol/openid-connect/certs"

// lockedBuffer is a stderr the server goroutine writes while the test reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// serverSettings writes a settings file for the server and returns its path.
// tokenSection is appended as it is, so a test can leave it out.
func serverSettings(t *testing.T, tokenSection string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"nexus-password": importPassword + "\n", "signature-key": importKey + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := "nexus:\n  url: https://nexus.example.internal\n  repository: npm-hosted\n  user: sealift-import\n  passwordFile: nexus-password\nsignatureKeyFile: signature-key\n" + tokenSection
	path := filepath.Join(dir, "settings.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func tokenSection(keySet string) string {
	return "token:\n  keySetUrl: " + keySet + "\n  issuer: https://idp.example.internal/realms/lab\n  audience: sealift\n"
}

// runningServer is a server started on a free port.
type runningServer struct {
	addr   string
	stderr *lockedBuffer
	done   chan int
	cancel context.CancelFunc
}

func (s *runningServer) stop(t *testing.T) int {
	t.Helper()
	s.cancel()
	select {
	case code := <-s.done:
		return code
	case <-time.After(15 * time.Second):
		t.Fatal("the server did not stop")
		return -1
	}
}

// startServer runs runImportServer and returns once it listens.
func startServer(t *testing.T, args ...string) *runningServer {
	t.Helper()
	listening := make(chan string, 1)
	onImportListen = func(a net.Addr) { listening <- a.String() }
	t.Cleanup(func() { onImportListen = nil })
	ctx, cancel := context.WithCancel(context.Background())
	s := &runningServer{stderr: &lockedBuffer{}, done: make(chan int, 1), cancel: cancel}
	go func() { s.done <- runImportServer(ctx, args, s.stderr) }()
	select {
	case s.addr = <-listening:
	case code := <-s.done:
		cancel()
		t.Fatalf("the server stopped with %d before it listened: %s", code, s.stderr.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("the server never listened")
	}
	t.Cleanup(func() { cancel() })
	return s
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestImportAcceptsServiceSections(t *testing.T) {
	f := newImportFixture(t)
	extra := "token:\n  keySetUrl: " + serverKeySet + "\n  issuer: https://idp.example.internal/realms/lab\n  audience: sealift\n"
	body, err := os.ReadFile(f.settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.settings, append(body, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCmd(t, "-settings", f.settings, f.archive)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestImportServerExitCodes(t *testing.T) {
	data := t.TempDir()
	tests := []struct {
		name string
		args func(t *testing.T) []string
		want int
		in   string
	}{
		{"no settings flag", func(*testing.T) []string { return []string{"-data", data} }, 2, "-settings"},
		{"unknown flag", func(*testing.T) []string { return []string{"-bogus"} }, 2, "bogus"},
		{"settings file missing", func(*testing.T) []string {
			return []string{"-settings", filepath.Join(data, "absent.yaml"), "-data", data}
		}, 2, "settings file"},
		{"settings error", func(t *testing.T) []string {
			return []string{"-settings", serverSettings(t, "token:\n  keySetUrl: ftp://idp.example.internal/certs\n  issuer: i\n  audience: a\n"), "-data", data}
		}, 2, "token.keySetUrl"},
		{"no token section", func(t *testing.T) []string { return []string{"-settings", serverSettings(t, ""), "-data", data} }, 2, "token"},
		{"address that cannot be bound", func(t *testing.T) []string {
			return []string{"-settings", serverSettings(t, tokenSection(serverKeySet)), "-data", data, "-addr", "not an address"}
		}, 1, "not an address"},
		{"data that cannot be made", func(t *testing.T) []string {
			file := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"-settings", serverSettings(t, tokenSection(serverKeySet)), "-data", file}
		}, 1, "imports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := runImportServer(context.Background(), tt.args(t), &stderr)
			if code != tt.want || !strings.Contains(stderr.String(), tt.in) {
				t.Errorf("exit %d, stderr %q; want %d naming %q", code, stderr.String(), tt.want, tt.in)
			}
			for _, secret := range []string{importPassword, importKey} {
				if strings.Contains(stderr.String(), secret) {
					t.Errorf("stderr holds %q", secret)
				}
			}
		})
	}
}

func TestImportServerSweepsAtStart(t *testing.T) {
	data := t.TempDir()
	root := filepath.Join(data, "imports")
	st, err := imports.Open(root, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	obj := imports.Object{Key: "packages_npm.tar.gz", ETag: "etag", Size: 1}
	imp, err := st.Create("alice", obj, imports.Object{Key: "manifest.json", ETag: "etag", Size: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get("alice", imp.ID); got.Outcome() != "running" {
		t.Fatalf("setup: outcome %q, want running", got.Outcome())
	}

	s := startServer(t, "-settings", serverSettings(t, tokenSection(serverKeySet)), "-data", data, "-addr", "127.0.0.1:0")
	if code, _ := get(t, "http://"+s.addr+"/healthz"); code != http.StatusOK {
		t.Fatalf("healthz = %d", code)
	}
	got, err := st.Get("alice", imp.ID)
	if err != nil || got.Outcome() != imports.OutcomeInterrupted {
		t.Errorf("outcome %q, %v; want interrupted", got.Outcome(), err)
	}
	if code := s.stop(t); code != 0 {
		t.Errorf("exit %d after the signal, stderr %s", code, s.stderr.String())
	}
}

func TestImportServerChecksTokens(t *testing.T) {
	s := startServer(t, "-settings", serverSettings(t, tokenSection(serverKeySet)), "-data", t.TempDir(), "-addr", "127.0.0.1:0")
	code, body := get(t, "http://"+s.addr+"/api/me")
	if code != http.StatusUnauthorized || !strings.Contains(body, "absent") {
		t.Errorf("GET /api/me without a token = %d %q, want 401 naming the check", code, body)
	}
	if code, _ := get(t, "http://"+s.addr+"/settings"); code != http.StatusNotFound {
		t.Errorf("GET /settings = %d, want 404", code)
	}
	s.stop(t)
}

func TestImportServerServesScreens(t *testing.T) {
	s := startServer(t, "-settings", serverSettings(t, tokenSection(serverKeySet)), "-data", t.TempDir(), "-addr", "127.0.0.1:0")
	for _, path := range []string{"/", "/imports", "/imports/20261106T101500Z-3f9a0c1d"} {
		resp, err := http.Get("http://" + s.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != service.ScreensPolicy || !strings.Contains(got, "frame-ancestors 'none'") {
			t.Errorf("GET %s: Content-Security-Policy = %q, want the screens' policy", path, got)
		}
	}
	s.stop(t)
}

func TestImportServerTakesNoAuthSwitch(t *testing.T) {
	fs, _ := importFlags()
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	sort.Strings(names)
	if want := []string{"addr", "data", "settings"}; !slices.Equal(names, want) {
		t.Errorf("the flags are %v, want exactly %v", names, want)
	}
	// A new field in the settings is a new way to configure the check: this list changes only with a review.
	var fields []string
	for _, typ := range []reflect.Type{reflect.TypeFor[importer.Settings](), reflect.TypeFor[importer.TokenSettings]()} {
		for i := range typ.NumField() {
			fields = append(fields, typ.Name()+"."+typ.Field(i).Name)
		}
	}
	want := []string{
		"Settings.NexusURL", "Settings.Repository", "Settings.User", "Settings.Password", "Settings.CAFile", "Settings.SignatureKey", "Settings.Token", "Settings.MinIO",
		"TokenSettings.KeySetURL", "TokenSettings.Issuer", "TokenSettings.Audience", "TokenSettings.CAFile",
	}
	if !slices.Equal(fields, want) {
		t.Errorf("the settings fields are %v, want %v", fields, want)
	}
}

func TestImportServerWarnsUnencrypted(t *testing.T) {
	tests := []struct {
		name   string
		keySet string
		want   int
	}{
		{"http", "http://idp.example.internal:8080/certs", 1},
		{"https", serverKeySet, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := startServer(t, "-settings", serverSettings(t, tokenSection(tt.keySet)), "-data", t.TempDir(), "-addr", "127.0.0.1:0")
			s.stop(t)
			n := 0
			for _, line := range strings.Split(s.stderr.String(), "\n") {
				if strings.Contains(line, "unencrypted") {
					n++
					if !strings.Contains(line, tt.keySet) {
						t.Errorf("warning %q does not name the key set URL", line)
					}
				}
			}
			if n != tt.want {
				t.Errorf("%d unencrypted warnings, want %d; stderr %s", n, tt.want, s.stderr.String())
			}
			for _, secret := range []string{importPassword, importKey} {
				if strings.Contains(s.stderr.String(), secret) {
					t.Errorf("stderr holds %q", secret)
				}
			}
		})
	}
}

func TestImportHTTPServerBounds(t *testing.T) {
	srv := newImportHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("MaxHeaderBytes = %d, want 65536", srv.MaxHeaderBytes)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want 60s", srv.IdleTimeout)
	}
}

// withMinIO appends a minio section and its key files to the settings file at path.
func withMinIO(t *testing.T, path, minioURL string) {
	t.Helper()
	dir := filepath.Dir(path)
	for name, content := range map[string]string{"minio-access-key": "test-access-id\n", "minio-secret-key": "test-minio-secret\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	section := "minio:\n  url: " + minioURL + "\n  accessKeyFile: minio-access-key\n  secretKeyFile: minio-secret-key\n"
	if err := os.WriteFile(path, append(body, section...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestImportServerStartsWithoutMinIO(t *testing.T) {
	s := startServer(t, "-settings", serverSettings(t, tokenSection(serverKeySet)), "-data", t.TempDir(), "-addr", "127.0.0.1:0")
	if code, body := get(t, "http://"+s.addr+"/api/archives"); code != http.StatusUnauthorized || !strings.Contains(body, "absent") {
		t.Errorf("GET /api/archives without a token = %d %q, want 401 naming the check", code, body)
	}
	if code := s.stop(t); code != 0 {
		t.Errorf("exit %d, stderr %s", code, s.stderr.String())
	}
	if strings.Contains(s.stderr.String(), "unencrypted") {
		t.Errorf("a warning without any http link: %s", s.stderr.String())
	}
}

func TestImportServerWiresMinIO(t *testing.T) {
	tests := []struct {
		name, url string
		warns     int
	}{
		{"http", "http://minio.example.internal:9000", 1},
		{"https", "https://minio.example.internal:9000", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := serverSettings(t, tokenSection(serverKeySet))
			withMinIO(t, path, tt.url)
			s := startServer(t, "-settings", path, "-data", t.TempDir(), "-addr", "127.0.0.1:0")
			s.stop(t)
			n := strings.Count(s.stderr.String(), "unencrypted")
			if n != tt.warns {
				t.Errorf("%d unencrypted warnings, want %d; stderr %s", n, tt.warns, s.stderr.String())
			}
			if tt.warns == 1 && !strings.Contains(s.stderr.String(), tt.url) {
				t.Errorf("the warning does not name %s: %s", tt.url, s.stderr.String())
			}
			for _, secret := range []string{"test-minio-secret", "test-access-id"} {
				if strings.Contains(s.stderr.String(), secret) {
					t.Errorf("stderr holds %q", secret)
				}
			}
		})
	}
}

func TestImportServerRefusesBadMinIO(t *testing.T) {
	path := serverSettings(t, tokenSection(serverKeySet))
	withMinIO(t, path, "ftp://minio.example.internal")
	var stderr bytes.Buffer
	code := runImportServer(context.Background(), []string{"-settings", path, "-data", t.TempDir(), "-addr", "127.0.0.1:0"}, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "minio.url") || strings.Contains(stderr.String(), "minio.example.internal") {
		t.Errorf("exit %d, stderr %q; want 2 naming minio.url without the URL", code, stderr.String())
	}
}
