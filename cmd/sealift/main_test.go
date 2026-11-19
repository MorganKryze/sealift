package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// TestToolsCredential proves toolsCredential builds a credential only when
// both SEALIFT_TOOLS_UID and SEALIFT_TOOLS_GID parse, so a bare host or a
// test that never sets them still runs pnpm and Trivy under the caller's
// own identity instead of failing to start.
func TestToolsCredential(t *testing.T) {
	t.Run("both set", func(t *testing.T) {
		t.Setenv("SEALIFT_TOOLS_UID", "10001")
		t.Setenv("SEALIFT_TOOLS_GID", "2000")
		cred := toolsCredential()
		if cred == nil {
			t.Fatal("toolsCredential() = nil, want a credential")
		}
		if cred.UID != 10001 || cred.GID != 2000 {
			t.Errorf("toolsCredential() = %+v, want UID 10001 GID 2000", cred)
		}
	})
	t.Run("uid missing", func(t *testing.T) {
		t.Setenv("SEALIFT_TOOLS_UID", "")
		t.Setenv("SEALIFT_TOOLS_GID", "2000")
		if cred := toolsCredential(); cred != nil {
			t.Errorf("toolsCredential() = %+v, want nil", cred)
		}
	})
	t.Run("gid missing", func(t *testing.T) {
		t.Setenv("SEALIFT_TOOLS_UID", "10001")
		t.Setenv("SEALIFT_TOOLS_GID", "")
		if cred := toolsCredential(); cred != nil {
			t.Errorf("toolsCredential() = %+v, want nil", cred)
		}
	})
	t.Run("unparseable", func(t *testing.T) {
		t.Setenv("SEALIFT_TOOLS_UID", "not-a-number")
		t.Setenv("SEALIFT_TOOLS_GID", "2000")
		if cred := toolsCredential(); cred != nil {
			t.Errorf("toolsCredential() = %+v, want nil", cred)
		}
	})
}

// TestRunServesHealthAndStopsOnSignal starts the real wiring on a free port,
// so a broken store, queue or route shows up here rather than in the image.
func TestRunServesHealthAndStopsOnSignal(t *testing.T) {
	localGitHub(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "data")
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health check never answered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if _, statErr := os.Stat(filepath.Join(root, "private", "settings.json")); statErr != nil {
		t.Errorf("settings file: %v", statErr)
	}

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
}

// blockingJob emits one "step" event, signals started, then blocks until
// ctx is canceled, standing in for a real analysis or export job whose
// event stream would otherwise stay open for as long as the job runs.
type blockingJob struct{ started chan struct{} }

func (j *blockingJob) Kind() string { return "test" }

func (j *blockingJob) Run(ctx context.Context, emit func(jobs.Event)) error {
	emit(jobs.Event{Kind: "step", Data: json.RawMessage(`{}`)})
	close(j.started)
	<-ctx.Done()
	return ctx.Err()
}

// TestRunCancelsRunningJobBeforeShuttingDownServer proves shutdown does not
// wait out its own timeout on a job's event stream: with a subscriber
// connected to a running job when the signal arrives, run must cancel that
// job before shutting the server down, so the connection goes idle quickly
// and run returns well under the 10 second shutdown timeout.
func TestRunCancelsRunningJobBeforeShuttingDownServer(t *testing.T) {
	localGitHub(t)
	started := make(chan struct{})
	onQueueReady = func(q *jobs.Queue) {
		if _, err := q.Submit(&blockingJob{started: started}); err != nil {
			t.Errorf("submit: %v", err)
		}
	}
	defer func() { onQueueReady = nil }()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "data")
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	// Keep-alives off: a pooled idle connection left open by this client
	// would sit outside any request and make the server's own shutdown
	// wait on it, which has nothing to do with what this test checks.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = client.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health check never answered: %v", err)
	}
	resp.Body.Close()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job never started")
	}

	// The subscriber's first Read only returns once the job's "step" event
	// is flushed, so this connection is genuinely established (not just
	// accepted) by the time the signal below arrives.
	streamResp, err := client.Get("http://" + addr + "/api/jobs/current/events")
	if err != nil {
		t.Fatalf("subscribe to event stream: %v", err)
	}
	defer streamResp.Body.Close()

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return well under the 10 second shutdown timeout")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("run took %v to return, want it well under the shutdown timeout", elapsed)
	}
}

func TestSubcommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantName string
		wantRest []string
	}{
		{"none", nil, "", nil},
		{"import", []string{"import", "-settings", "s", "a.tgz"}, "import", []string{"-settings", "s", "a.tgz"}},
		{"import-server", []string{"import-server", "-settings", "s"}, "import-server", []string{"-settings", "s"}},
		{"import without arguments", []string{"import"}, "import", []string{}},
		{"server flags keep their place", []string{"-addr", "x"}, "", []string{"-addr", "x"}},
		{"unknown word", []string{"serve"}, "", []string{"serve"}},
		{"prefix of a subcommand", []string{"import-servers"}, "", []string{"import-servers"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, rest := subcommand(tt.args)
			if name != tt.wantName || strings.Join(rest, "\x00") != strings.Join(tt.wantRest, "\x00") {
				t.Errorf("subcommand(%q) = %q, %q; want %q, %q", tt.args, name, rest, tt.wantName, tt.wantRest)
			}
		})
	}
}

// localGitHub points SEALIFT_GITHUB_API at a local server that answers 404 and
// reports the paths it is asked for. A test that starts run sets it first, so
// no test reaches api.github.com.
func localGitHub(t *testing.T) <-chan string {
	t.Helper()
	asked := make(chan string, 8)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case asked <- r.URL.Path:
		default:
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(gh.Close)
	t.Setenv("SEALIFT_GITHUB_API", gh.URL)
	return asked
}

// TestRunReadsGitHubAPIFromEnv proves SEALIFT_GITHUB_API reaches the tools
// manager: GET /api/tools looks up the latest Trivy release, and the server
// named by the variable must be the one asked.
func TestRunReadsGitHubAPIFromEnv(t *testing.T) {
	asked := localGitHub(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- run(addr, filepath.Join(t.TempDir(), "data"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err = client.Get("http://" + addr + "/api/tools"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /api/tools never answered: %v", err)
	}
	resp.Body.Close()

	select {
	case path := <-asked:
		if want := "/repos/aquasecurity/trivy/releases/latest"; path != want {
			t.Errorf("fake GitHub asked for %q, want %q", path, want)
		}
	default:
		t.Error("the fake GitHub was never asked: SEALIFT_GITHUB_API did not reach the tools manager")
	}

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
}

// TestNewToolsManagerGitHubAPI covers the lookup address the manager gets from
// SEALIFT_GITHUB_API: unset keeps the public API, a local or https address is
// used as given, and anything else stops the start without echoing the value.
func TestNewToolsManagerGitHubAPI(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{"unset keeps the public API", "", "", false},
		{"https mirror", "https://mirror.example.internal/github", "https://mirror.example.internal/github", false},
		{"http on 127.0.0.1", "http://127.0.0.1:8123", "http://127.0.0.1:8123", false},
		{"http on localhost", "http://localhost:8123", "http://localhost:8123", false},
		{"http on ::1", "http://[::1]:8123", "http://[::1]:8123", false},
		{"http on another host", "http://mirror.example.internal", "", true},
		{"http on a private address", "http://10.0.0.5:8123", "", true},
		{"no scheme", "mirror.example.internal", "", true},
		{"host and port without scheme", "127.0.0.1:8123", "", true},
		{"other scheme", "ftp://mirror.example.internal", "", true},
		{"no host", "https://", "", true},
		{"userinfo", "https://mirroruser:s3cretTOKEN@mirror.example.internal", "", true},
		{"userinfo on loopback", "http://mirroruser:s3cretTOKEN@127.0.0.1:8123", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SEALIFT_GITHUB_API", c.value)
			m, err := newToolsManager(nil, nil, nil)
			if c.wantErr {
				if err == nil {
					t.Fatalf("newToolsManager accepted %q", c.value)
				}
				if strings.Contains(err.Error(), "s3cretTOKEN") || strings.Contains(err.Error(), "mirroruser") {
					t.Errorf("error repeats the credentials: %v", err)
				}
				if !strings.Contains(err.Error(), "SEALIFT_GITHUB_API") {
					t.Errorf("error does not name the variable: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.GitHubAPI != c.want {
				t.Errorf("GitHubAPI = %q, want %q", m.GitHubAPI, c.want)
			}
		})
	}
}

// TestRunRefusesAnUnsafeGitHubAPI checks the start fails before it listens.
func TestRunRefusesAnUnsafeGitHubAPI(t *testing.T) {
	t.Setenv("SEALIFT_GITHUB_API", "http://mirror.example.internal")
	err := run("127.0.0.1:0", filepath.Join(t.TempDir(), "data"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("run accepted an http mirror on a non-loopback host")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestServerServesItsSigningKey(t *testing.T) {
	localGitHub(t)
	addr := freeAddr(t)
	root := filepath.Join(t.TempDir(), "data")
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	var resp *http.Response
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if resp, err = http.Get("http://" + addr + "/api/signing-key"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("the signing key was never served: %v", err)
	}
	defer resp.Body.Close()
	var key struct{ PublicKeyPem, PublicKeySha256 string }
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(key.PublicKeyPem, "-----BEGIN PUBLIC KEY-----") || len(key.PublicKeySha256) != 64 {
		t.Errorf("status %d, key %+v: want 200 and a public key with its sha256", resp.StatusCode, key)
	}
	info, err := os.Stat(filepath.Join(root, "private", "signing-key.pem"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, mode %v, want 0600", err, info)
	}

	// The listen address's own host may regenerate, a foreign Host may not.
	post := func(host string) int {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/api/signing-key/regenerate", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Host = host
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if got := post("evil.example:1"); got != http.StatusForbidden {
		t.Errorf("a foreign Host got status %d, want 403", got)
	}
	if got := post(addr); got != http.StatusOK {
		t.Errorf("the listen address got status %d, want 200", got)
	}

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
}

func TestServerStopsOnADamagedSigningKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	private := filepath.Join(root, "private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "signing-key.pem")
	damaged := []byte("not a key")
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	err := run(freeAddr(t), root, slog.New(slog.NewTextHandler(&logs, nil)))
	if err == nil {
		t.Fatal("run started on a damaged signing key")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "is not a PEM private key") {
		t.Errorf("error %q does not name the file and the problem", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(damaged) {
		t.Errorf("the damaged file was replaced by %q", got)
	}
}

// TestNewToolsManagerReadsGitHubToken proves SEALIFT_GITHUB_TOKEN reaches the
// tools manager's release lookups.
func TestNewToolsManagerReadsGitHubToken(t *testing.T) {
	var got atomic.Value
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		http.NotFound(w, r)
	}))
	t.Cleanup(gh.Close)
	t.Setenv("SEALIFT_GITHUB_API", gh.URL)
	t.Setenv("SEALIFT_GITHUB_TOKEN", "token-for-test")

	m, err := newToolsManager(nil, gh.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = m.UpdateTrivy(context.Background(), "", false)
	if v, _ := got.Load().(string); v != "Bearer token-for-test" {
		t.Errorf("Authorization = %q, want the bearer token", v)
	}
}
