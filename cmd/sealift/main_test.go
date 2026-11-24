package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/api"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
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

// TestRunServesTheInterfaceWhilePreparing starts the real wiring on a free
// port, with a GitHub that accepts the connection and never answers, so a
// broken store, queue or route shows up here rather than in the image, and
// a hung preparation neither blocks the interface nor the stop.
func TestRunServesTheInterfaceWhilePreparing(t *testing.T) {
	localUpstreams(t)
	hung := make(chan struct{})
	gh := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hung:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(gh.Close)
	t.Cleanup(func() { close(hung) })
	t.Setenv("SEALIFT_GITHUB_API", gh.URL)

	addr := freeAddr(t)
	root := filepath.Join(t.TempDir(), "data")
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	var resp *http.Response
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if resp, err = http.Get("http://" + addr + "/"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("the interface never answered: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / = %d, want 200", resp.StatusCode)
	}

	resp, err = http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var health struct {
		Status  string
		Missing []string
	}
	err = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || health.Status != "preparing" || !slices.Contains(health.Missing, "trivy") {
		t.Errorf("/healthz = %d %+v, want 503 preparing with trivy missing", resp.StatusCode, health)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "private", "settings.json")); !os.IsNotExist(statErr) {
		t.Errorf("a fresh volume holds a settings file (stat: %v), want none", statErr)
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
	localUpstreams(t)
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

// localUpstreams points SEALIFT_GITHUB_API at a local server that answers 404
// and reports the paths it is asked for, and SEALIFT_NPM_REGISTRY and
// SEALIFT_PIP_INDEX at another that answers 404. A test that starts run sets
// it first, so the preparation at start reaches nothing outside the machine.
func localUpstreams(t *testing.T) <-chan string {
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
	registries := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(registries.Close)
	t.Setenv("SEALIFT_NPM_REGISTRY", registries.URL)
	t.Setenv("SEALIFT_PIP_INDEX", registries.URL+"/simple/")
	return asked
}

// startAndStop serves a fresh volume on a free port until fn returns, then
// signals the process and waits for run to return. The server logs JSON to
// logs.
func startAndStop(t *testing.T, logs io.Writer, fn func(addr string)) {
	t.Helper()
	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() {
		done <- run(addr, filepath.Join(t.TempDir(), "data"), slog.New(slog.NewJSONHandler(logs, nil)))
	}()
	fn(addr)
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

// TestRunReadsGitHubAPIFromEnv proves SEALIFT_GITHUB_API reaches the tools
// manager: the preparation at start looks up the pinned Trivy release on the
// server the variable names.
func TestRunReadsGitHubAPIFromEnv(t *testing.T) {
	asked := localUpstreams(t)
	startAndStop(t, io.Discard, func(string) {
		select {
		case path := <-asked:
			if want := "/repos/aquasecurity/trivy/releases/tags/v" + tools.PinnedTrivy.Version; path != want {
				t.Errorf("fake GitHub asked for %q, want %q", path, want)
			}
		case <-time.After(5 * time.Second):
			t.Error("the fake GitHub was never asked: SEALIFT_GITHUB_API did not reach the tools manager")
		}
	})
}

// TestRunPassesTheNpmRegistryToTheTools proves SEALIFT_NPM_REGISTRY reaches
// the tools manager as well as the analysis's registry client: the pnpm the
// preparation installs comes from the registry the variable names.
func TestRunPassesTheNpmRegistryToTheTools(t *testing.T) {
	localUpstreams(t)
	asked := make(chan string, 8)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case asked <- r.URL.Path:
		default:
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(registry.Close)
	t.Setenv("SEALIFT_NPM_REGISTRY", registry.URL)
	startAndStop(t, io.Discard, func(string) {
		select {
		case path := <-asked:
			if path != "/pnpm" {
				t.Errorf("the registry was asked for %q, want /pnpm", path)
			}
		case <-time.After(5 * time.Second):
			t.Error("the registry was never asked: SEALIFT_NPM_REGISTRY did not reach the tools manager")
		}
	})
}

// TestRunPreparesThePolicysPnpmAndUv proves the probe answers from the
// preparer, built with the policy's pnpm and uv: both fail against local
// stand-ins, their causes name the version asked, and /healthz lists them.
func TestRunPreparesThePolicysPnpmAndUv(t *testing.T) {
	localUpstreams(t)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pnpm" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"pnpm","versions":{}}`)
	}))
	t.Cleanup(registry.Close)
	t.Setenv("SEALIFT_NPM_REGISTRY", registry.URL)
	logs := &lockedBuffer{}
	startAndStop(t, logs, func(addr string) {
		causes := map[string]string{}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && len(causes) < 3; time.Sleep(20 * time.Millisecond) {
			for line := range strings.Lines(logs.String()) {
				var entry struct{ Msg, Item, Cause string }
				if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "preparation failed, retrying" {
					causes[entry.Item] = entry.Cause
				}
			}
		}
		for item, version := range map[string]string{"pnpm": store.DefaultSettings.Target.PnpmVer, "uv": store.DefaultPipTarget.UvVer} {
			if want := item + " " + version + ":"; !strings.HasPrefix(causes[item], want) {
				t.Errorf("%s's cause = %q, want it to start with %q", item, causes[item], want)
			}
		}
		if _, ok := causes["trivy"]; !ok {
			t.Errorf("no failed trivy in the log:\n%s", logs)
		}

		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"status":"preparing","missing":["trivy","trivy-db","pnpm","uv"]}`
		if resp.StatusCode != http.StatusServiceUnavailable || strings.TrimSpace(string(body)) != want {
			t.Errorf("/healthz = %d %s, want 503 %s", resp.StatusCode, body, want)
		}
	})
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

// TestNewToolsManagerPipIndex covers the package index the manager gets from
// SEALIFT_PIP_INDEX: unset keeps the public index, a loopback or https address
// is used as given, and anything else stops the start without echoing the
// value.
func TestNewToolsManagerPipIndex(t *testing.T) {
	cases := []struct {
		name, value, want string
		wantErr           bool
	}{
		{"unset keeps the public index", "", tools.DefaultPipIndex, false},
		{"https mirror", "https://mirror.example.internal/simple/", "https://mirror.example.internal/simple/", false},
		{"http on loopback", "http://127.0.0.1:9/simple/", "http://127.0.0.1:9/simple/", false},
		{"http on another host", "http://mirror.example.internal/simple/", "", true},
		{"userinfo", "https://mirroruser:s3cretTOKEN@mirror.example.internal/simple/", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SEALIFT_PIP_INDEX", c.value)
			m, err := newToolsManager(nil, nil, nil)
			if c.wantErr {
				if err == nil {
					t.Fatalf("newToolsManager accepted %q", c.value)
				}
				if strings.Contains(err.Error(), "s3cretTOKEN") || strings.Contains(err.Error(), "mirroruser") {
					t.Errorf("error repeats the credentials: %v", err)
				}
				if !strings.Contains(err.Error(), "SEALIFT_PIP_INDEX") {
					t.Errorf("error does not name the variable: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.PipIndex != c.want {
				t.Errorf("PipIndex = %q, want %q", m.PipIndex, c.want)
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
	localUpstreams(t)
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
// tools manager's lookup of the pinned Trivy release.
func TestNewToolsManagerReadsGitHubToken(t *testing.T) {
	var got atomic.Value
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		http.NotFound(w, r)
	}))
	t.Cleanup(gh.Close)
	t.Setenv("SEALIFT_GITHUB_API", gh.URL)
	t.Setenv("SEALIFT_GITHUB_TOKEN", "token-for-test")

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := newToolsManager(st, gh.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	m.Arch = "amd64"
	_, _ = m.EnsureTrivy(context.Background())
	if v, _ := got.Load().(string); v != "Bearer token-for-test" {
		t.Errorf("Authorization = %q, want the bearer token", v)
	}
}

// startRun serves root on a free port and returns the address and a stop
// that signals the process and waits for run to return.
func startRun(t *testing.T, root string, log *slog.Logger) (string, func()) {
	t.Helper()
	localUpstreams(t)
	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() { done <- run(addr, root, log) }()
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var resp *http.Response
		if resp, err = http.Get("http://" + addr + "/healthz"); err == nil {
			resp.Body.Close()
			break
		}
	}
	if err != nil {
		t.Fatalf("the server never answered: %v", err)
	}
	return addr, func() {
		t.Helper()
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
}

// writeFile writes data at path, creating its directory.
func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// refusedStart runs the server on root, expects it to stop before it
// listens, and returns the error run gave.
func refusedStart(t *testing.T, root string) error {
	t.Helper()
	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() { done <- run(addr, root, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGTERM)
		if err := <-done; err != nil {
			t.Logf("run returned %v after the signal", err)
		}
		t.Fatal("run started and served until stopped")
	}
	if err == nil {
		t.Fatal("run started")
	}
	if conn, dialErr := net.Dial("tcp", addr); dialErr == nil {
		conn.Close()
		t.Errorf("something listens on %s after a refused start", addr)
	}
	return err
}

func TestRunRefusesABadPolicy(t *testing.T) {
	localUpstreams(t)
	dir := t.TempDir()
	for name, c := range map[string]struct{ body, want string }{
		"out of range": {"minReleaseAgeDays: 120\n", "minReleaseAgeDays must be between 1 and 90"},
		"unknown key":  {"brand:\n  colour: red\n", "brand.colour is an unknown key"},
		"missing file": {"", "the file does not exist"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
			if c.body != "" {
				writeFile(t, path, c.body)
			}
			t.Setenv("SEALIFT_POLICY", path)
			err := refusedStart(t, filepath.Join(t.TempDir(), "data"))
			if want := "policy " + path + ": " + c.want; !strings.Contains(err.Error(), want) {
				t.Errorf("run = %q, want it to hold %q", err, want)
			}
		})
	}
}

// settings070 is private/settings.json as 0.7.0 writes it, with the node
// version and the release age given.
func settings070(node string, age int) string {
	return fmt.Sprintf(`{
  "target": {
    "os": "linux",
    "cpu": "x64",
    "libc": "glibc",
    "node": %q,
    "pnpmVer": "10.34.5"
  },
  "minReleaseAgeDays": %d,
  "resolveParallelism": 4,
  "downloadParallelism": 16
}`, node, age)
}

// loggedKeys returns the key of each JSON log entry whose message is msg.
func loggedKeys(logs, msg string) []string {
	var keys []string
	for line := range strings.Lines(logs) {
		var entry struct{ Msg, Key string }
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == msg {
			keys = append(keys, entry.Key)
		}
	}
	return keys
}

func TestRunRefusesAStoredSettingOutsideTheRules(t *testing.T) {
	localUpstreams(t)
	t.Setenv("SEALIFT_POLICY", "")
	for name, c := range map[string]struct {
		node string
		age  int
		want string
	}{
		"a node range":                   {"22", 21, `target is refused: node must be exact, such as 22.17.1, not "22"; set targets.npm in the policy file to replace it`},
		"a release age past the maximum": {"22.17.1", 120, "minReleaseAgeDays must be between 1 and 90, not 120; set minReleaseAgeDays in the policy file to replace it"},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "data")
			path := filepath.Join(root, "private", "settings.json")
			writeFile(t, path, settings070(c.node, c.age))
			err := refusedStart(t, root)
			if want := path + ", left by an older release: " + c.want; !strings.Contains(err.Error(), want) {
				t.Errorf("run = %q, want it to hold %q", err, want)
			}
		})
	}
}

func TestRunLogsAStoredZero(t *testing.T) {
	t.Setenv("SEALIFT_POLICY", "")
	root := filepath.Join(t.TempDir(), "data")
	writeFile(t, filepath.Join(root, "private", "settings.json"), settings070("22.17.1", 0))
	var logs bytes.Buffer
	addr, stop := startRun(t, root, slog.New(slog.NewJSONHandler(&logs, nil)))

	resp, err := http.Get("http://" + addr + "/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	var got api.Settings
	err = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	stop()
	if err != nil {
		t.Fatal(err)
	}
	if got.MinReleaseAgeDays != store.DefaultSettings.MinReleaseAgeDays {
		t.Errorf("GET /api/settings gave a release age of %d, want the default %d", got.MinReleaseAgeDays, store.DefaultSettings.MinReleaseAgeDays)
	}
	if keys := loggedKeys(logs.String(), "default replaces an empty stored setting"); len(keys) != 1 || keys[0] != "minReleaseAgeDays" {
		t.Errorf("the start log names %v as defaulted, want only minReleaseAgeDays", keys)
	}
}

func TestRunAppliesThePolicy(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	// pnpm differs from the default, so a runner built before the policy
	// applies runs another version than the one the policy names.
	writeFile(t, policy, `targets:
  npm: {os: linux, cpu: arm64, libc: musl, node: 22.18.0, pnpm: 10.30.1}
  pip: {python: 3.12.4, os: linux, cpu: x86_64, glibc: 2.31, uv: 0.13.7}
minReleaseAgeDays: 30
parallelism: {resolve: 2, download: 3}
brand: {name: Harbor}
`)
	t.Setenv("SEALIFT_POLICY", policy)
	root := filepath.Join(t.TempDir(), "data")
	var logs bytes.Buffer
	addr, stop := startRun(t, root, slog.New(slog.NewJSONHandler(&logs, nil)))

	get := func(path string, into any) error {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(into)
	}
	var got api.Settings
	var instance api.Instance
	settingsErr := get("/api/settings", &got)
	instanceErr := get("/api/instance", &instance)
	stop()
	if settingsErr != nil {
		t.Fatal(settingsErr)
	}
	if instanceErr != nil {
		t.Fatal(instanceErr)
	}
	if got.Target.Cpu != "arm64" || got.Target.Libc != "musl" || got.Target.Node != "22.18.0" || got.Target.PnpmVer != "10.30.1" ||
		got.MinReleaseAgeDays != 30 || got.ResolveParallelism != 2 || got.DownloadParallelism != 3 {
		t.Errorf("GET /api/settings = %+v, want the policy's values", got)
	}
	// The instance answer and a new pip project's default read the policy
	// the handlers hold, a value apart from the stored settings above.
	if instance.Brand.Name != "Harbor" {
		t.Errorf("GET /api/instance brand.name = %q, want the policy's Harbor", instance.Brand.Name)
	}
	wantPip := api.PipTarget{Python: "3.12.4", Os: "linux", Cpu: "x86_64", Glibc: "2.31", UvVer: "0.13.7"}
	if instance.Policy.PipTarget != wantPip {
		t.Errorf("GET /api/instance policy.pipTarget = %+v, want the policy's %+v", instance.Policy.PipTarget, wantPip)
	}
	if instance.Policy.Target.PnpmVer != "10.30.1" || instance.Policy.MinReleaseAgeDays != 30 {
		t.Errorf("GET /api/instance policy = %+v, want the policy's values", instance.Policy)
	}
	if _, err := os.Lstat(filepath.Join(root, "private", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("the policy was written to the volume (stat: %v)", err)
	}
	var pnpm []string
	for line := range strings.Lines(logs.String()) {
		var entry struct{ Msg, Pnpm string }
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "child processes" {
			pnpm = append(pnpm, entry.Pnpm)
		}
	}
	if len(pnpm) != 1 || pnpm[0] != "10.30.1" {
		t.Errorf("the start log names pnpm %q for child processes, want the policy's 10.30.1", pnpm)
	}
}

func TestRunLogsAnOverriddenKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	stored := settings070("22.17.1", 21)
	writeFile(t, filepath.Join(root, "private", "settings.json"), stored)
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	writeFile(t, policy, "minReleaseAgeDays: 30\nparallelism: {resolve: 4}\n")
	t.Setenv("SEALIFT_POLICY", policy)

	var logs bytes.Buffer
	_, stop := startRun(t, root, slog.New(slog.NewJSONHandler(&logs, nil)))
	stop()

	overridden := loggedKeys(logs.String(), "policy overrides a stored setting")
	if len(overridden) != 1 || overridden[0] != "minReleaseAgeDays" {
		t.Errorf("the start log names %v as overridden, want only minReleaseAgeDays", overridden)
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "private", "settings.json")); string(raw) != stored {
		t.Errorf("settings.json changed to %s", raw)
	}
}

// TestNewToolsManagerNpmRegistry covers SEALIFT_NPM_REGISTRY: an http
// registry off loopback stops the start unless SEALIFT_ALLOW_HTTP_REGISTRY
// is true, which logs a warning naming the variable and never the URL.
func TestNewToolsManagerNpmRegistry(t *testing.T) {
	cases := []struct {
		name, value, allow string
		wantErr, wantWarn  bool
	}{
		{"unset keeps the public registry", "", "", false, false},
		{"https with credentials", "https://ci:s3cretTOKEN@npm.example.internal/", "", false, false},
		{"http on loopback", "http://127.0.0.1:4873", "", false, false},
		{"http on another host", "http://ci:s3cretTOKEN@registry:4873", "", true, false},
		{"http on another host, allowed", "http://ci:s3cretTOKEN@registry:4873", "true", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SEALIFT_NPM_REGISTRY", c.value)
			t.Setenv("SEALIFT_ALLOW_HTTP_REGISTRY", c.allow)
			var logs bytes.Buffer
			m, err := newToolsManager(nil, nil, slog.New(slog.NewTextHandler(&logs, nil)))
			if c.wantErr {
				if err == nil {
					t.Fatalf("newToolsManager accepted %q", c.value)
				}
				if strings.Contains(err.Error(), "s3cretTOKEN") || strings.Contains(err.Error(), "registry:4873") {
					t.Errorf("error repeats the value: %v", err)
				}
				if !strings.Contains(err.Error(), "SEALIFT_NPM_REGISTRY") {
					t.Errorf("error does not name the variable: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.NPMRegistry != c.value {
				t.Errorf("NPMRegistry = %q, want %q", m.NPMRegistry, c.value)
			}
			warned := strings.Contains(logs.String(), "SEALIFT_ALLOW_HTTP_REGISTRY")
			if warned != c.wantWarn {
				t.Errorf("warning logged = %v, want %v: %s", warned, c.wantWarn, logs.String())
			}
			if strings.Contains(logs.String(), "s3cretTOKEN") || strings.Contains(logs.String(), "registry:4873") {
				t.Errorf("log repeats the URL: %s", logs.String())
			}
		})
	}
}

// TestRunStopsOnABusyAddressBeforePreparing proves the listener binds before
// the preparation starts: on an address another process holds, run returns
// the bind error, prepares no item, asks nothing of GitHub and leaves tools/ empty.
func TestRunStopsOnABusyAddressBeforePreparing(t *testing.T) {
	asked := localUpstreams(t)
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	root := filepath.Join(t.TempDir(), "data")

	var logs lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(held.Addr().String(), root, slog.New(slog.NewJSONHandler(&logs, nil))) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run on a busy address returned nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run on a busy address did not return")
	}
	select {
	case path := <-asked:
		t.Errorf("the preparation asked GitHub for %s before the bind failed", path)
	default:
	}
	if strings.Contains(logs.String(), `"msg":"prepared"`) {
		t.Errorf("the preparation ran before the bind failed: %s", logs.String())
	}
	// store.Open creates tools/ empty; the preparation is what fills it.
	if entries, err := os.ReadDir(filepath.Join(root, "tools")); err != nil || len(entries) != 0 {
		t.Errorf("tools/ holds %v after a failed bind (%v), want it empty", entries, err)
	}
}
