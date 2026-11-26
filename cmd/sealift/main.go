// Command sealift serves the sealift backend.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/MorganKryze/sealift/internal/api"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/pip"
	"github.com/MorganKryze/sealift/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "signing-key" {
		os.Exit(runSigningKey(os.Args[2:], os.Stdout, os.Stderr))
	}
	// The subcommand is chosen before flag.Parse, so `sealift -addr ...` is unchanged.
	switch name, rest := subcommand(os.Args[1:]); name {
	case "import":
		os.Exit(runImport(context.Background(), rest, os.Stdout, os.Stderr))
	case "import-server":
		os.Exit(runImportServer(context.Background(), rest, os.Stderr))
	}
	// The host-side restriction comes from the publish flag
	// (-p 127.0.0.1:8080:8080), not from the bind address: binding to
	// 127.0.0.1 here would make the server unreachable through a published
	// container port.
	addr := flag.String("addr", "0.0.0.0:8080", "address to listen on")
	root := flag.String("data", "/data", "data volume")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*addr, *root, log); err != nil {
		log.Error("sealift stopped", "error", err)
		os.Exit(1)
	}
}

func run(addr, root string, log *slog.Logger) error {
	idle, err := ephemeralConfig(os.Getenv("SEALIFT_EPHEMERAL"), os.Getenv("SEALIFT_EPHEMERAL_IDLE"))
	if err != nil {
		return err
	}
	st, err := store.Open(root)
	if err != nil {
		return err
	}
	st.SetEphemeral(idle > 0)
	pol, err := applyPolicy(st, os.Getenv("SEALIFT_POLICY"), log)
	if err != nil {
		return err
	}
	swept, err := st.MarkRunningInterrupted()
	if err != nil {
		return err
	}
	if swept > 0 {
		log.Warn("marked analyses interrupted after a restart", "count", swept)
	}
	removed, err := st.RemoveOrphanDirs()
	if err != nil {
		return err
	}
	if removed > 0 {
		log.Warn("removed unfinished job directories left by a crash", "count", removed)
	}
	// A Trivy release asset runs tens of megabytes; give the download
	// enough time without leaving the client unbounded.
	toolsHTTP := &http.Client{Timeout: 5 * time.Minute}
	toolsManager, err := newToolsManager(st, toolsHTTP, log)
	if err != nil {
		return err
	}
	installed, err := toolsManager.InstalledTrivy()
	if err != nil {
		return err
	}
	log.Info("tools", "trivy_installed", installed)

	// The trivy binary is reached through the "current" symlink, so
	// ActivateTrivy repoints it without this ever being reconstructed. Each
	// analysis runs the pnpm its project's target names.
	asUser := toolsCredential()
	log.Info("child processes", "runs_as_tools_account", asUser != nil, "default_pnpm", st.Settings().Target.PnpmVer)
	if status, err := os.ReadFile("/proc/self/status"); asUser != nil && err == nil && noNewPrivs(string(status)) {
		log.Error("child processes cannot switch to the tools account: the container runs with no-new-privileges, so every analysis and the Trivy database install fail; set security_opt: [no-new-privileges=false], which also overrides a daemon.json default")
	}
	trivyRunner := runner.NewTrivyCLI(filepath.Join(root, "tools", "trivy", "current", "trivy"), filepath.Join(root, "trivy-cache"), asUser)
	pnpmRunner := runner.NewPnpmCLI(filepath.Join(root, "cache", "pnpm"), toolsManager.NPMRegistry, asUser)
	if onPnpmReady != nil {
		onPnpmReady(pnpmRunner)
	}
	registry := newRegistryClient(toolsManager.NPMRegistry)

	queue := jobs.NewQueue(log)
	defer queue.Close()
	if onQueueReady != nil {
		onQueueReady(queue)
	}
	if onRegistryReady != nil {
		onRegistryReady(registry)
	}
	service := jobs.NewService(st, queue, toolsManager, pnpmRunner, trivyRunner, registry)
	service.Review = pol.Review
	// uv needs an interpreter to start, and builds and runs nothing with it.
	// Without one, pip analyses fail at resolve and say so.
	python, err := exec.LookPath("python3")
	if err != nil {
		log.Warn("no python3 on the PATH: pip analyses cannot resolve", "error", err)
		python = ""
	}
	uvRunner := runner.NewUvCLI(python, filepath.Join(root, "cache", "uv"), asUser)
	service.SetPip(uvRunner, &pip.Client{Index: toolsManager.PipIndex})
	if onServiceReady != nil {
		onServiceReady(service)
	}
	handlers := api.NewHandlers(st, service, toolsManager)
	handlers.Ephemeral = idle
	handlers.Policy = pol
	preparer := tools.NewPreparer(toolsManager, trivyRunner, func() (string, error) {
		key := st.SigningKey()
		return key.PublicKeySHA256, key.Err()
	},
		pol.Settings.Target.PnpmVer, pol.Pip.UvVer, log)
	handlers.Ready = preparer

	static, err := web.Static()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Routes(handlers, static),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: the event stream stays open for a whole job.
	}
	// Bound before the preparation starts, so a busy address stops the
	// start before anything under tools/ is written.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The preparation writes under root, so run returns only once it has
	// stopped.
	prepared := make(chan struct{})
	go func() { defer close(prepared); preparer.Run(ctx) }()
	defer func() { stop(); <-prepared }()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(listener) }()

	log.Info("listening", "addr", addr, "data", root, "ephemeral", idle > 0)
	if idle > 0 {
		go sweepEphemeral(ctx, st, service.DeleteProject, idle, log)
	}
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	// The event stream only ends when its job does, so canceling the
	// running job before asking the server to shut down is what lets
	// Shutdown see that connection go idle quickly, instead of blocking
	// until its own timeout expires.
	queue.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		log.Error("shutdown", "error", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// signingKeyUsage is the line printed for a usage error.
const signingKeyUsage = "usage: sealift signing-key regenerate [-data <dir>]"

// runSigningKey runs `sealift signing-key regenerate [-data dir]` and returns
// the exit status: 0 replaced, 1 refused or failed, 2 usage. It prints the
// new public key and the replaced key's sha256, never the private key.
func runSigningKey(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, signingKeyUsage)
		return 2
	}
	if len(args) == 0 || args[0] != "regenerate" {
		return usage()
	}
	fs := flag.NewFlagSet("signing-key regenerate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("data", "/data", "data volume")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return usage()
	}
	key, replaced, err := store.ReplaceSigningKey(*root, os.Getuid())
	if err != nil {
		fmt.Fprintf(stderr, "sealift signing-key regenerate: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "public key sha256 %s\nreplaced %s\n%s", key.PublicKeySHA256, replaced, key.PublicPEM)
	return 0
}

// applyPolicy reads the policy file at path, "" meaning none, over the
// settings an older release left on the volume, makes the result the
// settings in effect, and returns the policy. It logs each key the file changed from a stored value,
// and each key whose stored value was empty, so the default applies.
func applyPolicy(st *store.Store, path string, log *slog.Logger) (policy.Policy, error) {
	stored, hasStored := st.StoredSettings()
	p, err := policy.Load(path, stored, hasStored)
	if held := (*policy.StoredError)(nil); errors.As(err, &held) {
		return policy.Policy{}, fmt.Errorf("%s, left by an older release: %w", filepath.Join(st.Root(), "private", "settings.json"), err)
	}
	if err != nil {
		return policy.Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	if err := st.UseSettings(p.Settings); err != nil {
		return policy.Policy{}, fmt.Errorf("settings in effect: %w", err)
	}
	for _, key := range p.Overrides {
		log.Info("policy overrides a stored setting", "key", key)
	}
	for _, key := range p.Defaulted {
		log.Warn("default replaces an empty stored setting", "key", key)
	}
	return p, nil
}

// onQueueReady, when non-nil, is called with the queue right after it is
// created. Only a test in this package sets it, to submit a job before the
// server starts accepting connections.
var onQueueReady func(*jobs.Queue)

// onServiceReady, when non-nil, is called with the service once it is set
// up. Only a test in this package sets it, to read what the service hands
// each analysis.
var onServiceReady func(*jobs.Service)

// onPnpmReady, when non-nil, is called with the pnpm runner run hands the
// service. Only a test in this package sets it, to check its registry.
var onPnpmReady func(*runner.PnpmCLI)

// onRegistryReady, when non-nil, is called with the npm client run hands
// the service. Only a test in this package sets it, to check its timeout.
var onRegistryReady func(*npm.Client)

// newRegistryClient builds the analysis's npm client. The timeout covers
// the whole response, so it matches the tools client's: a large packument
// or tarball needs minutes on a slow link, and a stalled registry must not
// hold a job forever.
func newRegistryClient(registry string) *npm.Client {
	return &npm.Client{Registry: registry, HTTP: &http.Client{Timeout: 5 * time.Minute}}
}

// toolsCredential builds the credential pnpm and Trivy run under, from the
// uid and gid docker-entrypoint.sh exports as SEALIFT_TOOLS_UID and
// SEALIFT_TOOLS_GID. It returns nil, leaving children under the caller's
// own identity, when either variable is unset or does not parse as a
// uint32, which covers every test and a bare host outside the image.
// newToolsManager builds the tools manager with the GitHub API address from
// SEALIFT_GITHUB_API. Unset keeps the public API. The download address of
// the pinned Trivy comes from that API, while the pinned sha256 decides what
// installs. The address must be https, or http on a loopback host for the
// browser gate. The
// error never repeats the value, which could carry credentials.
// SEALIFT_GITHUB_TOKEN, when set, authenticates those lookups.
// SEALIFT_PIP_INDEX names the package index uv comes from, under
// tools.ParseIndexURL's rules. SEALIFT_NPM_REGISTRY names the registry pnpm
// comes from and resolves through, and the analyses' registry client reads
// it from the manager, under tools.ParseRegistryURL's rules; SEALIFT_ALLOW_HTTP_REGISTRY=true
// lets it be plain http off loopback. Empty keeps npm.DefaultRegistry. The
// end-to-end test (test/e2e) sets it to a local Verdaccio that mirrors the
// public registry through an uplink, so it can publish a package sealift's
// own analysis and export need to resolve that the public registry never
// carries.
func newToolsManager(vol tools.Volume, client *http.Client, log *slog.Logger) (*tools.Manager, error) {
	m := tools.NewManager(vol, client, log)
	m.GitHubToken = os.Getenv("SEALIFT_GITHUB_TOKEN")
	registry, insecure, err := tools.ParseRegistryURL(os.Getenv("SEALIFT_NPM_REGISTRY"), os.Getenv("SEALIFT_ALLOW_HTTP_REGISTRY") == "true")
	if err != nil {
		return nil, fmt.Errorf("SEALIFT_NPM_REGISTRY: %w", err)
	}
	if insecure && log != nil {
		log.Warn("SEALIFT_ALLOW_HTTP_REGISTRY is true: pnpm and the packages come over plain http, so the network can change them")
	}
	m.NPMRegistry = registry
	index, err := tools.ParseIndexURL(os.Getenv("SEALIFT_PIP_INDEX"))
	if err != nil {
		return nil, fmt.Errorf("SEALIFT_PIP_INDEX: %w", err)
	}
	m.PipIndex = index
	raw := os.Getenv("SEALIFT_GITHUB_API")
	if raw == "" {
		return m, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errBadGitHubAPI
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return nil, errBadGitHubAPI
	}
	m.GitHubAPI = raw
	return m, nil
}

var errBadGitHubAPI = errors.New("SEALIFT_GITHUB_API must be an https URL without credentials, or an http URL on localhost, 127.0.0.1 or ::1")

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ephemeralConfig reads SEALIFT_EPHEMERAL and SEALIFT_EPHEMERAL_IDLE. It
// returns the idle delay after which a project is erased, zero when the
// mode is off, and refuses any value it does not understand rather than
// guess: an erase the operator did not mean, or one that never happens,
// both cost more than a refused start.
func ephemeralConfig(on, idle string) (time.Duration, error) {
	switch on {
	case "", "0":
		return 0, nil
	case "1":
	default:
		return 0, fmt.Errorf("SEALIFT_EPHEMERAL must be 1 or 0, not %q", on)
	}
	if idle == "" {
		return time.Hour, nil
	}
	minutes, err := strconv.Atoi(idle)
	if err != nil || minutes <= 0 {
		return 0, fmt.Errorf("SEALIFT_EPHEMERAL_IDLE must be a positive number of minutes, not %q", idle)
	}
	return time.Duration(minutes) * time.Minute, nil
}

// sweepEphemeral erases idle projects through deleteProject, then the
// caches once none remains, every minute until ctx ends. Its log lines
// carry counts, never an id.
func sweepEphemeral(ctx context.Context, st *store.Store, deleteProject func(string) error, idle time.Duration, log *slog.Logger) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			// Counts only: an error's text can hold a path that names a package.
			r := st.SweepEphemeral(idle, now, deleteProject)
			if r.Failed > 0 {
				log.Error("ephemeral sweep could not erase everything", "failed", r.Failed, "deleted_projects", r.Deleted, "caches_emptied", r.Purged)
			} else if r.Deleted > 0 || r.Purged {
				log.Info("ephemeral sweep", "deleted_projects", r.Deleted, "caches_emptied", r.Purged)
			}
		}
	}
}

// noNewPrivs reports whether a /proc/<pid>/status text has the
// no_new_privs flag set, which blocks the setuid switch to the tools user.
func noNewPrivs(status string) bool {
	for line := range strings.Lines(status) {
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok {
			return strings.TrimSpace(v) == "1"
		}
	}
	return false
}

func toolsCredential() *runner.Credential {
	uidEnv := os.Getenv("SEALIFT_TOOLS_UID")
	gidEnv := os.Getenv("SEALIFT_TOOLS_GID")
	if uidEnv == "" || gidEnv == "" {
		return nil
	}
	uid, err := strconv.ParseUint(uidEnv, 10, 32)
	if err != nil {
		return nil
	}
	gid, err := strconv.ParseUint(gidEnv, 10, 32)
	if err != nil {
		return nil
	}
	return &runner.Credential{UID: uint32(uid), GID: uint32(gid)}
}
