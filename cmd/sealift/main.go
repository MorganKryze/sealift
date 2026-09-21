// Command sealift serves the sealift backend.
package main

import (
	"context"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/MorganKryze/sealift/internal/api"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/web"
)

func main() {
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
	st, err := store.Open(root)
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
	toolsManager := tools.NewManager(st, toolsHTTP, log)
	installed, err := toolsManager.InstalledTrivy()
	if err != nil {
		return err
	}
	log.Info("tools", "trivy_installed", installed)

	// The trivy binary is reached through the "current" symlink, so
	// ActivateTrivy repoints it without this ever being reconstructed.
	// pnpm has no such symlink: this pins the default target's version at
	// startup, so a settings change to a different pnpm version needs a
	// restart to take effect, a known limit of the fixed constructor
	// jobs.NewService takes.
	target := st.Settings().Target
	asUser := toolsCredential()
	log.Info("child processes", "runs_as_tools_account", asUser != nil)
	trivyRunner := runner.NewTrivyCLI(filepath.Join(root, "tools", "trivy", "current", "trivy"), filepath.Join(root, "trivy-cache"), asUser)
	pnpmRunner := runner.NewPnpmCLI(filepath.Join(root, "tools", "pnpm", target.PnpmVer, "package", "bin", "pnpm.cjs"), filepath.Join(root, "cache", "pnpm"), asUser)
	// Empty keeps npm.DefaultRegistry, the only path production takes. The
	// end-to-end test (test/e2e) sets this to a local Verdaccio that mirrors
	// the public registry through an uplink, so it can publish a package
	// sealift's own analysis and export need to resolve that the public
	// registry never carries.
	registry := &npm.Client{Registry: os.Getenv("SEALIFT_NPM_REGISTRY")}

	queue := jobs.NewQueue(log)
	defer queue.Close()
	if onQueueReady != nil {
		onQueueReady(queue)
	}
	service := jobs.NewService(st, queue, toolsManager, pnpmRunner, trivyRunner, registry)
	handlers := api.NewHandlers(st, service, toolsManager, trivyRunner)

	static, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Routes(handlers, static),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: the event stream stays open for a whole job.
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	log.Info("listening", "addr", addr, "data", root)
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
	<-serveErr
	return nil
}

// onQueueReady, when non-nil, is called with the queue right after it is
// created. Only a test in this package sets it, to submit a job before the
// server starts accepting connections.
var onQueueReady func(*jobs.Queue)

// toolsCredential builds the credential pnpm and Trivy run under, from the
// uid and gid docker-entrypoint.sh exports as SEALIFT_TOOLS_UID and
// SEALIFT_TOOLS_GID. It returns nil, leaving children under the caller's
// own identity, when either variable is unset or does not parse as a
// uint32, which covers every test and a bare host outside the image.
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
