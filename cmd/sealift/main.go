// Command sealift serves the sealift backend.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MorganKryze/sealift/internal/api"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
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
	// A Trivy release asset runs tens of megabytes; give the download
	// enough time without leaving the client unbounded.
	toolsHTTP := &http.Client{Timeout: 5 * time.Minute}
	installed, err := tools.NewManager(st, toolsHTTP, log).InstalledTrivy()
	if err != nil {
		return err
	}
	log.Info("tools", "trivy_installed", installed)

	queue := jobs.NewQueue(log)
	defer queue.Close()

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Routes(queue),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: the event stream stays open for a whole job.
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Error("shutdown", "error", err)
		}
	}()
	log.Info("listening", "addr", addr, "data", root)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
