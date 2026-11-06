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
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/service"
	"github.com/MorganKryze/sealift/internal/importer/token"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

const (
	// importHeaderTimeout is how long a client has to send its request headers.
	importHeaderTimeout = 10 * time.Second
	// importMaxHeaderBytes caps the request headers: 64 KiB.
	importMaxHeaderBytes = 64 << 10
	// importShutdownTimeout is how long a stop waits for requests in flight.
	importShutdownTimeout = 10 * time.Second
)

// onImportListen, when non-nil, is called with the address the import server
// listens on, once it accepts connections. Only a test sets it.
var onImportListen func(net.Addr)

// subcommand splits the process arguments (without the program name) into a
// subcommand name and the arguments after it. The name is empty when the
// first argument names none, and rest is then args unchanged.
func subcommand(args []string) (name string, rest []string) {
	if len(args) > 0 && (args[0] == "import" || args[0] == "import-server") {
		return args[0], args[1:]
	}
	return "", args
}

// newImportHTTPServer bounds what a client can make the server hold open.
func newImportHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: importHeaderTimeout,
		MaxHeaderBytes:    importMaxHeaderBytes,
	}
}

// runImportServer runs `sealift import-server` until ctx ends or a signal
// arrives. It returns 2 for a usage or settings error and 1 for a failure to
// start or serve.
func runImportServer(ctx context.Context, args []string, stderr io.Writer) int {
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "sealift import-server: "+format+"\n", a...)
		return 2
	}
	fs := flag.NewFlagSet("import-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	settingsPath := fs.String("settings", "", "settings file")
	addr := fs.String("addr", "0.0.0.0:8080", "address to listen on")
	data := fs.String("data", "/data", "data volume")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usage("usage: sealift import-server -settings <file> [-addr <host:port>] [-data <dir>]")
		}
		return usage("%v", err)
	}
	if *settingsPath == "" {
		return usage("-settings is required")
	}
	if fs.NArg() != 0 {
		return usage("takes no argument")
	}
	settings, err := importer.LoadSettings(*settingsPath)
	if err != nil {
		return usage("%v", err)
	}
	if err := settings.CheckService(); err != nil {
		return usage("%v", err)
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	fail := func(what string, err error) int {
		log.Error(what, "error", err)
		return 1
	}

	store, err := imports.Open(filepath.Join(*data, "imports"), log)
	if err != nil {
		return fail("could not open the import store", err)
	}
	swept, err := store.Sweep()
	if err != nil {
		return fail("could not sweep the import store", err)
	}
	if swept > 0 {
		log.Warn("marked imports interrupted after a restart", "count", swept)
	}

	ts := settings.Token
	verifier, err := token.New(token.Config{KeySetURL: ts.KeySetURL, Issuer: ts.Issuer, Audience: ts.Audience, CAFile: ts.CAFile})
	if err != nil {
		return usage("token: %v", err)
	}
	var unencrypted []string
	if ts.KeySetURL.Scheme == "http" {
		unencrypted = append(unencrypted, ts.KeySetURL.String())
	}
	handlers := service.New(service.Config{Verifier: verifier, Unencrypted: unencrypted, Log: log})

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fail("could not listen", err)
	}
	srv := newImportHTTPServer(*addr, service.Routes(handlers))
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "data", *data)
	if onImportListen != nil {
		onImportListen(ln.Addr())
	}

	select {
	case err := <-serveErr:
		return fail("the server stopped", err)
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), importShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		return fail("shutdown", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail("the server stopped", err)
	}
	return 0
}
