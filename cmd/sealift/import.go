package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/nexus"
)

// importUsage is the one line printed for a usage error.
const importUsage = "usage: sealift import -settings <file> [-manifest <file>] [-sha256 <hex>] [-report <file>] <archive>"

var hexSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// runImport runs `sealift import` and returns the process exit code: 0 for a
// complete import, 1 incomplete, 2 for a usage or settings error and 3 for a
// refused archive.
func runImport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "sealift import: "+format+"\n", a...)
		return 2
	}
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	settingsPath := fs.String("settings", "", "settings file")
	manifestPath := fs.String("manifest", "", "manifest.json, next to the archive by default")
	expected := fs.String("sha256", "", "sha256 of the archive received through a separate channel")
	reportPath := fs.String("report", "", "write the JSON report to this file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, importUsage)
			return 2
		}
		return usage("%v", err)
	}
	if *settingsPath == "" {
		return usage("-settings is required")
	}
	if fs.NArg() != 1 {
		return usage("give exactly one archive")
	}
	if *expected != "" && !hexSHA256.MatchString(*expected) {
		return usage("-sha256 must be 64 hex digits")
	}
	archivePath := fs.Arg(0)
	if *manifestPath == "" {
		*manifestPath = filepath.Join(filepath.Dir(archivePath), "manifest.json")
	}
	for _, f := range []struct{ what, path string }{{"archive", archivePath}, {"manifest", *manifestPath}} {
		h, err := os.Open(f.path)
		if err != nil {
			return usage("cannot open the %s: %v", f.what, err)
		}
		h.Close()
	}
	settings, err := importer.LoadSettings(*settingsPath)
	if err != nil {
		return usage("%v", err)
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rep := importer.Run(ctx, importer.Options{
		Settings: settings, Archive: archivePath, Manifest: *manifestPath,
		ExpectedSHA256: *expected, ImportVersion: jobs.ToolVersion,
	}, func(s importer.Settings) (importer.Publisher, error) {
		c, err := nexus.New(nexus.Config{URL: s.NexusURL, Repository: s.Repository, User: s.User, Password: s.Password, CAFile: s.CAFile})
		if err != nil {
			return nil, err
		}
		return c, nil
	})

	code := rep.ExitCode()
	if *reportPath != "" {
		if err := writeReport(*reportPath, rep); err != nil {
			fmt.Fprintf(stderr, "sealift import: could not write the report: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	if err := rep.WriteText(stdout); err != nil && code == 0 {
		code = 1
	}
	return code
}

func writeReport(path string, rep importer.Report) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
