package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeTrivy writes a fake trivy executable that records its
// arguments, one per line, into argsFile, then runs body, and returns the
// executable's path.
func installFakeTrivy(t *testing.T, argsFile, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argsFile + "\"\n" + body
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	return path
}

func readArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read args file: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func TestTrivyCLI_ScanSBOM_Args(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := installFakeTrivy(t, argsFile, `echo "scan ok"
`)
	cacheDir := t.TempDir()

	cli := NewTrivyCLI(bin, cacheDir, nil)
	out, err := cli.ScanSBOM(context.Background(), "/work/project.cdx.json", "/work/project.trivy.json")
	if err != nil {
		t.Fatalf("ScanSBOM: %v", err)
	}
	if !strings.Contains(out, "scan ok") {
		t.Errorf("output = %q, want it to contain %q", out, "scan ok")
	}

	want := []string{
		"sbom", "/work/project.cdx.json",
		"--format", "json",
		"--skip-db-update",
		"--output", "/work/project.trivy.json",
		"--cache-dir", cacheDir,
	}
	assertArgs(t, readArgs(t, argsFile), want)
}

func TestTrivyCLI_ConvertToCycloneDX_Args(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := installFakeTrivy(t, argsFile, `echo "convert ok"
`)
	cacheDir := t.TempDir()

	cli := NewTrivyCLI(bin, cacheDir, nil)
	out, err := cli.ConvertToCycloneDX(context.Background(), "/work/report.trivy.json", "/work/report.cdx.json")
	if err != nil {
		t.Fatalf("ConvertToCycloneDX: %v", err)
	}
	if !strings.Contains(out, "convert ok") {
		t.Errorf("output = %q, want it to contain %q", out, "convert ok")
	}

	want := []string{
		"convert",
		"--format", "cyclonedx",
		"--output", "/work/report.cdx.json",
		"/work/report.trivy.json",
	}
	assertArgs(t, readArgs(t, argsFile), want)
}

func TestTrivyCLI_UpdateDB_Args(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := installFakeTrivy(t, argsFile, `echo "db updated"
`)
	cacheDir := t.TempDir()

	cli := NewTrivyCLI(bin, cacheDir, nil)
	out, err := cli.UpdateDB(context.Background())
	if err != nil {
		t.Fatalf("UpdateDB: %v", err)
	}
	if !strings.Contains(out, "db updated") {
		t.Errorf("output = %q, want it to contain %q", out, "db updated")
	}

	want := []string{
		"image",
		"--download-db-only",
		"--cache-dir", cacheDir,
	}
	assertArgs(t, readArgs(t, argsFile), want)
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args = %q, want %q", got, want)
		}
	}
}
