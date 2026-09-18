//go:build integration

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// toolsCredential reads SEALIFT_TOOLS_UID and SEALIFT_TOOLS_GID, skipping
// the calling test with the same message every cross-user test in this
// file uses when they are unset.
func toolsCredential(t *testing.T) *Credential {
	t.Helper()
	uidEnv := os.Getenv("SEALIFT_TOOLS_UID")
	gidEnv := os.Getenv("SEALIFT_TOOLS_GID")
	if uidEnv == "" || gidEnv == "" {
		t.Skip("SEALIFT_TOOLS_UID and SEALIFT_TOOLS_GID unset: run inside the sealift image as app, e.g. " +
			"docker exec -u app <container> env SEALIFT_TOOLS_UID=10001 SEALIFT_TOOLS_GID=2000 runner.test -test.run <name>")
	}
	uid, err := strconv.ParseUint(uidEnv, 10, 32)
	if err != nil {
		t.Fatalf("parse SEALIFT_TOOLS_UID: %v", err)
	}
	gid, err := strconv.ParseUint(gidEnv, 10, 32)
	if err != nil {
		t.Fatalf("parse SEALIFT_TOOLS_GID: %v", err)
	}
	return &Credential{UID: uint32(uid), GID: uint32(gid)}
}

// minimalTrivyReport is just enough of a Trivy JSON report (SchemaVersion
// 2) for "trivy convert --format cyclonedx" to accept as input.
const minimalTrivyReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "sealift-capcheck",
  "ArtifactType": "cyclonedx",
  "Results": [
    {
      "Target": "Node.js",
      "Class": "lang-pkgs",
      "Type": "node-pkg",
      "Packages": [
        {
          "ID": "left-pad@1.3.0",
          "Name": "left-pad",
          "Identifier": {
            "PURL": "pkg:npm/left-pad@1.3.0",
            "BOMRef": "pkg:npm/left-pad@1.3.0"
          },
          "Version": "1.3.0"
        }
      ]
    }
  ]
}`

// TestConvertToCycloneDXAsTools proves that ConvertToCycloneDX, with the
// explicit --cache-dir the fix to internal/runner/trivy.go added, still
// succeeds when the child runs as tools instead of the caller's own user,
// the one path nothing exercised before this test. This only means anything
// run as app inside the sealift image, the same requirement as
// TestCancelKillsCrossUserGroup, plus a real trivy binary.
func TestConvertToCycloneDXAsTools(t *testing.T) {
	asUser := toolsCredential(t)
	trivyBin, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy not found on PATH: install Trivy (https://github.com/aquasecurity/trivy) to run this test")
	}

	dir, err := os.MkdirTemp("", "sealift-capcheck-convert-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// World-writable: tools needs to create the cache dir and write the
	// converted report inside, and its gid here is whatever the caller
	// passed in SEALIFT_TOOLS_GID, not necessarily this process' own group.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	reportPath := filepath.Join(dir, "report.trivy.json")
	if err := os.WriteFile(reportPath, []byte(minimalTrivyReport), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	cdxPath := filepath.Join(dir, "report.cdx.json")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli := NewTrivyCLI(trivyBin, filepath.Join(dir, "trivy-cache"), asUser)
	out, err := cli.ConvertToCycloneDX(ctx, reportPath, cdxPath)
	if err != nil {
		t.Fatalf("ConvertToCycloneDX as tools: %v\noutput:\n%s", err, out)
	}
	if _, err := os.Stat(cdxPath); err != nil {
		t.Fatalf("stat converted report: %v", err)
	}
}

// TestCancelKillsCrossUserGroup proves that a cancellation started by the
// server, running as app, reaches a child process group running as
// tools. This only means anything when this test
// binary itself runs as app with the image's file capabilities, which
// happens only inside a container built from the sealift Dockerfile;
// outside it, the test binary runs under the caller's own uid and cannot
// switch children to another user at all, so it skips instead of passing
// for the wrong reason.
func TestCancelKillsCrossUserGroup(t *testing.T) {
	asUser := toolsCredential(t)

	// os.MkdirTemp, not t.TempDir: the testing package nests the returned
	// directory inside a per-test parent it creates mode 0700, which would
	// block the tools child's traversal regardless of this dir's own mode.
	dir, err := os.MkdirTemp("", "sealift-capcheck-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	script := filepath.Join(dir, "sleep.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	var runErr error
	start := time.Now()
	go func() {
		_, runErr = run(ctx, dir, script, nil, asUser)
		close(done)
	}()

	time.Sleep(200 * time.Millisecond) // let the child start and reach the sleep
	cancel()

	select {
	case <-done:
	case <-time.After(killGrace + 2*time.Second):
		t.Fatalf("run did not return within killGrace+2s: cap_kill likely missing or ineffective")
	}
	elapsed := time.Since(start)

	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("run error = %v, want context.Canceled (a killGrace timeout means the group kill failed: EPERM without cap_kill)", runErr)
	}
	if elapsed >= killGrace {
		t.Fatalf("run took %s, at or past killGrace (%s): the SIGKILL likely needed the timeout fallback instead of succeeding", elapsed, killGrace)
	}
}
