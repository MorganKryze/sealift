package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeScript writes an executable shell script named name under dir and
// returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestRun_Success(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "echoer.sh", `echo "hello from child"
`)

	out, err := run(context.Background(), dir, script, nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out != "hello from child\n" {
		t.Fatalf("output = %q, want %q", out, "hello from child\n")
	}
}

func TestRun_ExitError(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "failer.sh", `echo "boom" >&2
exit 1
`)

	out, err := run(context.Background(), dir, script, nil, nil)
	if err == nil {
		t.Fatal("run: want error, got nil")
	}
	if out != "boom\n" {
		t.Fatalf("output = %q, want %q", out, "boom\n")
	}
}

// TestRun_CancelKillsGroup proves that canceling ctx kills the whole
// process group, not just the leader: the fake script forks a grandchild
// that writes a marker file after a delay, and the marker must never
// appear once the group has been killed well before that delay elapses.
func TestRun_CancelKillsGroup(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	script := writeScript(t, dir, "spawner.sh", fmt.Sprintf(`(sleep 1; echo done > %q) &
sleep 5
`, marker))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() {
		_, runErr = run(ctx, dir, script, nil, nil)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond) // let the script start and fork its grandchild
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("run error = %v, want context.Canceled", runErr)
	}

	time.Sleep(2 * time.Second) // past the grandchild's 1s delay
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker file exists (or stat failed differently): %v", err)
	}
}

// TestRun_AsUser proves a Credential reaches the child's real uid and gid.
// It needs root to switch to another user, so it is skipped otherwise; the
// container path where the server actually runs as root is covered by the
// image test of the next plan.
func TestRun_AsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set a child's credential; the container path is covered by the image test of the next plan")
	}

	dir := t.TempDir()
	script := writeScript(t, dir, "whoami.sh", `id -u
id -g
`)

	const uid, gid = 65534, 65534 // nobody, present on both Linux and this test image
	out, err := run(context.Background(), dir, script, nil, &Credential{UID: uid, GID: gid})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	want := fmt.Sprintf("%d\n%d\n", uid, gid)
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}
