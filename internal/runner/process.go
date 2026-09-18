// Package runner starts pnpm and Trivy as subprocesses: it writes their
// input files, runs the binary, and gives the caller the combined output.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Credential identifies the uid and gid a child process runs as. A nil
// Credential leaves the child under the caller's own identity, the case
// outside the container.
type Credential struct {
	UID uint32
	GID uint32
}

// killGrace bounds how long run waits for a child to exit once ctx is
// canceled and the group has been sent SIGKILL. A test shrinks it to keep
// the timeout path fast; production code never reassigns it.
var killGrace = 5 * time.Second

// killGroup sends sig to every process sharing pgid, which equals the
// leader's own pid since run starts each child with Setpgid. A test
// replaces it to simulate the container's missing CAP_KILL (see run).
var killGroup = syscall.Kill

// syncBuffer guards a bytes.Buffer with a mutex. Once the wait after a
// group kill can time out, run may read the child's output while its
// stdout and stderr copy goroutines are still writing to it, so a plain
// bytes.Buffer is no longer safe here.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// run starts name with args in dir and waits for it to end or for ctx to be
// canceled. Every child gets its own process group (Setpgid): a
// cancellation kills the whole group with a single signal, not just the
// leader, so a grandchild pnpm or Trivy spawns cannot outlive it. A nil dir
// leaves the child in the caller's own working directory. It returns the
// combined stdout and stderr, so a failure still carries the tool's output
// for the caller to show.
func run(ctx context.Context, dir, name string, args []string, asUser *Credential) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if asUser != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: asUser.UID, Gid: asUser.GID}
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start %s: %w", name, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return out.String(), err
	case <-ctx.Done():
		pid := cmd.Process.Pid
		// In the container the server runs as app and children run as
		// tools; kill(2) on another user's process group needs CAP_KILL,
		// which the image grants the server binary. A signal can still
		// fail to reach a group that already exited on its own, so bound
		// the wait instead of blocking forever on a child that outlived
		// its cancellation.
		killErr := killGroup(-pid, syscall.SIGKILL)
		select {
		case <-done: // reap the process; its exit error carries no useful information
			return out.String(), ctx.Err()
		case <-time.After(killGrace):
			if killErr != nil {
				return out.String(), fmt.Errorf("pid %d outlived cancellation after %s: group kill failed: %w", pid, killGrace, killErr)
			}
			return out.String(), fmt.Errorf("pid %d outlived cancellation after %s despite a successful group kill", pid, killGrace)
		}
	}
}
