// Package runner starts pnpm and Trivy as subprocesses: it writes their
// input files, runs the binary, and gives the caller the combined output.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// Credential identifies the uid and gid a child process runs as. A nil
// Credential leaves the child under the caller's own identity, the case
// outside the container.
type Credential struct {
	UID uint32
	GID uint32
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

	var out bytes.Buffer
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
		killGroup(cmd.Process.Pid)
		<-done // reap the process; its exit error carries no useful information
		return out.String(), ctx.Err()
	}
}

// killGroup sends SIGKILL to every process sharing pgid, which equals the
// leader's own pid since run starts each child with Setpgid.
func killGroup(pgid int) {
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
