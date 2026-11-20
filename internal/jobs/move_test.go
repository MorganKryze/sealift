package jobs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// crossFilesystems makes every move fall back to its copy, as between the
// ephemeral overlay's RAM mounts: a rename fails with EXDEV unless it puts
// the copy's .part file in place.
func crossFilesystems(t *testing.T) {
	t.Helper()
	prev := rename
	t.Cleanup(func() { rename = prev })
	rename = func(from, to string) error {
		if !strings.HasSuffix(from, ".part") {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EXDEV}
		}
		return os.Rename(from, to)
	}
}

// moveFixture writes src in one directory and returns it with dst in
// another, on two filesystems as far as moveFile can tell.
func moveFixture(t *testing.T) (src, dst string) {
	t.Helper()
	dir := t.TempDir()
	src = filepath.Join(dir, "a", "x.tgz")
	dst = filepath.Join(dir, "b", "x.tgz")
	for _, d := range []string{filepath.Dir(src), filepath.Dir(dst)} {
		if err := os.MkdirAll(d, 0o770); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src, []byte("tarball"), 0o664); err != nil {
		t.Fatal(err)
	}
	crossFilesystems(t)
	return src, dst
}

// With the projects and the caches on two filesystems (the ephemeral
// overlay mounts each in RAM), a rename between them fails with EXDEV and
// the move falls back to a copy.
func TestMoveFileAcrossFilesystems(t *testing.T) {
	src, dst := moveFixture(t)
	if err := moveFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "tarball" {
		t.Errorf("dst = %q, %v; want the tarball", b, err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src still there after the move")
	}
	if _, err := os.Stat(dst + ".part"); !os.IsNotExist(err) {
		t.Errorf("the .part file stayed")
	}
}

// The caches are writable by the tools account, which may plant a link at
// the copy's .part path, aimed at a file only this process may write.
func TestMoveFileDoesNotWriteThroughALinkAtThePartPath(t *testing.T) {
	src, dst := moveFixture(t)
	victim := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(victim, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, dst+".part"); err != nil {
		t.Fatal(err)
	}
	if err := moveFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "private" {
		t.Errorf("the link's target holds %q (%v), want it untouched", b, err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "tarball" {
		t.Errorf("dst = %q, %v; want the tarball", b, err)
	}
	if _, err := os.Lstat(dst + ".part"); !os.IsNotExist(err) {
		t.Errorf("the .part entry stayed")
	}
}

// The downloads directory is writable by the tools account, which may put
// a link to a private file or a FIFO where the move's source was. The
// copy reads through no link and waits on no FIFO: it refuses both and
// leaves nothing at dst.
func TestMoveFileRefusesASourceThatIsNotAFile(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, src, victim string)
	}{
		{"a link to a private file", func(t *testing.T, src, victim string) {
			if err := os.Symlink(victim, src); err != nil {
				t.Fatal(err)
			}
		}},
		{"a FIFO", func(t *testing.T, src, _ string) {
			if err := syscall.Mkfifo(src, 0o660); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := moveFixture(t)
			victim := filepath.Join(t.TempDir(), "signing-key.pem")
			if err := os.WriteFile(victim, []byte("private"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(src); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, src, victim)

			done := make(chan error, 1)
			go func() { done <- moveFile(src, dst) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("moveFile = %v, want a refusal of a source that is not a regular file", err)
				}
			case <-time.After(10 * time.Second):
				// An open blocked on the FIFO returns once a writer opens it.
				if w, err := os.OpenFile(src, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = w.Close()
				}
				t.Fatalf("moveFile was still waiting on its source after 10s, then returned %v", <-done)
			}
			for _, p := range []string{dst, dst + ".part"} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("%s exists after the refusal (%v)", filepath.Base(p), err)
				}
			}
			if b, err := os.ReadFile(victim); err != nil || string(b) != "private" {
				t.Errorf("the private file holds %q (%v), want it untouched", b, err)
			}
		})
	}
}
