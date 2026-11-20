package jobs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// moveFixture writes src in one directory and returns it with dst in
// another, and makes the first rename fail with EXDEV, as between two
// filesystems.
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
	prev := rename
	t.Cleanup(func() { rename = prev })
	calls := 0
	rename = func(from, to string) error {
		calls++
		if calls == 1 {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EXDEV}
		}
		return os.Rename(from, to)
	}
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
