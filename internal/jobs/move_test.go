package jobs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// With the projects and the caches on two filesystems (the ephemeral
// overlay mounts each in RAM), a rename between them fails with EXDEV and
// the move falls back to a copy.
func TestMoveFileAcrossFilesystems(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a", "x.tgz")
	dst := filepath.Join(dir, "b", "x.tgz")
	for _, d := range []string{filepath.Dir(src), filepath.Dir(dst)} {
		if err := os.MkdirAll(d, 0o770); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src, []byte("tarball"), 0o664); err != nil {
		t.Fatal(err)
	}
	defer func(prev func(string, string) error) { rename = prev }(rename)
	calls := 0
	rename = func(from, to string) error {
		calls++
		if calls == 1 {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EXDEV}
		}
		return os.Rename(from, to)
	}
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
