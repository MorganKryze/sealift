package jobs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// rename is os.Rename; a test swaps it to make a rename cross filesystems.
var rename = os.Rename

// moveFile renames src to dst. When they sit on two filesystems, as with the
// ephemeral overlay's RAM mounts for projects and caches, it copies src to
// dst+".part", renames that into place and removes src, so dst never holds
// a partial file. The copy refuses a src that is not a regular file; a
// rename moves whatever entry sits at src, so a caller that needs a file
// at dst checks it there.
func moveFile(src, dst string) error {
	err := rename(src, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	// The downloads directory is writable by the tools account, which can
	// put a link or a FIFO at src. O_NOFOLLOW reads no link's target and
	// O_NONBLOCK keeps a FIFO from holding the open; the type check below
	// then refuses both.
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return errNotRegular(src)
	}
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errNotRegular(src)
	}
	part := dst + ".part"
	// The caches are writable by the tools account. Whatever sits at the
	// .part path goes, and O_EXCL refuses anything planted there again:
	// through a link, the copy would land in its target.
	if err := os.Remove(part); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o664)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(part)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(part)
		return err
	}
	if err := rename(part, dst); err != nil {
		_ = os.Remove(part)
		return err
	}
	return os.Remove(src)
}

func errNotRegular(path string) error {
	return fmt.Errorf("jobs: move %s: not a regular file", filepath.Base(path))
}

// createNew creates path for writing and fails when any entry holds the
// name already. The tools account can write every job directory, and
// through a link planted at path os.Create would fill the link's target.
func createNew(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o666)
}
