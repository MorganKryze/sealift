package jobs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// rename is os.Rename; a test swaps it to make a rename cross filesystems.
var rename = os.Rename

// moveFile renames src to dst. When they sit on two filesystems, as with the
// ephemeral overlay's RAM mounts for projects and caches, it copies src to
// dst+".part", renames that into place and removes src, so dst never holds
// a partial file.
func moveFile(src, dst string) error {
	err := rename(src, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
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
