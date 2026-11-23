package jobs

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
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

// writeNew writes data to a file it creates at path, under createNew's rule.
func writeNew(path string, data []byte) error {
	f, err := createNew(path)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// openLog opens the log at path for appending, creating it. O_NOFOLLOW
// refuses a link planted there, through which the log would land in the
// link's target.
func openLog(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o664)
}

// recorded is what a file read again must still hold: its length and hex
// digests, and its name for the error. An empty sha256 goes unchecked, as
// an npm lockfile records sha512 alone.
type recorded struct {
	name           string
	size           int64
	sha256, sha512 string
}

// changedAfterDownload is the error for a file whose bytes are no longer
// the ones checked when it was downloaded.
func changedAfterDownload(name string) error {
	return fmt.Errorf("%s changed after its download", name)
}

// openRegular opens path for reading when it is a regular file. The tools
// account can write the caches and the export directory: O_NOFOLLOW reads
// no link's target and O_NONBLOCK keeps a FIFO from holding the open.
// What is gone, a link or anything but a regular file has changed after
// its download.
func openRegular(path, name string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ELOOP):
		return nil, nil, changedAfterDownload(name)
	case err != nil:
		return nil, nil, fmt.Errorf("open %s: %w", name, withoutPath(err))
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, changedAfterDownload(name)
	}
	return f, st, nil
}

// readRegularFile reads the regular file at path, refusing one above limit
// bytes. The tools account can write the directories it reads from:
// O_NOFOLLOW reads no link's target, and O_NONBLOCK keeps a FIFO from
// holding an open that no cancel interrupts.
func readRegularFile(path string, limit int64) ([]byte, error) {
	name := filepath.Base(path)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB", name, limit>>20)
	}
	return data, nil
}

// openUnchanged opens path, under openRegular's rule, behind a reader that
// fails once the bytes read differ from want.
func openUnchanged(path string, want recorded) (io.ReadCloser, error) {
	f, _, err := openRegular(path, want.name)
	if err != nil {
		return nil, err
	}
	return newRehashed(f, want), nil
}

func newRehashed(f *os.File, want recorded) *rehashed {
	return &rehashed{f: f, want: want, h256: sha256.New(), h512: sha512.New()}
}

// rehashed reads a file and checks, at its end, that its length and
// digests are the ones recorded.
type rehashed struct {
	f          *os.File
	want       recorded
	h256, h512 hash.Hash
	n          int64
}

func (r *rehashed) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	if room := r.want.size - r.n; int64(n) > room {
		// The bytes past the recorded size never reach the archive, so the
		// tar writer cannot report a longer entry before this check does.
		r.n += int64(n)
		return int(room), changedAfterDownload(r.want.name)
	}
	r.h256.Write(p[:n])
	r.h512.Write(p[:n])
	r.n += int64(n)
	if errors.Is(err, io.EOF) && (r.n != r.want.size ||
		(r.want.sha256 != "" && hex.EncodeToString(r.h256.Sum(nil)) != r.want.sha256) ||
		hex.EncodeToString(r.h512.Sum(nil)) != r.want.sha512) {
		return n, changedAfterDownload(r.want.name)
	}
	return n, err
}

func (r *rehashed) Close() error { return r.f.Close() }
