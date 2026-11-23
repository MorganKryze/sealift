package runner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readOutput reads the file a tool wrote at dir/name, refusing one above
// limit bytes. The tools account can write dir: O_NOFOLLOW reads no link's
// target, the signing key included, and O_NONBLOCK keeps a FIFO from
// holding the open. Anything but a regular file is refused.
func readOutput(dir, name string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, notRegular(name)
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return nil, fmt.Errorf("open %s: %w", name, pathErr.Err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, notRegular(name)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(f, limit+1)); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB", name, limit>>20)
	}
	return buf.Bytes(), nil
}

func notRegular(name string) error {
	return fmt.Errorf("%s is not a regular file", name)
}

// writeNew writes data to a file it creates at dir/name, failing when any
// entry holds the name already. The tools account can write dir, and
// through a link planted there a plain write would fill the link's target.
// The caller's resolve directory is fresh, so a legitimate write always
// finds the name free.
func writeNew(dir, name string, data []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o664)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
