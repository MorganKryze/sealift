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
