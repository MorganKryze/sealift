package runner

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadOutput(t *testing.T) {
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		plant   func(path string) error
		want    string
		wantErr string
	}{
		{"regular", func(p string) error { return os.WriteFile(p, []byte("lock"), 0o600) }, "lock", ""},
		{"at the limit", func(p string) error { return os.WriteFile(p, []byte("12345678"), 0o600) }, "12345678", ""},
		{"above the limit", func(p string) error { return os.WriteFile(p, []byte("123456789"), 0o600) }, "", "out is larger than 0 MiB"},
		{"link", func(p string) error { return os.Symlink(target, p) }, "", "out is not a regular file"},
		{"fifo", func(p string) error { return syscall.Mkfifo(p, 0o600) }, "", "out is not a regular file"},
		{"directory", func(p string) error { return os.Mkdir(p, 0o700) }, "", "out is not a regular file"},
		{"missing", func(string) error { return nil }, "", "open out: no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := tc.plant(filepath.Join(dir, "out")); err != nil {
				t.Fatal(err)
			}
			got, err := readOutput(dir, "out", 8)
			if tc.wantErr == "" {
				if err != nil || string(got) != tc.want {
					t.Fatalf("readOutput = %q, %v, want %q", got, err, tc.want)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("readOutput error = %v, want %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), dir) {
				t.Errorf("error %q names the directory", err)
			}
		})
	}
}
