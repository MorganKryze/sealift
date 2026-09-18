package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
)

// fakeVolume implements Volume with an in-memory settings value and a
// temporary root, so tests never touch the real store package.
type fakeVolume struct {
	root     string
	settings store.Settings
}

func (v fakeVolume) Root() string             { return v.root }
func (v fakeVolume) Settings() store.Settings { return v.settings }

// buildTarGz packs files (path to content) into a gzip-compressed tar
// archive, mirroring the shape of a real release or package tarball.
func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestNewManagerDefaultsHTTPClient(t *testing.T) {
	m := NewManager(fakeVolume{root: t.TempDir()}, nil, nil)
	if m.http != http.DefaultClient {
		t.Fatalf("NewManager with a nil client did not default to http.DefaultClient")
	}
}

func TestExtractTarGzWritesFilesAndDirs(t *testing.T) {
	data := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"x"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	dest := filepath.Join(t.TempDir(), "out")

	if err := extractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "package", "bin", "pnpm.cjs"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "#!/usr/bin/env node\n" {
		t.Fatalf("extracted content = %q", got)
	}
}

func TestExtractTarGzRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{"../escape.txt", "/etc/passwd", "a/../../escape.txt"} {
		data := buildTarGz(t, map[string]string{name: "x"})
		dest := filepath.Join(t.TempDir(), "out")
		if err := extractTarGz(bytes.NewReader(data), dest); err == nil {
			t.Fatalf("extractTarGz(%q): want error, got nil", name)
		}
	}
}

// TestActivateTrivyConcurrentCallsDoNotRace exercises Manager's mutex: two
// installed versions activated from separate goroutines must not race on
// the shared "current" symlink. go test -race is what actually catches a
// missing lock here; this only gives it something concurrent to catch.
func TestActivateTrivyConcurrentCallsDoNotRace(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, nil, nil)
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if err := os.MkdirAll(filepath.Join(root, "tools", "trivy", v), 0o770); err != nil {
			t.Fatalf("mkdir %s: %v", v, err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		version := []string{"1.0.0", "2.0.0"}[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.ActivateTrivy(version); err != nil {
				t.Errorf("ActivateTrivy(%s): %v", version, err)
			}
		}()
	}
	wg.Wait()
}
