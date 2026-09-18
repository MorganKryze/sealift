// Package tools installs and manages the pnpm and Trivy binaries that
// sealift's jobs run as subprocesses.
package tools

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/MorganKryze/sealift/internal/store"
)

// defaultGitHubAPI is the public GitHub API, overridden in tests through
// Manager.GitHubAPI.
const defaultGitHubAPI = "https://api.github.com"

// Volume is the narrow view of the data volume that Manager needs. The
// store package builds it; a caller outside the container can supply any
// implementation with the same root and settings.
type Volume interface {
	Root() string
	Settings() store.Settings
}

// Manager installs pnpm and Trivy under the data volume and switches which
// installed Trivy version is active.
type Manager struct {
	vol  Volume
	http *http.Client
	log  *slog.Logger

	// NPMRegistry overrides the npm registry base URL. Empty uses the
	// public registry; tests point it at an httptest server.
	NPMRegistry string
	// GitHubAPI overrides the GitHub API base URL. Empty uses the public
	// API; tests point it at an httptest server.
	GitHubAPI string
	// Arch overrides the host CPU architecture used to pick the Trivy
	// release asset. Empty uses runtime.GOARCH.
	Arch string
}

// NewManager returns a Manager that installs tools into vol's data volume,
// using httpClient for every registry and release request.
func NewManager(vol Volume, httpClient *http.Client, log *slog.Logger) *Manager {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Manager{vol: vol, http: httpClient, log: log}
}

func (m *Manager) githubAPI() string {
	if m.GitHubAPI != "" {
		return strings.TrimSuffix(m.GitHubAPI, "/")
	}
	return defaultGitHubAPI
}

// errUnsafePath reports a tar entry with an absolute path or a ".." segment.
var errUnsafePath = errors.New("unsafe path in archive")

// extractTarGz extracts a gzip-compressed tar archive into destDir, which
// it creates if missing. It rejects entries that would escape destDir.
func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open tar.gz: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		target, err := safeJoin(destDir, h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o770); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeTarFile(target, tr, h.FileInfo().Mode()); err != nil {
				return err
			}
		}
	}
}

// safeJoin joins destDir and name, rejecting a name that escapes destDir.
func safeJoin(destDir, name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", errUnsafePath, name)
	}
	return filepath.Join(destDir, clean), nil
}

func writeTarFile(target string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o770); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm()|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// installDir renames a freshly extracted "<dir>.tmp" into dir, removing any
// stale partial extraction first so a crash never leaves dir half-written.
func installDir(dir string, extract func(tmp string) error) error {
	tmp := dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := extract(tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o770); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	return nil
}
