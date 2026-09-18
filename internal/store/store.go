package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// dirMode is the mode of every directory under the data volume except
// private/, so the tools user's group can create and write files in it.
// fileMode is the mode of every file the store writes there, for the same
// reason. settingsMode and privateMode keep private/settings.json unreadable
// outside the owner.
const (
	dirMode      = 0o770
	privateMode  = 0o700
	fileMode     = 0o664
	settingsMode = 0o600
)

// defaultSettings are the values a freshly created store starts with.
var defaultSettings = Settings{
	Target: Target{
		OS:      "linux",
		CPU:     "x64",
		Libc:    "glibc",
		Node:    "22.17.1",
		PnpmVer: "10.34.5",
	},
	MinReleaseAgeDays:   7,
	ResolveParallelism:  4,
	DownloadParallelism: 16,
}

// Store is sealift's data volume: settings, projects, analyses and exports
// rooted at one directory.
type Store struct {
	root string

	mu       sync.RWMutex
	settings Settings
}

// Open creates the data volume layout under root when it is missing, then
// loads private/settings.json or writes the defaults there.
//
// It also sets the process umask to 002. A container's default umask of 022
// would strip the group write bit from every file this package creates
// through os.OpenFile, and the tools user needs that bit to write lockfiles
// and caches outside private/.
func Open(root string) (*Store, error) {
	syscall.Umask(0o002)

	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{root, dirMode},
		{filepath.Join(root, "private"), privateMode},
		{filepath.Join(root, "tools"), dirMode},
		{filepath.Join(root, "trivy-cache"), dirMode},
		{filepath.Join(root, "cache"), dirMode},
		{filepath.Join(root, "cache", "resolve"), dirMode},
		{filepath.Join(root, "projects"), dirMode},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", d.path, err)
		}
	}

	s := &Store{root: root}
	settingsPath := filepath.Join(root, "private", "settings.json")
	switch _, err := os.Stat(settingsPath); {
	case errors.Is(err, os.ErrNotExist):
		if err := s.SaveSettings(defaultSettings); err != nil {
			return nil, fmt.Errorf("store: write default settings: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("store: stat settings: %w", err)
	default:
		var loaded Settings
		if err := readJSONFile(settingsPath, &loaded); err != nil {
			return nil, fmt.Errorf("store: read settings: %w", err)
		}
		s.mu.Lock()
		s.settings = loaded
		s.mu.Unlock()
	}
	return s, nil
}

// Root returns the directory the store is rooted at.
func (s *Store) Root() string { return s.root }

// Settings returns the current settings. Safe for concurrent use.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// SaveSettings atomically writes settings to private/settings.json, mode
// 0600, and refuses a target whose OS, CPU, Node or PnpmVer is empty.
func (s *Store) SaveSettings(set Settings) error {
	if err := validateTarget(set.Target); err != nil {
		return err
	}
	path := filepath.Join(s.root, "private", "settings.json")
	if err := writeJSONFile(path, set, settingsMode); err != nil {
		return err
	}
	s.mu.Lock()
	s.settings = set
	s.mu.Unlock()
	return nil
}

// validateTarget refuses a target the rest of the pipeline cannot resolve or
// export with.
func validateTarget(t Target) error {
	if t.OS == "" || t.CPU == "" || t.Node == "" || t.PnpmVer == "" {
		return fmt.Errorf("store: target missing a required field: %+v", t)
	}
	return nil
}

// atomicWriteFile writes data to a temporary file next to path and renames
// it into place, so a crash never leaves a partial file where callers expect
// a complete one. The temporary file is created with mode directly, so the
// process umask set by Open governs the group write bit the same way it
// would for any other file the store writes.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("store: create %s: %w", dir, err)
	}

	tmp, err := tempFile(dir, filepath.Base(path), mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // no-op once the rename below succeeds

	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: rename to %s: %w", path, err)
	}
	return nil
}

// NewResolveDir reserves a fresh, group-writable directory under
// cache/resolve for one isolated pnpm resolution. Unlike os.MkdirTemp,
// which always creates mode 0700 under the system temp directory, this
// stays under the volume Open laid out and in a mode the tools account can
// traverse once it runs pnpm as a different uid. The caller removes the
// directory once the resolution ends.
func (s *Store) NewResolveDir() (string, error) {
	parent := filepath.Join(s.root, "cache", "resolve")
	for attempt := 0; attempt < 10; attempt++ {
		suffix, err := randomHex(6)
		if err != nil {
			return "", fmt.Errorf("store: generate resolve dir name: %w", err)
		}
		dir := filepath.Join(parent, suffix)
		if err := os.Mkdir(dir, dirMode); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("store: create %s: %w", dir, err)
		}
		return dir, nil
	}
	return "", fmt.Errorf("store: could not allocate a resolve dir under %s", parent)
}

// tempFile reserves a unique path in dir for name and returns it, without
// leaving the file behind for atomicWriteFile to overwrite with the real
// content and mode.
func tempFile(dir, name string, mode os.FileMode) (string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		suffix, err := randomHex(4)
		if err != nil {
			return "", fmt.Errorf("store: generate temp name: %w", err)
		}
		path := filepath.Join(dir, "."+name+".tmp-"+suffix)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			return path, f.Close()
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("store: create %s: %w", path, err)
		}
	}
	return "", fmt.Errorf("store: could not reserve a temp file for %s", name)
}

func writeJSONFile(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", path, err)
	}
	return atomicWriteFile(path, data, mode)
}

func readJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("store: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("store: unmarshal %s: %w", path, err)
	}
	return nil
}

// validID refuses an identifier that could escape the directory it names.
// Handlers pass path parameters straight through, so this is the last check
// before a path join.
func validID(s string) error {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") || strings.Contains(s, "..") {
		return fmt.Errorf("%w: invalid identifier %q", ErrNotFound, s)
	}
	for _, r := range s {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_'
		if !allowed {
			return fmt.Errorf("%w: invalid identifier %q", ErrNotFound, s)
		}
	}
	return nil
}

// randomHex returns n random bytes as a lowercase hex string. It backs both
// the temp file names atomicWriteFile picks and, through randomHexFunc, the
// project ID suffix in project.go.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
