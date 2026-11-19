package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SetEphemeral switches the store to ephemeral mode: CreateProject then
// draws ids that do not derive from the project's name, so no log line
// names a project.
func (s *Store) SetEphemeral(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ephemeral = on
}

func (s *Store) isEphemeral() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ephemeral
}

// cacheDirs are the shared caches that hold what past projects fetched:
// pnpm's metadata and store, the export's tarball cache, and the resolve
// working directories.
var cacheDirs = []string{"pnpm", "tarballs", "resolve"}

// PurgeCaches empties the shared caches. Tools, the vulnerability database,
// the settings and the signing key stay.
func (s *Store) PurgeCaches() error {
	for _, name := range cacheDirs {
		dir := filepath.Join(s.root, "cache", name)
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("store: purge %s: %w", dir, err)
		}
	}
	// Open creates cache/resolve and NewResolveDir expects it.
	if err := os.MkdirAll(filepath.Join(s.root, "cache", "resolve"), dirMode); err != nil {
		return fmt.Errorf("store: recreate cache/resolve: %w", err)
	}
	return nil
}

// cachesEmpty reports whether no shared cache holds anything.
func (s *Store) cachesEmpty() (bool, error) {
	for _, name := range cacheDirs {
		entries, err := os.ReadDir(filepath.Join(s.root, "cache", name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("store: list cache/%s: %w", name, err)
		}
		if len(entries) > 0 {
			return false, nil
		}
	}
	return true, nil
}

// Busy reports whether any project has a job in flight: a job holds a .tmp
// directory from the moment it queues until it commits.
func (s *Store) Busy() (bool, error) {
	projects, err := os.ReadDir(filepath.Join(s.root, "projects"))
	if err != nil {
		return false, fmt.Errorf("store: list projects: %w", err)
	}
	for _, p := range projects {
		busy, err := projectBusy(filepath.Join(s.root, "projects", p.Name()))
		if err != nil || busy {
			return busy, err
		}
	}
	return false, nil
}

func projectBusy(dir string) (bool, error) {
	for _, kind := range []string{"analyses", "exports"} {
		entries, err := os.ReadDir(filepath.Join(dir, kind))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("store: list %s: %w", filepath.Join(dir, kind), err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				return true, nil
			}
		}
	}
	return false, nil
}

// lastActivity is the newest modification time under dir.
func lastActivity(dir string) (time.Time, error) {
	var newest time.Time
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return newest, err
}

// SweepEphemeral deletes every project with no job in flight whose newest
// file is older than idle, then empties the caches when no project remains
// and no job is in flight. It reports how many projects it deleted and
// whether it emptied the caches.
func (s *Store) SweepEphemeral(idle time.Duration, now time.Time) (deleted int, purged bool, err error) {
	root := filepath.Join(s.root, "projects")
	projects, err := os.ReadDir(root)
	if err != nil {
		return 0, false, fmt.Errorf("store: list projects: %w", err)
	}
	remaining := 0
	for _, p := range projects {
		dir := filepath.Join(root, p.Name())
		busy, err := projectBusy(dir)
		if err != nil {
			return deleted, false, err
		}
		last, err := lastActivity(dir)
		if err != nil {
			return deleted, false, fmt.Errorf("store: read %s: %w", dir, err)
		}
		if busy || now.Sub(last) < idle {
			remaining++
			continue
		}
		// DeleteProject checks again for a job queued since.
		switch err := s.DeleteProject(p.Name()); {
		case errors.Is(err, ErrBusy):
			remaining++
		case err != nil:
			return deleted, false, err
		default:
			deleted++
		}
	}
	if remaining > 0 {
		return deleted, false, nil
	}
	// A project created since the listing above may have queued a job.
	if busy, err := s.Busy(); err != nil || busy {
		return deleted, false, err
	}
	if empty, err := s.cachesEmpty(); err != nil || empty {
		return deleted, false, err
	}
	if err := s.PurgeCaches(); err != nil {
		return deleted, false, err
	}
	return deleted, true, nil
}
