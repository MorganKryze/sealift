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
// pnpm's metadata and store, uv's index pages and metadata, the export's
// tarball cache, and the resolve working directories.
var cacheDirs = []string{"pnpm", "uv", "tarballs", "resolve"}

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

// lastActivity is the newest modification time under dir. An entry that
// vanishes during the walk, such as a download a job moves into the cache,
// is skipped.
func lastActivity(dir string) (time.Time, error) {
	var newest time.Time
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		info, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
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

// PurgeIfIdle empties the caches when no job is in flight. With a job in
// flight it records the purge as pending, for the sweep to run once the
// instance is idle. It reports whether it emptied anything.
func (s *Store) PurgeIfIdle() (bool, error) {
	s.purgeMu.Lock()
	defer s.purgeMu.Unlock()
	busy, err := s.Busy()
	if err != nil {
		return false, err
	}
	if busy {
		s.purgePending = true
		return false, nil
	}
	empty, err := s.cachesEmpty()
	if err != nil {
		return false, err
	}
	if !empty {
		if err := s.PurgeCaches(); err != nil {
			return false, err
		}
	}
	s.purgePending = false
	return !empty, nil
}

func (s *Store) isPurgePending() bool {
	s.purgeMu.RLock()
	defer s.purgeMu.RUnlock()
	return s.purgePending
}

// Sweep is what one SweepEphemeral pass did. Failed counts the projects it
// could not read or delete; their errors stay out of the log, since a path
// under a project can name a package.
type Sweep struct {
	Deleted int
	Purged  bool
	Failed  int
}

// SweepEphemeral deletes every project with no job in flight whose newest
// file is older than idle. A project it cannot read or delete is counted
// and skipped, so one bad entry never stops the others. It then empties the
// caches when the instance is idle and either no project remains or a
// purge was put off.
func (s *Store) SweepEphemeral(idle time.Duration, now time.Time) Sweep {
	var r Sweep
	root := filepath.Join(s.root, "projects")
	projects, err := os.ReadDir(root)
	if err != nil {
		r.Failed++
		return r
	}
	remaining := 0
	for _, p := range projects {
		dir := filepath.Join(root, p.Name())
		busy, err := projectBusy(dir)
		if err != nil || busy {
			if err != nil {
				r.Failed++
			}
			remaining++
			continue
		}
		last, err := lastActivity(dir)
		if err != nil {
			r.Failed++
			remaining++
			continue
		}
		if now.Sub(last) < idle {
			remaining++
			continue
		}
		// DeleteProject checks again for a job queued since.
		switch err := s.DeleteProject(p.Name()); {
		case err == nil:
			r.Deleted++
		case errors.Is(err, ErrNotFound):
			// Deleted by hand during this pass.
		case errors.Is(err, ErrBusy):
			remaining++
		default:
			r.Failed++
			remaining++
		}
	}
	if remaining == 0 || s.isPurgePending() {
		purged, err := s.PurgeIfIdle()
		if err != nil {
			r.Failed++
		}
		r.Purged = purged
	}
	return r
}
