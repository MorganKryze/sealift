package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
// pnpm's metadata and store, uv's index pages and metadata, the npm
// export's tarball cache, the pip export's wheel cache, and the resolve
// working directories.
var cacheDirs = []string{"pnpm", "uv", "tarballs", "wheels", "resolve"}

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

// anyJob reports whether hasJob finds a job queued or running for any
// project. hasJob comes from the job service: a job directory outlives
// its job when the commit fails, so the directories cannot tell.
func (s *Store) anyJob(hasJob func(projectID string) bool) (bool, error) {
	projects, err := os.ReadDir(filepath.Join(s.root, "projects"))
	if err != nil {
		return false, fmt.Errorf("store: list projects: %w", err)
	}
	for _, p := range projects {
		if hasJob(p.Name()) {
			return true, nil
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

// PurgeIfIdleUnguarded skips the job service's guard: a job queued
// during the call can lose its caches. Callers outside tests go through
// jobs.Service.PurgeIfIdle. It empties the caches when hasJob finds no project with a job
// queued or running. Otherwise it records the purge as pending, for the
// sweep to run once the instance is idle. It reports whether it emptied
// anything.
func (s *Store) PurgeIfIdleUnguarded(hasJob func(projectID string) bool) (bool, error) {
	s.purgeMu.Lock()
	defer s.purgeMu.Unlock()
	busy, err := s.anyJob(hasJob)
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

// SweepEphemeralUnguarded skips the job service's guard on its own:
// callers outside tests go through jobs.Service.SweepEphemeral, which
// passes its guarded delete and purge. It deletes, through deleteProject, every project for which
// hasJob finds no job queued or running and whose newest file is older
// than idle. deleteProject answers ErrBusy for a project whose job was
// queued since the sweep looked, and that project stays. A project it
// cannot read or delete is counted and skipped, so one bad entry never
// stops the others. It then calls purgeIfIdle when no project remains or
// a purge was put off. The job service passes its own PurgeIfIdle, which
// holds off new jobs during the purge.
func (s *Store) SweepEphemeralUnguarded(idle time.Duration, now time.Time, hasJob func(projectID string) bool, deleteProject func(id string) error, purgeIfIdle func() (bool, error)) Sweep {
	var r Sweep
	root := filepath.Join(s.root, "projects")
	projects, err := os.ReadDir(root)
	if err != nil {
		r.Failed++
		return r
	}
	remaining := 0
	for _, p := range projects {
		if hasJob(p.Name()) {
			remaining++
			continue
		}
		last, err := lastActivity(filepath.Join(root, p.Name()))
		if err != nil {
			r.Failed++
			remaining++
			continue
		}
		if now.Sub(last) < idle {
			remaining++
			continue
		}
		switch err := deleteProject(p.Name()); {
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
		purged, err := purgeIfIdle()
		if err != nil {
			r.Failed++
		}
		r.Purged = purged
	}
	return r
}
