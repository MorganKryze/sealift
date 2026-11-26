package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// nowFunc generates the UTC timestamp NewDir bases an id on. Tests override
// it to force two calls into the same second deterministically; production
// code never reassigns it.
var nowFunc = time.Now

// Pending is an analysis or export directory being written under a .tmp
// name. Commit publishes it atomically; Discard removes it and everything
// under it.
type Pending struct {
	final string // the path Commit renames to
	id    string
}

// NewDir creates a new pending directory for a project, named after the
// current UTC time. kind is "analyses" or "exports". The caller writes into
// Path and calls Commit or Discard when done.
//
// The first job of a second takes the bare timestamp; each later one in
// that second takes the timestamp, "-" and the next six-digit hex counter
// after the highest one already there, pending or committed. The counter
// keeps jobs of one second listed in creation order, where a random suffix
// would not. Ids from before the counter, with a random suffix, keep their
// place: a new job of their second still counts past them.
func (s *Store) NewDir(kind, projectID string) (*Pending, error) {
	if kind != "analyses" && kind != "exports" {
		return nil, fmt.Errorf("%w: invalid kind %q", ErrNotFound, kind)
	}
	if err := validID(projectID); err != nil {
		return nil, err
	}
	s.purgeMu.RLock()
	defer s.purgeMu.RUnlock()

	parent := filepath.Join(s.root, "projects", projectID, kind)
	if err := os.MkdirAll(parent, dirMode); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", parent, err)
	}

	base := nowFunc().UTC().Format(analysisIDLayout)
	// Each miss means a concurrent call took the id first, so a retry
	// only fails past this many jobs racing for one project and second.
	for attempt := 0; attempt < 10; attempt++ {
		id, err := nextJobID(parent, base)
		if err != nil {
			return nil, err
		}
		final := filepath.Join(parent, id)
		tmp := final + ".tmp"
		if err := os.Mkdir(tmp, dirMode); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, fmt.Errorf("store: create %s: %w", tmp, err)
		}
		// A concurrent call may have committed this id between the scan
		// and the Mkdir above.
		if _, err := os.Stat(final); err == nil {
			_ = os.Remove(tmp)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("store: stat %s: %w", final, err)
		}
		return &Pending{final: final, id: id}, nil
	}
	return nil, fmt.Errorf("store: could not allocate an id under %s/%s", projectID, kind)
}

// nextJobID returns the id NewDir tries next for the second base names:
// base itself when no directory of that second exists under parent, or
// base, "-" and the highest counter found there plus one.
func nextJobID(parent, base string) (string, error) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", fmt.Errorf("store: list %s: %w", parent, err)
	}
	taken := false
	var highest uint64
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".tmp")
		if name == base {
			taken = true
			continue
		}
		suffix, ok := strings.CutPrefix(name, base+"-")
		if !ok || len(suffix) != 6 || strings.Trim(suffix, "0123456789abcdef") != "" {
			continue
		}
		n, err := strconv.ParseUint(suffix, 16, 32)
		if err != nil {
			continue
		}
		taken = true
		highest = max(highest, n)
	}
	switch {
	case !taken:
		return base, nil
	case highest == 0xffffff:
		return "", fmt.Errorf("store: no id left for %s under %s", base, parent)
	}
	return fmt.Sprintf("%s-%06x", base, highest+1), nil
}

// Path returns the <id>.tmp directory the caller writes into.
func (p *Pending) Path() string { return p.final + ".tmp" }

// Final returns the path Commit renames Path to: the directory a reader
// finds once the job has published it. A caller that needs to read back
// something a completed job wrote, such as reconciling a status.json
// field against the queue's own account of how the job ended, uses this
// rather than assuming Path with its ".tmp" suffix trimmed.
func (p *Pending) Final() string { return p.final }

// ID returns the analysis or export ID this directory commits under.
func (p *Pending) ID() string { return p.id }

// Commit renames the <id>.tmp directory to <id>, publishing it atomically.
// Nothing under a committed directory changes afterward.
func (p *Pending) Commit() error {
	if err := os.Rename(p.Path(), p.final); err != nil {
		return fmt.Errorf("store: commit %s: %w", p.final, err)
	}
	return nil
}

// Discard removes the <id>.tmp directory and everything under it, leaving
// no trace of a job that never finished.
func (p *Pending) Discard() error {
	if err := os.RemoveAll(p.Path()); err != nil {
		return fmt.Errorf("store: discard %s: %w", p.Path(), err)
	}
	return nil
}

// WriteJSON atomically marshals v as indented JSON to path, mode 0664, so a
// reader never observes a partial file.
func (s *Store) WriteJSON(path string, v any) error {
	return writeJSONFile(path, v, fileMode)
}

// WriteFile atomically writes data to path, mode 0664, so a reader never
// observes a partial file.
func (s *Store) WriteFile(path string, data []byte) error {
	return atomicWriteFile(path, data, fileMode)
}

// ReadJSON unmarshals the JSON file at path into v.
func (s *Store) ReadJSON(path string, v any) error {
	return readJSONFile(path, v)
}
