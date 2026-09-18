package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// Two calls inside the same second would otherwise get the same ID: this
// checks both the pending (.tmp) and the final path before reserving one,
// and appends a short random suffix to the second try onward, the same
// defense reserveProjectDir gives project IDs. Without it, the second job's
// own Commit would collide with the first job's already-committed
// directory of the same timestamp.
func (s *Store) NewDir(kind, projectID string) (*Pending, error) {
	if kind != "analyses" && kind != "exports" {
		return nil, fmt.Errorf("%w: invalid kind %q", ErrNotFound, kind)
	}
	if err := validID(projectID); err != nil {
		return nil, err
	}

	parent := filepath.Join(s.root, "projects", projectID, kind)
	if err := os.MkdirAll(parent, dirMode); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", parent, err)
	}

	base := nowFunc().UTC().Format("20060102T150405Z")
	for attempt := 0; attempt < 10; attempt++ {
		id := base
		if attempt > 0 {
			suffix, err := randomHex(3)
			if err != nil {
				return nil, fmt.Errorf("store: generate %s id: %w", kind, err)
			}
			id = base + "-" + suffix
		}
		final := filepath.Join(parent, id)
		tmp := final + ".tmp"
		if _, err := os.Stat(final); err == nil {
			continue // a committed directory already holds this id
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("store: stat %s: %w", final, err)
		}
		if err := os.Mkdir(tmp, dirMode); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, fmt.Errorf("store: create %s: %w", tmp, err)
		}
		return &Pending{final: final, id: id}, nil
	}
	return nil, fmt.Errorf("store: could not allocate an id under %s/%s", projectID, kind)
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

// ReadJSON unmarshals the JSON file at path into v.
func (s *Store) ReadJSON(path string, v any) error {
	return readJSONFile(path, v)
}
