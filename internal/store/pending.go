package store

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

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
func (s *Store) NewDir(kind, projectID string) (*Pending, error) {
	id := time.Now().UTC().Format("20060102T150405Z")
	final := filepath.Join(s.root, "projects", projectID, kind, id)
	tmp := final + ".tmp"
	if err := os.MkdirAll(tmp, dirMode); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", tmp, err)
	}
	return &Pending{final: final, id: id}, nil
}

// Path returns the <id>.tmp directory the caller writes into.
func (p *Pending) Path() string { return p.final + ".tmp" }

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
