package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// runningJSON and interruptedJSON are the State constants as they appear in
// a status.json's "state" field, so the sweep can compare and rewrite them
// without importing the status schema internal/jobs owns.
var (
	runningJSON     = jsonString(Running)
	interruptedJSON = jsonString(Interrupted)
)

func jsonString(s State) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic("store: State failed to marshal: " + err.Error()) // a string type cannot fail here.
	}
	return string(b)
}

// MarkRunningInterrupted is the startup sweep: every analyses/<id> or
// exports/<id> status.json still in state running belongs to a job the
// previous process never finished, so it moves to state interrupted. It
// returns how many files it changed.
func (s *Store) MarkRunningInterrupted() (int, error) {
	pattern := filepath.Join(s.root, "projects", "*", "*", "*", "status.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("store: list status files: %w", err)
	}

	changed := 0
	for _, path := range matches {
		did, err := markIfRunning(path)
		if err != nil {
			// One damaged status.json must not stop the server from
			// starting, or from sweeping every other analysis and export
			// that is readable.
			slog.Warn("store: skipping a damaged status.json", "path", path, "error", err)
			continue
		}
		if did {
			changed++
		}
	}
	return changed, nil
}

// RemoveOrphanDirs settles every analyses/<id>.tmp or exports/<id>.tmp
// directory left under any project. A .tmp directory can only exist while
// its job is running: Analysis commits its own on every path, including
// failure and cancellation, before Run returns, and Export leaves one only
// for the queue's finalize hook to commit while the server is still up. A
// .tmp directory found at startup therefore belongs to a job the previous
// process never got to finish.
//
// An analysis .tmp whose status.json holds a state other than running was
// started and marked, so it is renamed to analyses/<id>, the commit the
// dead process never did, and shows as interrupted once
// MarkRunningInterrupted has run first. A .tmp still in state running is
// one MarkRunningInterrupted could not rewrite (a full disk, a directory it
// cannot write to): committing it would list a job that does not exist, so
// it is removed like an analysis .tmp with no status.json (queued, never
// started), an unreadable status.json, every export .tmp and a directory
// whose rename fails. It returns how many it removed; a renamed directory
// is kept, so it does not count.
func (s *Store) RemoveOrphanDirs() (int, error) {
	// Only these two folders hold job directories. A wider glob would also
	// match a requirements file a pip project stores under a name ending
	// in .tmp.
	var matches []string
	for _, folder := range []string{"analyses", "exports"} {
		found, err := filepath.Glob(filepath.Join(s.root, "projects", "*", folder, "*.tmp"))
		if err != nil {
			return 0, fmt.Errorf("store: list orphan directories: %w", err)
		}
		matches = append(matches, found...)
	}

	removed := 0
	for _, dir := range matches {
		if filepath.Base(filepath.Dir(dir)) == "analyses" && settledAnalysis(dir) {
			final := strings.TrimSuffix(dir, ".tmp")
			err := os.Rename(dir, final)
			if err == nil {
				continue
			}
			slog.Warn("store: could not keep an interrupted analysis, removing it", "path", dir, "error", err)
		}
		if err := os.RemoveAll(dir); err != nil {
			// One directory this process cannot remove (permissions, a
			// stray open file) must not stop the server from starting, or
			// from clearing every other orphan that is removable.
			slog.Warn("store: could not remove an orphan directory", "path", dir, "error", err)
			continue
		}
		removed++
	}
	return removed, nil
}

// settledAnalysis reports whether dir holds a readable status.json whose
// state is no longer running: an analysis that started and was marked, safe
// to commit under its final name.
func settledAnalysis(dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	state, ok := fields["state"]
	return ok && string(state) != runningJSON
}

// markIfRunning flips one status.json's "state" field to interrupted,
// leaving every other field untouched, and reports whether it did.
func markIfRunning(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("store: read %s: %w", path, err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false, fmt.Errorf("store: unmarshal %s: %w", path, err)
	}
	state, ok := fields["state"]
	if !ok || string(state) != runningJSON {
		return false, nil
	}

	fields["state"] = json.RawMessage(interruptedJSON)
	data, err := json.Marshal(fields)
	if err != nil {
		return false, fmt.Errorf("store: marshal %s: %w", path, err)
	}
	if err := atomicWriteFile(path, data, fileMode); err != nil {
		return false, err
	}
	return true, nil
}
