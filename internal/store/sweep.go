package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// RemoveOrphanDirs removes every analyses/<id>.tmp or exports/<id>.tmp
// directory left under any project. A .tmp directory can only exist while
// its job is running: Analysis commits its own on every path, including
// failure and cancellation, before Run returns, and Export leaves one only
// for the queue's finalize hook to commit while the server is still up. A
// .tmp directory found at startup therefore belongs to a job the previous
// process never got to finish. It returns how many it removed.
func (s *Store) RemoveOrphanDirs() (int, error) {
	pattern := filepath.Join(s.root, "projects", "*", "*", "*.tmp")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("store: list orphan directories: %w", err)
	}

	removed := 0
	for _, dir := range matches {
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
