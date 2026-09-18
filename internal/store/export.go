package store

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ExportInfo summarizes one export for the API: its identity, the analysis
// it came from, its state, and the files ready to download once it is
// done. Every ExportInfo this package reads back from disk reports state
// Done: only a complete export keeps its directory, a failed one removes
// its pending directory instead. internal/jobs reports a queued or running
// export by other means, since neither has a committed directory yet.
type ExportInfo struct {
	ID         string
	ProjectID  string
	AnalysisID string
	State      State
	CreatedAt  time.Time
	Files      []string
}

// exportManifest is the subset of manifest.json this package reads back.
// internal/report owns the full shape; reading only these two fields here
// avoids a store -> report -> store import cycle (report.Manifest embeds
// store.Target).
type exportManifest struct {
	AnalysisID string    `json:"analysisId"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Exports lists every committed export of a project, newest first.
func (s *Store) Exports(projectID string) ([]ExportInfo, error) {
	if err := validID(projectID); err != nil {
		return nil, err
	}
	parent := filepath.Join(s.root, "projects", projectID, "exports")
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: list %s: %w", parent, err)
	}

	infos := make([]ExportInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		info, err := readExportInfo(projectID, e.Name(), filepath.Join(parent, e.Name()))
		if err != nil {
			slog.Warn("store: skipping a damaged export entry", "project", projectID, "id", e.Name(), "error", err)
			continue
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID > infos[j].ID })
	return infos, nil
}

// ExportInfo reads one committed export by ID.
func (s *Store) ExportInfo(projectID, id string) (ExportInfo, error) {
	if err := validID(projectID); err != nil {
		return ExportInfo{}, err
	}
	if err := validID(id); err != nil {
		return ExportInfo{}, err
	}
	dir := filepath.Join(s.root, "projects", projectID, "exports", id)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return ExportInfo{}, ErrNotFound
		}
		return ExportInfo{}, fmt.Errorf("store: stat %s: %w", dir, err)
	}
	return readExportInfo(projectID, id, dir)
}

// DeleteExport removes a committed export directory.
func (s *Store) DeleteExport(projectID, id string) error {
	return s.deleteJobDir(projectID, "exports", id)
}

// ExportFile opens one file inside a committed export directory for
// reading, refusing a name that is not a plain file name: no path
// separator, no "..", nothing that could join outside the export
// directory.
func (s *Store) ExportFile(projectID, exportID, name string) (*os.File, error) {
	if err := validID(projectID); err != nil {
		return nil, err
	}
	if err := validID(exportID); err != nil {
		return nil, err
	}
	if err := validID(name); err != nil {
		return nil, err
	}
	path := filepath.Join(s.root, "projects", projectID, "exports", exportID, name)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	return f, nil
}

// readExportInfo reads manifest.json for the analysis ID and creation
// time, and lists every regular file in dir for Files. A missing or
// unreadable manifest.json still yields an ExportInfo: CreatedAt falls
// back to the ID's own timestamp, and AnalysisID stays empty.
func readExportInfo(projectID, id, dir string) (ExportInfo, error) {
	createdAt, err := time.Parse(analysisIDLayout, id)
	if err != nil {
		return ExportInfo{}, fmt.Errorf("store: %s is not a valid export id: %w", id, err)
	}

	info := ExportInfo{ID: id, ProjectID: projectID, State: Done, CreatedAt: createdAt}
	var manifest exportManifest
	if err := readJSONFile(filepath.Join(dir, "manifest.json"), &manifest); err == nil {
		info.AnalysisID = manifest.AnalysisID
		if !manifest.CreatedAt.IsZero() {
			info.CreatedAt = manifest.CreatedAt
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return info, fmt.Errorf("store: read manifest.json for %s: %w", id, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return info, fmt.Errorf("store: list %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			info.Files = append(info.Files, e.Name())
		}
	}
	sort.Strings(info.Files)
	return info, nil
}
