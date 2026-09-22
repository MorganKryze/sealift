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
// done. A committed export directory can hold any terminal state: a
// successful one reports Done from manifest.json alone, while a failed or
// cancelled one keeps its directory too, with a status.json Export.Run
// wrote on its way out (see internal/jobs).
type ExportInfo struct {
	ID         string
	ProjectID  string
	AnalysisID string
	State      State
	CreatedAt  time.Time
	Files      []string
	// Failure names the first step status.json recorded as failed, and
	// why, for a failed export. Nil for a done or cancelled one.
	Failure *StepFailure
}

// exportManifest is the subset of manifest.json this package reads back.
// internal/report owns the full shape; reading only these two fields here
// avoids a store -> report -> store import cycle (report.Manifest embeds
// store.Target).
type exportManifest struct {
	AnalysisID string    `json:"analysisId"`
	CreatedAt  time.Time `json:"createdAt"`
}

// exportStatus is the subset of a failed or cancelled export's status.json
// this package reads back. internal/jobs writes the full shape.
type exportStatus struct {
	State      State             `json:"state"`
	AnalysisID string            `json:"analysisId"`
	Steps      []analysisStepRow `json:"steps"`
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
//
// status.json, present only for a failed or cancelled export, overrides
// State and AnalysisID and fills Failure, using the same first-failed-step
// rule readAnalysisInfo uses. It is excluded from Files: it is bookkeeping
// for this package, not one of the export's own deliverables.
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

	var status exportStatus
	if err := readJSONFile(filepath.Join(dir, "status.json"), &status); err == nil {
		info.State = status.State
		if status.AnalysisID != "" {
			info.AnalysisID = status.AnalysisID
		}
		for _, step := range status.Steps {
			if step.State == string(Failed) {
				info.Failure = &StepFailure{Step: step.Name, Message: step.Error}
				break
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return info, fmt.Errorf("store: read status.json for %s: %w", id, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return info, fmt.Errorf("store: list %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() && e.Name() != "status.json" {
			info.Files = append(info.Files, e.Name())
		}
	}
	sort.Strings(info.Files)
	return info, nil
}
