package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// analysisIDLayout is the time.Parse layout analysis and export IDs use:
// a UTC timestamp with second precision.
const analysisIDLayout = "20060102T150405Z"

// AnalysisInfo summarizes one committed analysis for the API: its identity,
// its state, and the result an API response embeds once ranking.json
// exists. Result is nil before the job ranks anything.
type AnalysisInfo struct {
	ID        string
	ProjectID string
	State     State
	CreatedAt time.Time
	Result    json.RawMessage
}

// analysisStatus is the subset of status.json this package reads back.
// internal/jobs writes the full shape; only the state matters here.
type analysisStatus struct {
	State State `json:"state"`
}

// Analyses lists every committed analysis of a project, newest first. A
// directory that fails to parse, such as one with a corrupt status.json,
// is logged and skipped rather than failing the whole list, the same
// tolerance MarkRunningInterrupted and Projects give a damaged entry.
func (s *Store) Analyses(projectID string) ([]AnalysisInfo, error) {
	return s.jobInfos(projectID, "analyses")
}

// AnalysisInfo reads one committed analysis by ID.
func (s *Store) AnalysisInfo(projectID, id string) (AnalysisInfo, error) {
	if err := validID(projectID); err != nil {
		return AnalysisInfo{}, err
	}
	if err := validID(id); err != nil {
		return AnalysisInfo{}, err
	}
	dir := filepath.Join(s.root, "projects", projectID, "analyses", id)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return AnalysisInfo{}, ErrNotFound
		}
		return AnalysisInfo{}, fmt.Errorf("store: stat %s: %w", dir, err)
	}
	return readAnalysisInfo(projectID, id, dir)
}

// DeleteAnalysis removes a committed analysis directory.
func (s *Store) DeleteAnalysis(projectID, id string) error {
	return s.deleteJobDir(projectID, "analyses", id)
}

// jobInfos lists every committed directory under projects/<projectID>/<kind>,
// newest first (IDs are UTC timestamps, so a descending string sort orders
// them correctly).
func (s *Store) jobInfos(projectID, kind string) ([]AnalysisInfo, error) {
	if err := validID(projectID); err != nil {
		return nil, err
	}
	parent := filepath.Join(s.root, "projects", projectID, kind)
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: list %s: %w", parent, err)
	}

	infos := make([]AnalysisInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		info, err := readAnalysisInfo(projectID, e.Name(), filepath.Join(parent, e.Name()))
		if err != nil {
			slog.Warn("store: skipping a damaged entry", "kind", kind, "project", projectID, "id", e.Name(), "error", err)
			continue
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID > infos[j].ID })
	return infos, nil
}

// readAnalysisInfo reads status.json and ranking.json under dir. A missing
// or unreadable status.json is not fatal: the analysis ID still carries a
// creation time, and the caller can show state Interrupted for a directory
// this process cannot otherwise explain.
func readAnalysisInfo(projectID, id, dir string) (AnalysisInfo, error) {
	createdAt, err := time.Parse(analysisIDLayout, id)
	if err != nil {
		return AnalysisInfo{}, fmt.Errorf("store: %s is not a valid analysis id: %w", id, err)
	}

	info := AnalysisInfo{ID: id, ProjectID: projectID, CreatedAt: createdAt, State: Interrupted}
	var status analysisStatus
	if err := readJSONFile(filepath.Join(dir, "status.json"), &status); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return info, fmt.Errorf("store: read status.json for %s: %w", id, err)
		}
	} else {
		info.State = status.State
	}

	if raw, err := os.ReadFile(filepath.Join(dir, "ranking.json")); err == nil {
		info.Result = json.RawMessage(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return info, fmt.Errorf("store: read ranking.json for %s: %w", id, err)
	}
	return info, nil
}

// deleteJobDir removes a committed analysis or export directory, shared by
// DeleteAnalysis and DeleteExport.
func (s *Store) deleteJobDir(projectID, kind, id string) error {
	if err := validID(projectID); err != nil {
		return err
	}
	if err := validID(id); err != nil {
		return err
	}
	dir := filepath.Join(s.root, "projects", projectID, kind, id)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("store: stat %s: %w", dir, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("store: delete %s: %w", dir, err)
	}
	return nil
}
