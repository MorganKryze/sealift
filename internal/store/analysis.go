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

// JobCreatedAt reads the creation time out of an analysis or export ID: the
// timestamp alone, or the timestamp, "-" and six lowercase hex digits, the
// suffix NewDir adds to tell apart two jobs of one project started in the
// same second. Any other shape is refused.
func JobCreatedAt(id string) (time.Time, error) {
	stamp := len(analysisIDLayout)
	if len(id) == stamp+7 && id[stamp] == '-' && strings.Trim(id[stamp+1:], "0123456789abcdef") == "" {
		id = id[:stamp]
	}
	return time.Parse(analysisIDLayout, id)
}

// AnalysisInfo summarizes one committed analysis for the API: its identity,
// its state, and the result an API response embeds once ranking.json, or
// pip-result.json for a pip analysis, exists. Result is nil before an npm
// job ranks anything, and PipResult before a pip job scans its set.
type AnalysisInfo struct {
	ID           string
	ProjectID    string
	State        State
	CreatedAt    time.Time
	Result       json.RawMessage
	PipResult    json.RawMessage
	TrivyVersion string
	TrivyDBDate  time.Time
	PnpmVersion  string
	UvVersion    string
	Failure      *StepFailure // the first step status.json recorded as failed, nil otherwise
}

// StepFailure names the step an analysis or export failed on and why,
// read back from the failed step's own status.json entry: the log.txt a
// reader would otherwise have to open to find that reason.
type StepFailure struct {
	Step    string
	Message string
}

// analysisStatus is the subset of status.json this package reads back.
// internal/jobs writes the full shape; a field left at its zero value here
// means the job never recorded it (an analysis that failed or was
// interrupted before preparing its tools).
type analysisStatus struct {
	State        State             `json:"state"`
	TrivyVersion string            `json:"trivyVersion"`
	TrivyDBDate  time.Time         `json:"trivyDbDate"`
	PnpmVersion  string            `json:"pnpmVersion"`
	UvVersion    string            `json:"uvVersion"`
	Steps        []analysisStepRow `json:"steps"`
}

// analysisStepRow is the subset of internal/jobs' stepRecord this package
// reads back: enough to name the step status.json recorded as failed, and
// why.
type analysisStepRow struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Error string `json:"error"`
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

// AnalysisLog opens a committed analysis' log.txt for reading, the running
// account of every step a reader would otherwise have to reconstruct from
// status.json alone. A log.txt that is not a regular file is not found.
func (s *Store) AnalysisLog(projectID, id string) (*os.File, error) {
	if err := validID(projectID); err != nil {
		return nil, err
	}
	if err := validID(id); err != nil {
		return nil, err
	}
	return s.openProjectFile(filepath.Join(projectID, "analyses", id, "log.txt"))
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

// readAnalysisInfo reads status.json, ranking.json and pip-result.json
// under dir. A missing
// or unreadable status.json is not fatal: the analysis ID still carries a
// creation time, and the caller can show state Interrupted for a directory
// this process cannot otherwise explain.
func readAnalysisInfo(projectID, id, dir string) (AnalysisInfo, error) {
	createdAt, err := JobCreatedAt(id)
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
		info.TrivyVersion = status.TrivyVersion
		info.TrivyDBDate = status.TrivyDBDate
		info.PnpmVersion = status.PnpmVersion
		info.UvVersion = status.UvVersion
		for _, step := range status.Steps {
			if step.State == string(Failed) {
				info.Failure = &StepFailure{Step: step.Name, Message: step.Error}
				break
			}
		}
	}

	if info.Result, err = readOptional(dir, "ranking.json"); err != nil {
		return info, fmt.Errorf("store: read ranking.json for %s: %w", id, err)
	}
	if info.PipResult, err = readOptional(dir, "pip-result.json"); err != nil {
		return info, fmt.Errorf("store: read pip-result.json for %s: %w", id, err)
	}
	return info, nil
}

// readOptional reads dir/name, or returns nil when the file is absent.
func readOptional(dir, name string) (json.RawMessage, error) {
	raw, err := ReadRegularFile(filepath.Join(dir, name), storedFileLimit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
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

// ProjectManifest opens the package.json a project was created from, as
// uploaded. ErrNotFound when the project does not exist, or when its
// package.json is not a regular file.
func (s *Store) ProjectManifest(projectID string) (*os.File, error) {
	if err := validID(projectID); err != nil {
		return nil, err
	}
	return s.openProjectFile(filepath.Join(projectID, "package.json"))
}
