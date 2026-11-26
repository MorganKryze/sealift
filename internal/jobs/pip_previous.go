package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// previousCrossing finds the set a pip analysis of project compares with:
// the latest done export, created before before, of a pip project whose
// name matches project's once trimmed and without case, project itself
// included. It returns that export and the set its analysis recorded, or
// nothing when no such export exists. An error means one exists and does
// not read, or the store could not be listed; it names no package.
func previousCrossing(s *store.Store, project store.Project, before time.Time) (*PipPreviousCrossing, []runner.Resolved, error) {
	projects, err := s.Projects()
	if err != nil {
		return nil, nil, err
	}
	name := strings.TrimSpace(project.Name)
	var latest *PipPreviousCrossing
	for _, p := range projects {
		if p.Ecosystem != store.Pip || !strings.EqualFold(strings.TrimSpace(p.Name), name) {
			continue
		}
		exports, err := s.Exports(p.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("list the exports of %s: %w", p.ID, err)
		}
		for _, e := range exports {
			if e.State != store.Done || !e.CreatedAt.Before(before) {
				continue
			}
			if latest == nil || e.CreatedAt.After(latest.SealedAt) || e.CreatedAt.Equal(latest.SealedAt) && e.ID > latest.ExportID {
				latest = &PipPreviousCrossing{ProjectID: p.ID, ProjectName: p.Name, ExportID: e.ID, AnalysisID: e.AnalysisID, SealedAt: e.CreatedAt}
			}
		}
	}
	if latest == nil {
		return nil, nil, nil
	}
	set, err := sealedSet(s, latest)
	if err != nil {
		return nil, nil, fmt.Errorf("the previous crossing, export %s, could not be read: %w", latest.ExportID, err)
	}
	return latest, set, nil
}

// sealedSet reads the set the analysis of crossing c recorded. Each name
// and version is checked as the import checks a manifest's, since they
// reach this analysis's scan.
func sealedSet(s *store.Store, c *PipPreviousCrossing) ([]runner.Resolved, error) {
	info, err := s.AnalysisInfo(c.ProjectID, c.AnalysisID)
	if err != nil {
		return nil, err
	}
	if info.State != store.Done {
		return nil, fmt.Errorf("its analysis %s is %s", c.AnalysisID, info.State)
	}
	if len(info.PipResult) == 0 {
		return nil, fmt.Errorf("its analysis %s has no pip-result.json", c.AnalysisID)
	}
	var result PipResult
	if err := json.Unmarshal(info.PipResult, &result); err != nil {
		return nil, fmt.Errorf("read pip-result.json of %s: %w", c.AnalysisID, err)
	}
	set := make([]runner.Resolved, 0, len(result.Packages))
	for i, p := range result.Packages {
		if !pip.ValidName(p.Name) || !pip.IsExactVersion(p.Version) {
			return nil, fmt.Errorf("package %d of %s has no valid name and exact version", i+1, c.AnalysisID)
		}
		set = append(set, runner.Resolved{Name: pip.Normalize(p.Name), Version: p.Version})
	}
	return set, nil
}

// calendarSegment is the first release segment from which a version reads
// as a date, such as 2023.11.17, whose first segment moves every year.
const calendarSegment = 1000

// pipMajorJump reports whether going from one exact version to another
// changes the epoch or the first release segment, unless either segment
// is calendarSegment or more. Python makes no semver promise; the first
// segment is what PEP 440 users read as the major.
func pipMajorJump(from, to string) bool {
	fromEpoch, fromMajor, err := majorOf(from)
	if err != nil {
		return false
	}
	toEpoch, toMajor, err := majorOf(to)
	if err != nil {
		return false
	}
	if fromEpoch != toEpoch {
		return true
	}
	if fromMajor >= calendarSegment || toMajor >= calendarSegment {
		return false
	}
	return fromMajor != toMajor
}

// majorOf reads the epoch and the first release segment of a version.
func majorOf(v string) (epoch, major uint64, err error) {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	if e, rest, ok := strings.Cut(v, "!"); ok {
		if epoch, err = strconv.ParseUint(e, 10, 64); err != nil {
			return 0, 0, err
		}
		v = rest
	}
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end < 0 {
		end = len(v)
	}
	if end == 0 {
		return 0, 0, errors.New("no release segment")
	}
	major, err = strconv.ParseUint(v[:end], 10, 64)
	return epoch, major, err
}
