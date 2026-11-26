package imports

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/MorganKryze/sealift/internal/importer"
)

// ErrBusy answers a retry of an import whose latest attempt is queued or running.
var ErrBusy = errors.New("imports: an attempt is queued or running")

// ErrRetryList answers a retry whose files are not failed packages of the
// latest attempt, or name one twice.
var ErrRetryList = errors.New("imports: the packages to retry must be failed packages of the latest attempt")

// Retry adds a queued attempt numbered one past the latest. Earlier attempts
// stay as they are. With no files the new attempt carries nothing over from
// them; with files it records them as the packages it uploads, each a failed
// package of the latest attempt, none twice.
func (s *Store) Retry(user, id string, files ...string) (Import, error) {
	var out Import
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		last := imp.Attempts[len(imp.Attempts)-1]
		if last.Status != StatusEnded {
			return "", ErrBusy
		}
		var retry []string
		if len(files) > 0 {
			if !failedFiles(last.Report.Packages, files) {
				return "", ErrRetryList
			}
			retry = slices.Clone(files)
		}
		now := s.clock()
		imp.Attempts = append(imp.Attempts, Attempt{N: last.N + 1, Status: StatusQueued, QueuedAt: &now, Retry: retry})
		out = normalize(*imp)
		return "", nil
	})
	if err != nil {
		return Import{}, err
	}
	return out, nil
}

// Abandon ends the latest attempt as interrupted with reason when it is still
// queued or running, and does nothing to one that has ended. The queue calls
// it for an attempt it can neither run nor finish.
func (s *Store) Abandon(user, id, reason string) error {
	return s.endUnfinished(user, id, OutcomeInterrupted, reason, OutcomeInterrupted)
}

// Break ends the latest attempt as incomplete with reason when it is still
// running, like Abandon, for a run that panicked. The package states the run
// stored stay; the ones still pending are marked failed.
func (s *Store) Break(user, id, reason string) error {
	return s.endUnfinished(user, id, importer.OutcomeIncomplete, reason, "not reached")
}

// endUnfinished ends a queued or running attempt with outcome and reason,
// keeps its stored packages and fails the pending ones with the reason
// pending, and removes its working directory. An attempt that has ended is left alone.
func (s *Store) endUnfinished(user, id, outcome, reason, pending string) error {
	work, err := s.update(user, id, func(imp *Import) (string, error) {
		a := &imp.Attempts[len(imp.Attempts)-1]
		if a.Status == StatusEnded {
			return "", nil
		}
		now := s.clock()
		a.Status, a.EndedAt, a.Outcome, a.Removal = StatusEnded, &now, outcome, nil
		a.Report.Outcome, a.Report.Reason = outcome, reason
		for i, p := range a.Report.Packages {
			if p.State == importer.Pending {
				a.Report.Packages[i].State, a.Report.Packages[i].Reason, a.Report.Packages[i].Kind = importer.Failed, pending, importer.KindInterrupted
			}
		}
		recount(&a.Report)
		return filepath.Join(s.dir(user, id), workPrefix+strconv.Itoa(a.N)), nil
	})
	if err != nil || work == "" {
		return err
	}
	if err := os.RemoveAll(work); err != nil {
		return fmt.Errorf("imports: %w", err)
	}
	return nil
}

// failedFiles reports whether each of files names a failed package of pkgs,
// none twice. A list longer than pkgs is refused before any is read.
func failedFiles(pkgs []importer.Result, files []string) bool {
	if len(files) > len(pkgs) {
		return false
	}
	failed := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if p.State == importer.Failed {
			failed[p.File] = true
		}
	}
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if !failed[f] || seen[f] {
			return false
		}
		seen[f] = true
	}
	return true
}
