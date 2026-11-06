package imports

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/MorganKryze/sealift/internal/importer"
)

// ErrBusy answers a retry of an import whose latest attempt is queued or running.
var ErrBusy = errors.New("imports: an attempt is queued or running")

// Retry adds a queued attempt numbered one past the latest. Earlier attempts
// stay as they are; the new one carries nothing over from them.
func (s *Store) Retry(user, id string) (Import, error) {
	var out Import
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		last := imp.Attempts[len(imp.Attempts)-1]
		if last.Status != StatusEnded {
			return "", ErrBusy
		}
		now := s.clock()
		imp.Attempts = append(imp.Attempts, Attempt{N: last.N + 1, Status: StatusQueued, QueuedAt: &now})
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
