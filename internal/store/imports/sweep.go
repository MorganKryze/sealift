package imports

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MorganKryze/sealift/internal/importer"
)

// Sweep runs at startup, before anything is queued. It ends every queued or
// running attempt as interrupted, fails the packages still pending, and
// removes working directories. It starts nothing. It returns the number of
// attempts it marked; a damaged import is logged and left as it is.
func (s *Store) Sweep() (marked int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := os.ReadDir(s.root)
	if err != nil {
		return 0, fmt.Errorf("imports: %w", err)
	}
	for _, u := range users {
		if !u.IsDir() || !ValidUser(u.Name()) {
			continue
		}
		ids, err := os.ReadDir(filepath.Join(s.root, u.Name()))
		if err != nil {
			s.log.Warn("skipping an unreadable user folder", "user", u.Name(), "err", err)
			continue
		}
		for _, d := range ids {
			if !d.IsDir() || !ValidID(d.Name()) {
				continue
			}
			n, err := s.sweepOne(u.Name(), d.Name())
			if err != nil {
				s.log.Warn("skipping an import in the sweep", "user", u.Name(), "id", d.Name(), "err", err)
				continue
			}
			marked += n
		}
	}
	return marked, nil
}

func (s *Store) sweepOne(user, id string) (int, error) {
	imp, err := s.read(user, id)
	if err != nil {
		return 0, err
	}
	marked, changed := 0, false
	now := s.clock()
	for i := range imp.Attempts {
		a := &imp.Attempts[i]
		if a.Status != StatusEnded {
			a.Status, a.EndedAt, a.Outcome = StatusEnded, &now, OutcomeInterrupted
			if a.Report.Outcome == "" {
				a.Report.Outcome, a.Report.Reason = importer.OutcomeIncomplete, OutcomeInterrupted
			}
			marked++
			changed = true
		}
		for j, p := range a.Report.Packages {
			if p.State == importer.Pending {
				a.Report.Packages[j].State, a.Report.Packages[j].Reason = importer.Failed, OutcomeInterrupted
				changed = true
			}
		}
		recount(&a.Report)
	}
	// The record is written first: if the files outlive a crash, the next
	// sweep removes them.
	if changed {
		if err := s.write(imp); err != nil {
			return 0, err
		}
	}
	entries, err := os.ReadDir(s.dir(user, id))
	if err != nil {
		return marked, err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), workPrefix) || e.Name() == recordFile+".tmp" {
			if err := os.RemoveAll(filepath.Join(s.dir(user, id), e.Name())); err != nil {
				return marked, err
			}
		}
	}
	return marked, nil
}
