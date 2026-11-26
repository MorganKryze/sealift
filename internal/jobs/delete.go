package jobs

import (
	"sync"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// projectLock serializes queueing a project's jobs against deleting the
// project. holders counts the callers holding or waiting for it, so the
// entry goes once none is left.
type projectLock struct {
	mu      sync.Mutex
	holders int
}

// lockProject takes projectID's lock and returns the function that
// releases it.
func (s *Service) lockProject(projectID string) (unlock func()) {
	s.mu.Lock()
	l := s.projectLocks[projectID]
	if l == nil {
		l = &projectLock{}
		s.projectLocks[projectID] = l
	}
	l.holders++
	s.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.mu.Lock()
		l.holders--
		if l.holders == 0 {
			delete(s.projectLocks, projectID)
		}
		s.mu.Unlock()
	}
}

// DeleteProject removes a project and everything under it. It answers
// store.ErrBusy while one of the project's jobs is queued or running, and
// no job of the project can be queued while it runs: a job queued after it
// finds the project gone. A job directory with no job behind it, which a
// crash leaves, goes with the rest.
func (s *Service) DeleteProject(projectID string) error {
	unlock := s.lockProject(projectID)
	defer unlock()
	// A job stays tracked until its finalizer has committed its directory,
	// so nothing writes under the project once none is.
	if s.HasJob(projectID) {
		return store.ErrBusy
	}
	return s.store.DeleteProjectUnguarded(projectID)
}

// HasJob reports whether Service tracks a queued or running job of
// projectID. byProjectID holds only the latest one, which a cancel can
// untrack while an earlier job still runs, so this walks every job.
func (s *Service) HasJob(projectID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.byJobKey {
		if key.projectID == projectID {
			return true
		}
	}
	return false
}

// PurgeIfIdle empties the shared caches when no project has a job queued
// or running, and otherwise leaves the purge pending for the next sweep.
// It reports whether it emptied anything.
func (s *Service) PurgeIfIdle() (bool, error) {
	return s.purgeIfIdle(s.HasJob)
}

// purgeIfIdle is PurgeIfIdle with the live-job check as a parameter. Lock
// order: a project's lock, then queueing, then the store's purge lock,
// then s.mu. Queueing a job takes the first two in that order, the purge
// takes queueing then the store's lock, and HasJob takes s.mu last.
func (s *Service) purgeIfIdle(hasJob func(projectID string) bool) (bool, error) {
	s.queueing.Lock()
	defer s.queueing.Unlock()
	return s.store.PurgeIfIdle(hasJob)
}

// SweepEphemeral runs one ephemeral sweep: it deletes every project with
// no job that has been idle for idle at now, then purges the caches
// through PurgeIfIdle when the store asks for it. The deletes take each
// project's lock with queueing released, which keeps the lock order.
func (s *Service) SweepEphemeral(idle time.Duration, now time.Time) store.Sweep {
	return s.store.SweepEphemeral(idle, now, s.HasJob, s.DeleteProject, s.PurgeIfIdle)
}
