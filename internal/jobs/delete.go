package jobs

import (
	"sync"

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
