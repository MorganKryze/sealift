// Package imports keeps each import and the state of its packages on the data
// volume, one directory per import, so a restart finds what the last run did.
package imports

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MorganKryze/sealift/internal/importer"
)

// FormatVersion is the version every record carries.
const FormatVersion = 1

const (
	recordFile = "import.json"
	workPrefix = "work-"
	idAttempts = 5 // ids drawn before Create gives up on a collision
)

// The three states of an attempt.
const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusEnded   Status = "ended"
)

// OutcomeInterrupted is the outcome of an attempt a restart or a shutdown cut short.
const OutcomeInterrupted = "interrupted"

var (
	userPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,56}[a-z0-9])?$`)
	idPattern   = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
)

// ValidUser reports whether name can be a folder name: lower case letters,
// digits, dots and hyphens, 1 to 58 characters, with no "..".
func ValidUser(name string) bool {
	return userPattern.MatchString(name) && !strings.Contains(name, "..")
}

// ValidID reports whether id has the shape Create gives.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Status is where an attempt stands.
type Status string

// Object is a MinIO object as it was when the import was created.
type Object struct {
	Key  string `json:"key"`
	ETag string `json:"etag"`
	Size int64  `json:"size"`
}

// Removal records what became of the archive after a complete import.
type Removal struct {
	Removed bool   `json:"removed"`
	Reason  string `json:"reason"`
}

// Attempt is one try at an import. Each keeps its own report.
type Attempt struct {
	N         int             `json:"n"`
	Status    Status          `json:"status"`
	QueuedAt  *time.Time      `json:"queuedAt,omitempty"`
	StartedAt *time.Time      `json:"startedAt,omitempty"`
	EndedAt   *time.Time      `json:"endedAt,omitempty"`
	Outcome   string          `json:"outcome"`
	Report    importer.Report `json:"report"`
	Removal   *Removal        `json:"removal,omitempty"`
}

// Import is the record of one archive and its attempts.
type Import struct {
	FormatVersion  int       `json:"formatVersion"`
	ID             string    `json:"id"`
	User           string    `json:"user"`
	CreatedAt      time.Time `json:"createdAt"`
	Archive        Object    `json:"archive"`
	Manifest       Object    `json:"manifest"`
	ExpectedSHA256 string    `json:"expectedSha256"`
	Attempts       []Attempt `json:"attempts"`
}

// Outcome is the latest attempt's outcome, or "queued" or "running" while it
// has none.
func (i Import) Outcome() string {
	if len(i.Attempts) == 0 {
		return string(StatusQueued)
	}
	a := i.Attempts[len(i.Attempts)-1]
	if a.Status == StatusEnded {
		return a.Outcome
	}
	return string(a.Status)
}

// ArchiveRemoved reports whether an attempt removed the archive from MinIO.
func (i Import) ArchiveRemoved() bool {
	for _, a := range i.Attempts {
		if a.Removal != nil && a.Removal.Removed {
			return true
		}
	}
	return false
}

// ErrNotFound answers a bad id, a bad user, another user's id and a missing import.
var ErrNotFound = errors.New("imports: no such import")

// Store keeps imports below one root. One mutex serialises every read and write.
type Store struct {
	mu   sync.Mutex
	root string
	log  *slog.Logger
	now  func() time.Time
}

// Open creates root (mode 0700) when it is missing.
func Open(root string, log *slog.Logger) (*Store, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("imports: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("imports: %w", err)
	}
	return &Store{root: root, log: log, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Store) clock() time.Time { return s.now().UTC().Truncate(time.Second) }

func (s *Store) dir(user, id string) string { return filepath.Join(s.root, user, id) }

// Create records a new import with its first attempt queued.
func (s *Store) Create(user string, archive, manifest Object, expectedSHA256 string) (Import, error) {
	if !ValidUser(user) {
		return Import{}, errors.New("imports: invalid user")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mkdirPrivate(filepath.Join(s.root, user)); err != nil {
		return Import{}, err
	}
	now := s.clock()
	for range idAttempts {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Import{}, fmt.Errorf("imports: %w", err)
		}
		id := now.Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
		if err := os.Mkdir(s.dir(user, id), 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return Import{}, fmt.Errorf("imports: %w", err)
		}
		imp := Import{
			FormatVersion: FormatVersion, ID: id, User: user, CreatedAt: now,
			Archive: archive, Manifest: manifest, ExpectedSHA256: expectedSHA256,
			Attempts: []Attempt{{N: 1, Status: StatusQueued, QueuedAt: &now}},
		}
		if err := s.write(imp); err != nil {
			_ = os.RemoveAll(s.dir(user, id))
			return Import{}, err
		}
		return normalize(imp), nil
	}
	return Import{}, errors.New("imports: could not draw a free id")
}

// Get reads one import. Another user's id answers ErrNotFound like a missing one.
func (s *Store) Get(user, id string) (Import, error) {
	if !ValidUser(user) || !ValidID(id) {
		return Import{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(user, id)
}

// List returns the user's imports, newest first. A damaged record is logged
// and left out.
func (s *Store) List(user string) ([]Import, error) {
	if !ValidUser(user) {
		return []Import{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list(user)
}

func (s *Store) list(user string) ([]Import, error) {
	out := []Import{}
	entries, err := os.ReadDir(filepath.Join(s.root, user))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("imports: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		imp, err := s.read(user, e.Name())
		if err != nil {
			s.log.Warn("skipping a damaged import", "user", user, "id", e.Name(), "err", err)
			continue
		}
		out = append(out, imp)
	}
	slices.SortFunc(out, func(a, b Import) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	return out, nil
}

// Begin marks the latest attempt running and makes its working directory. It
// returns the attempt's number, which the later calls must name.
func (s *Store) Begin(user, id string) (dir string, n int, err error) {
	dir, err = s.update(user, id, func(imp *Import) (string, error) {
		a := &imp.Attempts[len(imp.Attempts)-1]
		if a.Status != StatusQueued {
			return "", fmt.Errorf("imports: attempt %d is %s, not queued", a.N, a.Status)
		}
		n = a.N
		now := s.clock()
		a.Status, a.StartedAt = StatusRunning, &now
		work := filepath.Join(s.dir(user, id), workPrefix+strconv.Itoa(a.N))
		if err := os.RemoveAll(work); err != nil {
			return "", fmt.Errorf("imports: %w", err)
		}
		if err := os.Mkdir(work, 0o700); err != nil {
			return "", fmt.Errorf("imports: %w", err)
		}
		return work, nil
	})
	return dir, n, err
}

// Listed stores the report of running attempt n as the run gave it when it
// read the manifest: the target, the archive and Nexus, with every package
// pending. The counts are recomputed from the packages.
func (s *Store) Listed(user, id string, n int, rep importer.Report) error {
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		a, err := running(imp, n)
		if err != nil {
			return "", err
		}
		rep.Packages = append([]importer.Result{}, rep.Packages...)
		a.Report = rep
		recount(&a.Report)
		return "", nil
	})
	return err
}

// Checked records that the archive of running attempt n passed its checks.
func (s *Store) Checked(user, id string, n int) error {
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		a, err := running(imp, n)
		if err != nil {
			return "", err
		}
		checked := true
		a.Report.ArchiveChecked = &checked
		return "", nil
	})
	return err
}

// Ended stores the result of package i of running attempt n.
func (s *Store) Ended(user, id string, n, i int, r importer.Result) error {
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		a, err := running(imp, n)
		if err != nil {
			return "", err
		}
		if i < 0 || i >= len(a.Report.Packages) {
			return "", fmt.Errorf("imports: package %d is not in the list of %d", i, len(a.Report.Packages))
		}
		a.Report.Packages[i] = r
		recount(&a.Report)
		return "", nil
	})
	return err
}

// Finish ends attempt n, which must be the latest, with its report and removes
// its working directory. The queue owns the end; the run only reports package states.
func (s *Store) Finish(user, id string, n int, rep importer.Report, rem *Removal) error {
	work, err := s.update(user, id, func(imp *Import) (string, error) {
		a := &imp.Attempts[len(imp.Attempts)-1]
		if a.N != n {
			return "", fmt.Errorf("imports: attempt %d is not the latest, %d is", n, a.N)
		}
		if a.Status == StatusEnded {
			return "", fmt.Errorf("imports: attempt %d already ended", a.N)
		}
		now := s.clock()
		a.Status, a.EndedAt, a.Outcome, a.Report, a.Removal = StatusEnded, &now, rep.Outcome, rep, rem
		return filepath.Join(s.dir(user, id), workPrefix+strconv.Itoa(a.N)), nil
	})
	if err != nil {
		return err
	}
	// The record says ended before the files go, so a crash here leaves a
	// directory the sweep removes and never a running attempt without files.
	if err := os.RemoveAll(work); err != nil {
		return fmt.Errorf("imports: %w", err)
	}
	return nil
}

// Removed stores what became of the archive after attempt n ended complete.
// The removal comes after the end so that a crash between the two leaves a
// complete attempt. It is stored once, and for attempt n even when a retry
// has since queued a later one.
func (s *Store) Removed(user, id string, n int, rem Removal) error {
	_, err := s.update(user, id, func(imp *Import) (string, error) {
		i := slices.IndexFunc(imp.Attempts, func(a Attempt) bool { return a.N == n })
		if i < 0 {
			return "", fmt.Errorf("imports: no attempt %d", n)
		}
		a := &imp.Attempts[i]
		switch {
		case a.Status != StatusEnded || a.Outcome != importer.OutcomeComplete:
			return "", fmt.Errorf("imports: attempt %d did not end complete", a.N)
		case a.Removal != nil:
			return "", fmt.Errorf("imports: attempt %d already has a removal", a.N)
		}
		a.Removal = &rem
		return "", nil
	})
	return err
}

func running(imp *Import, n int) (*Attempt, error) {
	a := &imp.Attempts[len(imp.Attempts)-1]
	if a.N != n {
		return nil, fmt.Errorf("imports: attempt %d is not the latest, %d is", n, a.N)
	}
	if a.Status != StatusRunning {
		return nil, fmt.Errorf("imports: attempt %d is %s, not running", a.N, a.Status)
	}
	return a, nil
}

// update reads the record, applies change and writes the result. Nothing is
// written when change fails.
func (s *Store) update(user, id string, change func(*Import) (string, error)) (string, error) {
	if !ValidUser(user) || !ValidID(id) {
		return "", ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	imp, err := s.read(user, id)
	if err != nil {
		return "", err
	}
	if len(imp.Attempts) == 0 {
		return "", errors.New("imports: the record has no attempt")
	}
	out, err := change(&imp)
	if err != nil {
		return "", err
	}
	if err := s.write(imp); err != nil {
		return "", err
	}
	return out, nil
}

// recount totals the packages by state; a pending one counts nowhere.
func recount(r *importer.Report) {
	r.Counts = importer.Counts{}
	for _, p := range r.Packages {
		switch p.State {
		case importer.Published:
			r.Counts.Published++
		case importer.Present:
			r.Counts.Present++
		case importer.Failed:
			r.Counts.Failed++
		}
	}
}

// normalize gives every slice a value, so none is written as null.
func normalize(imp Import) Import {
	if imp.Attempts == nil {
		imp.Attempts = []Attempt{}
	}
	for i := range imp.Attempts {
		if imp.Attempts[i].Report.Packages == nil {
			imp.Attempts[i].Report.Packages = []importer.Result{}
		}
	}
	return imp
}

func (s *Store) read(user, id string) (Import, error) {
	b, err := os.ReadFile(filepath.Join(s.dir(user, id), recordFile))
	if errors.Is(err, os.ErrNotExist) {
		return Import{}, ErrNotFound
	}
	if err != nil {
		return Import{}, fmt.Errorf("imports: %w", err)
	}
	var imp Import
	if err := json.Unmarshal(b, &imp); err != nil {
		return Import{}, fmt.Errorf("imports: damaged record: %w", err)
	}
	switch {
	case imp.FormatVersion != FormatVersion:
		return Import{}, fmt.Errorf("imports: format version %d is not %d", imp.FormatVersion, FormatVersion)
	case imp.ID != id:
		return Import{}, fmt.Errorf("imports: the record names import %q", imp.ID)
	case imp.User != user:
		// A record in one user's folder that names another never serves.
		return Import{}, ErrNotFound
	}
	return normalize(imp), nil
}

// write replaces the record through a temporary file and a rename.
func (s *Store) write(imp Import) error {
	b, err := json.MarshalIndent(normalize(imp), "", "  ")
	if err != nil {
		return fmt.Errorf("imports: %w", err)
	}
	dir := s.dir(imp.User, imp.ID)
	tmp := filepath.Join(dir, recordFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("imports: %w", err)
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, recordFile))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("imports: %w", err)
	}
	return nil
}

func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("imports: %w", err)
	}
	return nil
}
