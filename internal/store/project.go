package store

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ErrNotFound is returned when a project ID has no matching directory.
var ErrNotFound = errors.New("not found")

// Project is one project directory: an uploaded package.json, its target
// platform, and the analyses and exports run against it.
type Project struct {
	ID     string
	Name   string
	Target Target
	Dir    string
}

// projectRecord is the on-disk shape of project.json. Name and Target come
// straight from Project; CreatedAt has no exported counterpart yet, since
// nothing in this plan reads it back.
type projectRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Target    Target    `json:"target"`
	CreatedAt time.Time `json:"createdAt"`
}

// nonSlugRun matches any character, run, that a project id cannot contain.
var nonSlugRun = regexp.MustCompile(`[^a-z0-9]+`)

// slug reduces name to lowercase [a-z0-9-], folding "@" and "/" to "-" so a
// scoped package name such as "@scope/name" becomes "scope-name". It returns
// "" when name has no character a slug can keep.
func slug(name string) string {
	s := strings.ToLower(name)
	s = strings.NewReplacer("@", "-", "/", "-").Replace(s)
	s = nonSlugRun.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// randomHexFunc generates a project ID suffix. Tests override it to force a
// collision deterministically; production code never reassigns it.
var randomHexFunc = randomHex

// CreateProject slugs name into a project ID, appends a random 6 hex
// character suffix to keep it unique, and writes package.json and
// project.json under projects/<id>/. It rejects a name that slugs to
// nothing.
func (s *Store) CreateProject(name string, manifest []byte) (Project, error) {
	base := slug(name)
	if base == "" {
		return Project{}, fmt.Errorf("store: %q has no usable characters for a project id", name)
	}

	id, dir, err := s.reserveProjectDir(base)
	if err != nil {
		return Project{}, err
	}

	target := s.Settings().Target
	record := projectRecord{ID: id, Name: name, Target: target, CreatedAt: time.Now().UTC()}
	if err := writeJSONFile(filepath.Join(dir, "project.json"), record, fileMode); err != nil {
		_ = os.RemoveAll(dir) // the reserved directory holds no usable project; leaving it behind would block a later CreateProject or a real project's rename
		return Project{}, err
	}
	if err := atomicWriteFile(filepath.Join(dir, "package.json"), manifest, fileMode); err != nil {
		_ = os.RemoveAll(dir)
		return Project{}, err
	}
	return Project{ID: id, Name: name, Target: target, Dir: dir}, nil
}

// reserveProjectDir creates projects/<base>-<suffix> under an id no other
// project holds, retrying with a fresh suffix on a collision.
func (s *Store) reserveProjectDir(base string) (id, dir string, err error) {
	for attempt := 0; attempt < 10; attempt++ {
		suffix, err := randomHexFunc(3)
		if err != nil {
			return "", "", fmt.Errorf("store: generate project id: %w", err)
		}
		candidate := base + "-" + suffix
		candidateDir := filepath.Join(s.root, "projects", candidate)
		if err := os.Mkdir(candidateDir, dirMode); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", "", fmt.Errorf("store: create %s: %w", candidateDir, err)
		}
		return candidate, candidateDir, nil
	}
	return "", "", fmt.Errorf("store: could not allocate an id for %q", base)
}

// Projects lists every project, sorted by name.
func (s *Store) Projects() ([]Project, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "projects"))
	if err != nil {
		return nil, fmt.Errorf("store: list projects: %w", err)
	}

	projects := make([]Project, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		p, err := s.Project(e.Name())
		if err != nil {
			// A directory without a readable project.json belongs to no
			// project a caller can act on; skip it instead of failing the
			// whole listing over one damaged entry.
			slog.Warn("store: skipping a damaged project directory", "id", e.Name(), "error", err)
			continue
		}
		projects = append(projects, p)
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Name < projects[j].Name })
	return projects, nil
}

// Project reads one project by ID.
func (s *Store) Project(id string) (Project, error) {
	if err := validID(id); err != nil {
		return Project{}, err
	}
	dir := filepath.Join(s.root, "projects", id)
	var record projectRecord
	if err := readJSONFile(filepath.Join(dir, "project.json"), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Project{}, ErrNotFound
		}
		return Project{}, err
	}
	return Project{ID: record.ID, Name: record.Name, Target: record.Target, Dir: dir}, nil
}

// SetProjectTarget changes a project's target platform, refusing an empty
// field the same way SaveSettings does.
func (s *Store) SetProjectTarget(id string, t Target) error {
	if err := validID(id); err != nil {
		return err
	}
	if err := validateTarget(t); err != nil {
		return err
	}
	dir := filepath.Join(s.root, "projects", id)
	path := filepath.Join(dir, "project.json")

	var record projectRecord
	if err := readJSONFile(path, &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	record.Target = t
	return writeJSONFile(path, record, fileMode)
}

// DeleteProject removes a project directory and everything under it.
func (s *Store) DeleteProject(id string) error {
	if err := validID(id); err != nil {
		return err
	}
	dir := filepath.Join(s.root, "projects", id)
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
