package store

import (
	"crypto/sha256"
	"encoding/hex"
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

// ErrBusy means a queued or running job still writes under the project.
var ErrBusy = errors.New("a job is still writing to this project")

// Project is one project directory: an uploaded package.json or a set of
// requirements files, its target platform, and the analyses and exports run
// against it. Target is the npm target and PipTarget the pip one; the other
// stays zero.
type Project struct {
	ID             string
	Name           string
	Ecosystem      Ecosystem
	Target         Target
	PipTarget      PipTarget
	Dir            string
	ManifestSha256 string // sha256 of the uploaded package.json bytes, lowercase hex
	CreatedAt      time.Time
}

// projectRecord is the on-disk shape of project.json. An npm record keeps
// the keys 0.6.2 wrote and no other: the ecosystem is empty for npm, so a
// record from before pip reads as npm and an older release reads a new npm
// record unchanged.
type projectRecord struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Target         Target    `json:"target,omitzero"`
	CreatedAt      time.Time `json:"createdAt"`
	ManifestSha256 string    `json:"manifestSha256,omitempty"`
	Ecosystem      Ecosystem `json:"ecosystem,omitempty"`
	PipTarget      PipTarget `json:"pipTarget,omitzero"`
	Requirements   []string  `json:"requirements,omitempty"` // file names in upload order
}

// manifestSHA256 hashes the bytes at path as uploaded, not the parsed
// manifest, so the browser (crypto.subtle.digest over the exact file
// bytes) and the server agree on the same hash.
func manifestSHA256(path string) (string, error) {
	data, err := ReadRegularFile(path, storedFileLimit)
	if err != nil {
		return "", fmt.Errorf("store: read %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
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
	if s.isEphemeral() {
		base = "project"
	}
	if base == "" {
		return Project{}, fmt.Errorf("store: %q has no usable characters for a project id", name)
	}

	id, dir, err := s.reserveProjectDir(base)
	if err != nil {
		return Project{}, err
	}

	target := s.Settings().Target
	sum := sha256.Sum256(manifest)
	hash := hex.EncodeToString(sum[:])
	createdAt := time.Now().UTC()
	record := projectRecord{ID: id, Name: name, Target: target, CreatedAt: createdAt, ManifestSha256: hash}
	if err := writeJSONFile(filepath.Join(dir, "project.json"), record, fileMode); err != nil {
		_ = os.RemoveAll(dir) // the reserved directory holds no usable project; leaving it behind would block a later CreateProject or a real project's rename
		return Project{}, err
	}
	if err := atomicWriteFile(filepath.Join(dir, "package.json"), manifest, fileMode); err != nil {
		_ = os.RemoveAll(dir)
		return Project{}, err
	}
	return Project{ID: id, Name: name, Ecosystem: NPM, Target: target, Dir: dir, ManifestSha256: hash, CreatedAt: createdAt}, nil
}

// RequirementsFile is one uploaded requirements file.
type RequirementsFile struct {
	Name string
	Data []byte
}

// requirementsNameRE bounds a requirements file name before it joins a path.
var requirementsNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ErrInvalidRequirements means the files given for a pip project cannot be stored.
var ErrInvalidRequirements = errors.New("invalid requirements files")

// ValidRequirementsName refuses a requirements file name the store cannot
// keep. The refusal never quotes the name, which may be of any length.
func ValidRequirementsName(name string) error {
	if !requirementsNameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%w: a file name is 1 to 128 characters, letters, digits, dots, dashes and underscores, starting with a letter or digit, with no two dots in a row", ErrInvalidRequirements)
	}
	return nil
}

func validRequirementsNames(files []RequirementsFile) error {
	if len(files) == 0 {
		return fmt.Errorf("%w: a pip project needs at least one file", ErrInvalidRequirements)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if err := ValidRequirementsName(f.Name); err != nil {
			return err
		}
		lower := strings.ToLower(f.Name)
		if seen[lower] {
			return fmt.Errorf("%w: file name %q repeats another ignoring case", ErrInvalidRequirements, f.Name)
		}
		seen[lower] = true
	}
	return nil
}

// CreatePipProject writes a pip project under projects/<id>/: the files under
// requirements/ and a project.json with the pip target. It checks the target
// and every file name before it writes anything.
func (s *Store) CreatePipProject(name string, files []RequirementsFile, target PipTarget) (Project, error) {
	if err := ValidatePipTarget(target); err != nil {
		return Project{}, err
	}
	if err := validRequirementsNames(files); err != nil {
		return Project{}, err
	}
	base := slug(name)
	if s.isEphemeral() {
		base = "project"
	}
	if base == "" {
		return Project{}, fmt.Errorf("store: %q has no usable characters for a project id", name)
	}
	id, dir, err := s.reserveProjectDir(base)
	if err != nil {
		return Project{}, err
	}

	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.Name
		if err := atomicWriteFile(filepath.Join(dir, "requirements", f.Name), f.Data, fileMode); err != nil {
			_ = os.RemoveAll(dir)
			return Project{}, err
		}
	}
	createdAt := time.Now().UTC()
	record := projectRecord{ID: id, Name: name, CreatedAt: createdAt, Ecosystem: Pip, PipTarget: target, Requirements: names}
	if err := writeJSONFile(filepath.Join(dir, "project.json"), record, fileMode); err != nil {
		_ = os.RemoveAll(dir)
		return Project{}, err
	}
	return Project{ID: id, Name: name, Ecosystem: Pip, PipTarget: target, Dir: dir, CreatedAt: createdAt}, nil
}

// ProjectRequirements reads a pip project's requirements files in upload
// order. It returns ErrNotFound for an npm project.
func (s *Store) ProjectRequirements(id string) ([]RequirementsFile, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.root, "projects", id)
	var record projectRecord
	if err := readJSONFile(filepath.Join(dir, "project.json"), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if record.Ecosystem != Pip {
		return nil, ErrNotFound
	}
	files := make([]RequirementsFile, len(record.Requirements))
	for i, name := range record.Requirements {
		// A damaged record must not walk out of requirements/.
		if err := validRequirementsNames([]RequirementsFile{{Name: name}}); err != nil {
			return nil, err
		}
		data, err := ReadRegularFile(filepath.Join(dir, "requirements", name), storedFileLimit)
		if err != nil {
			return nil, fmt.Errorf("store: read requirements file %s of %s: %w", name, id, err)
		}
		files[i] = RequirementsFile{Name: name, Data: data}
	}
	return files, nil
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

// Projects lists every project, newest first.
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
	sort.Slice(projects, func(i, j int) bool {
		if !projects[i].CreatedAt.Equal(projects[j].CreatedAt) {
			return projects[i].CreatedAt.After(projects[j].CreatedAt)
		}
		return projects[i].ID < projects[j].ID
	})
	return projects, nil
}

// Project reads one project by ID. A project created before manifestSha256
// existed carries none in project.json; this computes it from package.json
// instead of returning it empty, but never rewrites the record: Project is
// a read.
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
	if record.Ecosystem == Pip {
		return Project{ID: record.ID, Name: record.Name, Ecosystem: Pip, PipTarget: record.PipTarget, Dir: dir, CreatedAt: record.CreatedAt}, nil
	}
	hash := record.ManifestSha256
	if hash == "" {
		if computed, herr := manifestSHA256(filepath.Join(dir, "package.json")); herr == nil {
			hash = computed
		}
	}
	return Project{ID: record.ID, Name: record.Name, Ecosystem: NPM, Target: record.Target, Dir: dir, ManifestSha256: hash, CreatedAt: record.CreatedAt}, nil
}

// ProjectsByManifestSha256 returns every project whose manifest hash
// equals hash, newest first: a session re-uploading a manifest it has
// already analysed wants its most recent project, not alphabetical order.
func (s *Store) ProjectsByManifestSha256(hash string) ([]Project, error) {
	all, err := s.Projects()
	if err != nil {
		return nil, err
	}
	matches := make([]Project, 0, len(all))
	for _, p := range all {
		if p.ManifestSha256 == hash {
			matches = append(matches, p)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].CreatedAt.After(matches[j].CreatedAt) })
	return matches, nil
}

// SetProjectTarget changes a project's target platform, refusing an empty
// field the same way UseSettings does.
func (s *Store) SetProjectTarget(id string, t Target) error {
	if err := validID(id); err != nil {
		return err
	}
	if err := ValidateTarget(t); err != nil {
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
	if record.Ecosystem == Pip {
		return fmt.Errorf("%w: a pip project has a pip target, not an npm one", ErrInvalidTarget)
	}
	record.Target = t
	return writeJSONFile(path, record, fileMode)
}

// DeleteProject removes a project directory and everything under it. It
// does not know whether a job still writes there: jobs.Service.DeleteProject
// asks the queue first, and a directory a crashed job left goes too.
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
