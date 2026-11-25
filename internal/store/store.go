package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/MorganKryze/sealift/npm"
)

// ErrInvalidLimits reports a minimum release age or a parallelism outside
// the range the settings allow.
var ErrInvalidLimits = errors.New("invalid limits")

// Limits the settings accept. Parallelism past these runs more pnpm or
// download processes than a single sealift host gains from.
const (
	MaxMinReleaseAgeDays   = 90
	MaxResolveParallelism  = 16
	MaxDownloadParallelism = 32
)

// ErrInvalidTarget reports a target with an empty field or a Node or pnpm
// version that is not exact: the caller's own mistake, not a server failure.
var ErrInvalidTarget = errors.New("invalid target")

// dirMode is the mode of every directory under the data volume except
// private/, so the tools user's group can create and write files in it.
// fileMode is the mode of every file the store writes there, for the same
// reason. privateMode keeps private/ unreadable outside the owner;
// settingsMode is the mode of the signing key and of a settings.json from
// an older release.
const (
	dirMode      = 0o770
	privateMode  = 0o700
	fileMode     = 0o664
	settingsMode = 0o600
)

// DefaultSettings are the values that apply when neither the deployment nor
// an older release's settings.json sets them.
//
// ResolveParallelism is 4 because each resolution is one pnpm process, and 8
// would double peak memory inside a desktop container where an OOM kill is
// worse than a slower analysis. DownloadParallelism is 16, and stays a
// setting so a deployment behind a limiting proxy can lower it.
// TestOpenStartsWithSettledParallelism pins both.
var DefaultSettings = Settings{
	Target: Target{
		OS:      "linux",
		CPU:     "x64",
		Libc:    "glibc",
		Node:    "22.17.1",
		PnpmVer: "10.34.5",
	},
	MinReleaseAgeDays:   14,
	ResolveParallelism:  4,
	DownloadParallelism: 16,
}

// Store is sealift's data volume: settings, projects, analyses and exports
// rooted at one directory.
type Store struct {
	root string
	// projects is projects/, opened once, where every reader of a file a
	// job wrote resolves its path.
	projects *os.Root

	mu       sync.RWMutex
	settings Settings
	// stored is what private/settings.json held when the store opened, and
	// hasStored whether there was such a file. Releases up to 0.7.0 wrote
	// it; it is read and never written, so they can still open the volume.
	stored    Settings
	hasStored bool
	// signing is a pointer: fmt prints a nested pointer as an address, so
	// printing a Store never reaches the private key.
	signing *SigningKey
	// keyStamp is the digest of the key file signing was read from; keyRead is
	// false while the file does not read, so each call tries it again.
	keyStamp keyStamp
	keyRead  bool

	// ephemeral draws project ids that do not derive from the name.
	ephemeral bool

	// purgeMu makes a purge and the creation of a job directory exclusive,
	// so a job either exists before the purge checks for one or starts
	// after the caches are gone. purgePending, guarded by it, records a
	// purge that a job in flight put off.
	purgeMu      sync.RWMutex
	purgePending bool
}

// Open creates the data volume layout under root when it is missing, then
// reads private/settings.json if an older release left one, then loads
// private/signing-key.pem or generates the key pair. Until UseSettings, the
// settings are the stored ones, or the defaults on a fresh volume.
//
// It also sets the process umask to 002. A container's default umask of 022
// would strip the group write bit from every file this package creates
// through os.OpenFile, and the tools user needs that bit to write lockfiles
// and caches outside private/.
func Open(root string) (*Store, error) {
	syscall.Umask(0o002)

	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{root, dirMode},
		{filepath.Join(root, "private"), privateMode},
		{filepath.Join(root, "tools"), dirMode},
		{filepath.Join(root, "trivy-cache"), dirMode},
		{filepath.Join(root, "cache"), dirMode},
		{filepath.Join(root, "cache", "resolve"), dirMode},
		{filepath.Join(root, "projects"), dirMode},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", d.path, err)
		}
	}

	projects, err := openProjectsRoot(filepath.Join(root, "projects"))
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, projects: projects, settings: DefaultSettings}
	settingsPath := filepath.Join(root, "private", "settings.json")
	switch _, err := os.Stat(settingsPath); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("store: stat settings: %w", err)
	default:
		var loaded Settings
		if err := readJSONFile(settingsPath, &loaded); err != nil {
			return nil, fmt.Errorf("store: read settings: %w", err)
		}
		if err := dropSignatureKey(settingsPath, loaded); err != nil {
			return nil, err
		}
		s.settings, s.stored, s.hasStored = loaded, loaded, true
	}

	key, stamp, err := loadSigningKey(s.signingKeyPath())
	if err != nil {
		return nil, err
	}
	s.signing, s.keyStamp, s.keyRead = &key, stamp, true
	return s, nil
}

// openProjectsRoot opens dir as the root the readers resolve in. The data
// volume is group-writable, so the tools account can put a link in place of
// projects/; the root counts only when it is the directory found at dir.
func openProjectsRoot(dir string) (*os.Root, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", dir, err)
	}
	opened, err := r.Stat(".")
	var found os.FileInfo
	if err == nil {
		found, err = os.Lstat(dir)
	}
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("store: stat %s: %w", dir, err)
	}
	if !os.SameFile(opened, found) {
		_ = r.Close()
		return nil, fmt.Errorf("store: %s must be a directory, not a link", dir)
	}
	return r, nil
}

// dropSignatureKey rewrites a settings.json from a 0.4 volume without its
// shared "signatureKey", which the signing key replaced. A file without the
// field is left as it is.
func dropSignatureKey(path string, loaded Settings) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("store: read settings: %w", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("store: read settings: %w", err)
	}
	if _, ok := keys["signatureKey"]; !ok {
		return nil
	}
	if err := writeJSONFile(path, loaded, settingsMode); err != nil {
		return fmt.Errorf("store: rewrite settings: %w", err)
	}
	return nil
}

// Root returns the directory the store is rooted at.
func (s *Store) Root() string { return s.root }

// Settings returns the current settings. Safe for concurrent use.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// StoredSettings returns what private/settings.json held when the store
// opened, and false when the volume had no such file.
func (s *Store) StoredSettings() (Settings, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stored, s.hasStored
}

// UseSettings makes set the settings in effect, refusing an invalid target
// or limits out of range. It writes nothing to the volume.
func (s *Store) UseSettings(set Settings) error {
	if err := ValidateTarget(set.Target); err != nil {
		return err
	}
	if err := validateLimits(set); err != nil {
		return err
	}
	s.mu.Lock()
	s.settings = set
	s.mu.Unlock()
	return nil
}

func validateLimits(set Settings) error {
	var problems []string
	check := func(name string, value, low, high int) {
		if value < low || value > high {
			problems = append(problems, fmt.Sprintf("%s must be between %d and %d, not %d", name, low, high, value))
		}
	}
	check("minimum release age", set.MinReleaseAgeDays, 1, MaxMinReleaseAgeDays)
	check("resolve parallelism", set.ResolveParallelism, 1, MaxResolveParallelism)
	check("download parallelism", set.DownloadParallelism, 1, MaxDownloadParallelism)
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidLimits, strings.Join(problems, "; "))
	}
	return nil
}

// ValidateTarget refuses a target the rest of the pipeline cannot resolve or
// export with, naming each field at fault.
func ValidateTarget(t Target) error {
	var problems []string
	for _, f := range []struct{ name, value string }{{"os", t.OS}, {"cpu", t.CPU}, {"node", t.Node}, {"pnpm version", t.PnpmVer}} {
		if f.value == "" {
			problems = append(problems, f.name+" is empty")
		}
	}
	// Both versions pin the exact toolchain an export is resolved with; a
	// range such as "22.x" would let the resolution drift between runs.
	if t.Node != "" && !npm.IsExactVersion(t.Node) {
		problems = append(problems, fmt.Sprintf("node must be exact, such as 22.17.1, not %q", t.Node))
	}
	if t.PnpmVer != "" && !npm.IsExactVersion(t.PnpmVer) {
		problems = append(problems, fmt.Sprintf("pnpm version must be exact, such as 10.34.5, not %q", t.PnpmVer))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidTarget, strings.Join(problems, "; "))
	}
	return nil
}

// beforeTempWrite is a test's hook between the creation of a temporary
// file and the write of its content.
var beforeTempWrite func(tmp string)

// atomicWriteFile writes data to a temporary file next to path and renames
// it into place, so a crash never leaves a partial file where callers expect
// a complete one. The temporary file is created with mode directly, so the
// process umask set by Open governs the group write bit the same way it
// would for any other file the store writes.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("store: create %s: %w", dir, err)
	}

	f, err := tempFile(dir, filepath.Base(path), mode)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below succeeds

	if beforeTempWrite != nil {
		beforeTempWrite(tmp)
	}
	// The tools account can replace any name in a group-writable directory,
	// so the content goes through the descriptor tempFile created, never
	// through a second open that would follow a link put in its place.
	_, err = f.Write(data)
	var written os.FileInfo
	if err == nil {
		written, err = f.Stat()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: rename to %s: %w", path, err)
	}
	// The rename moves whatever entry holds the temporary name by then, a
	// link or a file the tools account put there included. The write
	// counts only when path names the file written above.
	placed, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("store: stat %s: %w", path, err)
	}
	if !os.SameFile(written, placed) {
		return fmt.Errorf("store: %s was replaced while it was written", path)
	}
	return nil
}

// NewResolveDir reserves a fresh, group-writable directory under
// cache/resolve for one isolated pnpm resolution. Unlike os.MkdirTemp,
// which always creates mode 0700 under the system temp directory, this
// stays under the volume Open laid out and in a mode the tools account can
// traverse once it runs pnpm as a different uid. The caller removes the
// directory once the resolution ends.
func (s *Store) NewResolveDir() (string, error) {
	parent := filepath.Join(s.root, "cache", "resolve")
	for attempt := 0; attempt < 10; attempt++ {
		suffix, err := randomHex(6)
		if err != nil {
			return "", fmt.Errorf("store: generate resolve dir name: %w", err)
		}
		dir := filepath.Join(parent, suffix)
		if err := os.Mkdir(dir, dirMode); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("store: create %s: %w", dir, err)
		}
		return dir, nil
	}
	return "", fmt.Errorf("store: could not allocate a resolve dir under %s", parent)
}

// tempFile creates a file under a unique name in dir for name and returns
// it open for writing. O_EXCL never opens an entry that exists, a link
// included.
func tempFile(dir, name string, mode os.FileMode) (*os.File, error) {
	for attempt := 0; attempt < 10; attempt++ {
		suffix, err := randomHex(4)
		if err != nil {
			return nil, fmt.Errorf("store: generate temp name: %w", err)
		}
		path := filepath.Join(dir, "."+name+".tmp-"+suffix)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			return f, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("store: create %s: %w", path, err)
		}
	}
	return nil, fmt.Errorf("store: could not reserve a temp file for %s", name)
}

func writeJSONFile(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", path, err)
	}
	return atomicWriteFile(path, data, mode)
}

func readJSONFile(path string, v any) error {
	data, err := ReadRegularFile(path, storedFileLimit)
	if err != nil {
		return fmt.Errorf("store: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("store: unmarshal %s: %w", path, err)
	}
	return nil
}

// storedFileLimit bounds every file the store reads back. Each is JSON or a
// requirements file the server wrote, far smaller; the bound keeps a file
// the tools account planted from filling memory.
const storedFileLimit = 64 << 20

// ReadRegularFile reads the regular file at path, refusing one above limit
// bytes. The tools account can write the job directories and the caches:
// O_NOFOLLOW reads no link's target, and O_NONBLOCK keeps a FIFO from
// holding an open that nothing interrupts.
func ReadRegularFile(path string, limit int64) ([]byte, error) {
	name := filepath.Base(path)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return data, nil
}

// openProjectFile opens rel, a path under projects/ joined from validated
// identifiers, for reading. The tools account can write every directory
// there and put a link at any component of rel. The root follows a link
// only to a target inside projects/, which holds nothing kept from an API
// reader, so a path that leaves projects/, a loop of links and anything but
// a regular file are not found. O_NONBLOCK keeps a FIFO from holding the
// open until the type check refuses it.
func (s *Store) openProjectFile(rel string) (*os.File, error) {
	f, err := s.projects.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		// The root refuses a path that leaves it with an error that
		// carries no errno.
		var errno syscall.Errno
		if errors.As(err, &errno) && errno != syscall.ELOOP {
			return nil, fmt.Errorf("store: open %s: %w", rel, err)
		}
		slog.Warn("store: refusing a link out of projects/ or a loop of links", "path", rel)
		return nil, ErrNotFound
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: stat %s: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		slog.Warn("store: refusing a path that is not a regular file", "path", rel, "type", st.Mode().Type().String())
		return nil, ErrNotFound
	}
	return f, nil
}

// validID refuses an identifier that could escape the directory it names.
// Handlers pass path parameters straight through, so this is the last check
// before a path join.
func validID(s string) error {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") || strings.Contains(s, "..") {
		return fmt.Errorf("%w: invalid identifier %q", ErrNotFound, s)
	}
	for _, r := range s {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_'
		if !allowed {
			return fmt.Errorf("%w: invalid identifier %q", ErrNotFound, s)
		}
	}
	return nil
}

// randomHex returns n random bytes as a lowercase hex string. It backs both
// the temp file names atomicWriteFile picks and, through randomHexFunc, the
// project ID suffix in project.go.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
