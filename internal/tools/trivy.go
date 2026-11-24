package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// ErrReleaseTooRecent reports a release younger than the configured
// minimum age. No caller can force the install.
var ErrReleaseTooRecent = errors.New("trivy release is too recent")

// ErrChecksumMismatch reports a downloaded Trivy asset whose sha256 does
// not match the pinned one.
var ErrChecksumMismatch = errors.New("trivy asset checksum mismatch")

// ErrReleaseSourceUnavailable reports that GitHub, where Trivy releases
// come from, did not answer usefully: unreachable, rate-limited or down.
var ErrReleaseSourceUnavailable = errors.New("could not reach GitHub to look up Trivy releases")

// ErrInvalidTrivyVersion reports a requested Trivy version that is not a
// plain X.Y.Z release number.
var ErrInvalidTrivyVersion = errors.New("trivy version must be a release number such as 0.74.0")

const trivyRepo = "aquasecurity/trivy"

// releaseNumber accepts a plain release number, with or without its "v".
// The version ends up in a GitHub API path and names a directory, so
// nothing else may pass.
var releaseNumber = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// TrivyState summarizes the Trivy versions on the data volume and the pin.
type TrivyState struct {
	Active    string    // version behind tools/trivy/current, empty if none
	Installed []string  // every version present under tools/trivy/, sorted
	Pinned    string    // the release sealift runs
	DBDate    time.Time // last update of the vulnerability database, zero if unknown
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// trivyPin returns the pin this Manager runs: Trivy when set, PinnedTrivy
// otherwise.
func (m *Manager) trivyPin() TrivyPin {
	if m.Trivy.Version == "" {
		return PinnedTrivy
	}
	return m.Trivy
}

// TrivyState reports the active and installed Trivy versions, the pinned
// one and the vulnerability database's date. Everything comes from the
// data volume: it asks nothing of the network.
func (m *Manager) TrivyState(_ context.Context) (TrivyState, error) {
	installed, err := m.InstalledTrivy()
	if err != nil {
		return TrivyState{}, err
	}
	active, err := m.activeTrivy()
	if err != nil {
		return TrivyState{}, err
	}
	return TrivyState{
		Active:    active,
		Installed: installed,
		Pinned:    m.trivyPin().Version,
		DBDate:    m.trivyDBDate(),
	}, nil
}

// Scanner reports the pinned Trivy and the vulnerability database's date.
// Neither read can fail: a missing or unreadable database is a zero time.
func (m *Manager) Scanner() (pinned string, dbDate time.Time) {
	return m.trivyPin().Version, m.trivyDBDate()
}

// Ready reports whether an analysis or export can run without sealift
// installing anything on its own: the pinned Trivy active and a
// vulnerability database, both already on the data volume. Another active
// version counts as no Trivy. It never reaches the network.
func (m *Manager) Ready() (ready bool, missing []string) {
	active, err := m.activeTrivy()
	if err != nil || active != m.trivyPin().Version {
		missing = append(missing, "trivy")
	}
	if m.trivyDBDate().IsZero() {
		missing = append(missing, "trivy-db")
	}
	return len(missing) == 0, missing
}

// EnsureTrivy installs the pinned Trivy release when it is not on the
// volume, activates it, and removes every other version. The download is
// installed only when its sha256 equals the pinned digest for this host;
// a mismatch installs nothing and leaves the active version as it was.
// GitHub is asked for the pinned tag alone, and nothing at all once the
// pin is on the volume.
func (m *Manager) EnsureTrivy(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pin := m.trivyPin()
	version := strings.TrimPrefix(pin.Version, "v")
	if !releaseNumber.MatchString(version) {
		return "", ErrInvalidTrivyVersion
	}
	arch := m.hostArch()
	want := pin.SHA256[arch]
	if want == "" {
		return "", fmt.Errorf("trivy %s: no pinned digest for %q", version, arch)
	}
	assetName, err := trivyAssetName(version, arch)
	if err != nil {
		return "", err
	}

	// A directory of the pinned version's name comes from an earlier
	// install and is kept; anything else there, a link included, is
	// replaced by a checked download.
	dir := filepath.Join(m.vol.Root(), "tools", "trivy", version)
	info, err := os.Lstat(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err != nil || !info.IsDir() {
		if err := m.installTrivyLocked(ctx, version, assetName, want, dir); err != nil {
			return "", err
		}
	}

	if active, err := m.activeTrivy(); err != nil || active != version {
		if err := m.activateTrivyLocked(version); err != nil {
			return "", err
		}
	}
	m.removeOtherTrivyLocked(version)
	return version, nil
}

// installTrivyLocked downloads the release asset, checks it against the
// pinned digest and extracts it into dir. The caller holds mu.
func (m *Manager) installTrivyLocked(ctx context.Context, version, assetName, want, dir string) error {
	rel, err := m.trivyReleaseByTag(ctx, version)
	if err != nil {
		return fmt.Errorf("%w: release %s: %w", ErrReleaseSourceUnavailable, version, err)
	}
	asset, ok := findAsset(rel.Assets, assetName)
	if !ok {
		return fmt.Errorf("trivy %s: no release asset %q", version, assetName)
	}

	tmp, err := os.MkdirTemp("", "sealift-trivy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	archivePath := filepath.Join(tmp, assetName)
	if err := m.download(ctx, asset.BrowserDownloadURL, archivePath); err != nil {
		return fmt.Errorf("trivy %s: %w", version, err)
	}
	if err := verifySHA256(archivePath, want); err != nil {
		return fmt.Errorf("trivy %s: %w", version, err)
	}
	if err := installDir(dir, func(target string) error {
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		return extractTarGz(f, target)
	}); err != nil {
		return fmt.Errorf("extract trivy %s: %w", version, err)
	}
	return nil
}

// removeOtherTrivyLocked removes every directory under tools/trivy/ but the
// pinned version's, leftovers of an interrupted install included. A
// directory it cannot remove is logged and left: the pin is active either
// way. The caller holds mu.
func (m *Manager) removeOtherTrivyLocked(keep string) {
	installed, err := m.InstalledTrivy()
	if err != nil {
		m.log.Warn("trivy: could not list the installed versions", "error", err)
		return
	}
	for _, v := range installed {
		if v == keep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(m.vol.Root(), "tools", "trivy", v)); err != nil {
			m.log.Warn("trivy: an old version stays on the volume", "version", v, "error", err)
		}
	}
}

// ActivateTrivy points tools/trivy/current at an installed version,
// rolling back when version is an older one already on disk. The switch
// is a single rename of a relative symlink, so it never leaves the
// directory in a half-updated state.
func (m *Manager) ActivateTrivy(version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activateTrivyLocked(version)
}

// activateTrivyLocked is ActivateTrivy's body, called both directly and
// from inside EnsureTrivy, which already holds mu.
func (m *Manager) activateTrivyLocked(version string) error {
	// The version names a directory and the link's target, so anything but
	// a release number could point the active Trivy anywhere.
	if !releaseNumber.MatchString(version) {
		return ErrInvalidTrivyVersion
	}
	dir := filepath.Join(m.vol.Root(), "tools", "trivy", version)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("trivy %s is not installed: %w", version, err)
	}
	link := filepath.Join(m.vol.Root(), "tools", "trivy", "current")
	tmp := link + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// InstalledTrivy lists every Trivy version present under tools/trivy/,
// sorted, excluding the current symlink.
func (m *Manager) InstalledTrivy() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(m.vol.Root(), "tools", "trivy"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name() != "current" && e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}

func (m *Manager) activeTrivy() (string, error) {
	target, err := os.Readlink(filepath.Join(m.vol.Root(), "tools", "trivy", "current"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return filepath.Base(target), nil
}

// trivyMetadataLimit bounds the database's metadata.json, a few hundred
// bytes as Trivy writes it.
const trivyMetadataLimit = 1 << 20

// trivyDBDate reads the vulnerability database's update time from Trivy's
// own cache metadata. A missing or unreadable file means no database yet,
// reported as a zero time rather than an error. Trivy runs as the tools
// account, which can leave a link or a FIFO there: neither is read.
func (m *Manager) trivyDBDate() time.Time {
	data, err := store.ReadRegularFile(filepath.Join(m.vol.Root(), "trivy-cache", "db", "metadata.json"), trivyMetadataLimit)
	if err != nil {
		return time.Time{}
	}
	var meta struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	if json.Unmarshal(data, &meta) != nil {
		return time.Time{}
	}
	return meta.UpdatedAt
}

// trivyReleaseByTag fetches one named release, the pinned one.
func (m *Manager) trivyReleaseByTag(ctx context.Context, version string) (ghRelease, error) {
	tag := version
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	data, err := m.fetchAPI(ctx, m.githubAPI()+"/repos/"+trivyRepo+"/releases/tags/"+tag)
	if err != nil {
		return ghRelease{}, err
	}
	var rel ghRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return ghRelease{}, err
	}
	return rel, nil
}

func (m *Manager) hostArch() string {
	if m.Arch != "" {
		return m.Arch
	}
	return runtime.GOARCH
}

// releaseJSONLimit bounds a GitHub API answer, a release's JSON listing a
// few dozen assets, so a misbehaving or compromised server cannot make get
// buffer an unbounded body in memory.
const releaseJSONLimit = 1 << 20

// assetSizeLimit bounds a Trivy release tarball, which runs tens of
// megabytes, generously, so download cannot be made to write an unbounded
// body to disk.
const assetSizeLimit = 512 << 20

// fetchAPI fetches a GitHub API URL. It is the only request that carries
// the GitHub token: release assets come from other addresses and get none.
func (m *Manager) fetchAPI(ctx context.Context, url string) ([]byte, error) {
	return m.get(ctx, url, m.GitHubToken)
}

// get never puts the token in an error: the messages carry the URL and the
// status only.
func (m *Manager) get(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, releaseJSONLimit))
}

func (m *Manager) download(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, assetSizeLimit)); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// trivyAssetName returns the release asset name for a host architecture,
// following Trivy's own naming: Linux-64bit for amd64, Linux-ARM64 for
// arm64. The container always runs Linux, so the OS name is fixed.
func trivyAssetName(version, arch string) (string, error) {
	switch arch {
	case "amd64":
		return fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", version), nil
	case "arm64":
		return fmt.Sprintf("trivy_%s_Linux-ARM64.tar.gz", version), nil
	default:
		return "", fmt.Errorf("unsupported host architecture %q", arch)
	}
}

func findAsset(assets []ghAsset, name string) (ghAsset, bool) {
	for _, a := range assets {
		if a.Name == name {
			return a, true
		}
	}
	return ghAsset{}, false
}

func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%w: got %s, want %s", ErrChecksumMismatch, got, want)
	}
	return nil
}
