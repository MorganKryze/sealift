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
	"runtime"
	"sort"
	"strings"
	"time"
)

// ErrReleaseTooRecent reports a Trivy release younger than the configured
// minimum age, refused unless the caller forces the install.
var ErrReleaseTooRecent = errors.New("trivy release is too recent")

// ErrChecksumMismatch reports a downloaded Trivy asset whose sha256 does
// not match the release's checksums file.
var ErrChecksumMismatch = errors.New("trivy asset checksum mismatch")

const trivyRepo = "aquasecurity/trivy"

// TrivyState summarizes the installed and available Trivy versions.
type TrivyState struct {
	Active    string        // version behind tools/trivy/current, empty if none
	Installed []string      // every version present under tools/trivy/, sorted
	Latest    string        // latest version on GitHub
	LatestAge time.Duration // time since the latest release was published
	DBDate    time.Time     // last update of the vulnerability database, zero if unknown
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// TrivyState reports the active and installed Trivy versions, the latest
// release on GitHub and its age, and the vulnerability database's date.
func (m *Manager) TrivyState(ctx context.Context) (TrivyState, error) {
	installed, err := m.InstalledTrivy()
	if err != nil {
		return TrivyState{}, err
	}
	active, err := m.activeTrivy()
	if err != nil {
		return TrivyState{}, err
	}
	rel, err := m.latestTrivyRelease(ctx)
	if err != nil {
		return TrivyState{}, fmt.Errorf("trivy latest release: %w", err)
	}
	return TrivyState{
		Active:    active,
		Installed: installed,
		Latest:    strings.TrimPrefix(rel.TagName, "v"),
		LatestAge: time.Since(rel.PublishedAt),
		DBDate:    m.trivyDBDate(),
	}, nil
}

// UpdateTrivy installs the latest Trivy release and activates it. It
// refuses a release younger than Settings().MinReleaseAgeDays unless force
// is true. The checksum catches corruption, not a compromised release; the
// minimum age is the protection against that.
func (m *Manager) UpdateTrivy(ctx context.Context, force bool) (string, error) {
	rel, err := m.latestTrivyRelease(ctx)
	if err != nil {
		return "", fmt.Errorf("trivy latest release: %w", err)
	}
	version := strings.TrimPrefix(rel.TagName, "v")

	minAge := time.Duration(m.vol.Settings().MinReleaseAgeDays) * 24 * time.Hour
	if age := time.Since(rel.PublishedAt); !force && age < minAge {
		return "", fmt.Errorf("%w: %s was published %s ago, minimum age is %s", ErrReleaseTooRecent, version, age.Round(time.Hour), minAge)
	}

	assetName, err := trivyAssetName(version, m.hostArch())
	if err != nil {
		return "", err
	}
	asset, ok := findAsset(rel.Assets, assetName)
	if !ok {
		return "", fmt.Errorf("trivy %s: no release asset %q", version, assetName)
	}
	checksumsAsset, ok := findAsset(rel.Assets, fmt.Sprintf("trivy_%s_checksums.txt", version))
	if !ok {
		return "", fmt.Errorf("trivy %s: no checksums file", version)
	}

	sums, err := m.fetchBytes(ctx, checksumsAsset.BrowserDownloadURL)
	if err != nil {
		return "", fmt.Errorf("trivy %s checksums: %w", version, err)
	}
	want, err := checksumFor(sums, assetName)
	if err != nil {
		return "", fmt.Errorf("trivy %s: %w", version, err)
	}

	tmp, err := os.MkdirTemp("", "sealift-trivy-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	archivePath := filepath.Join(tmp, assetName)
	if err := m.download(ctx, asset.BrowserDownloadURL, archivePath); err != nil {
		return "", fmt.Errorf("trivy %s: %w", version, err)
	}
	if err := verifySHA256(archivePath, want); err != nil {
		return "", fmt.Errorf("trivy %s: %w", version, err)
	}

	dir := filepath.Join(m.vol.Root(), "tools", "trivy", version)
	if err := installDir(dir, func(target string) error {
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		return extractTarGz(f, target)
	}); err != nil {
		return "", fmt.Errorf("extract trivy %s: %w", version, err)
	}

	if err := m.ActivateTrivy(version); err != nil {
		return "", err
	}
	return version, nil
}

// ActivateTrivy points tools/trivy/current at an installed version,
// rolling back when version is an older one already on disk. The switch
// is a single rename of a relative symlink, so it never leaves the
// directory in a half-updated state.
func (m *Manager) ActivateTrivy(version string) error {
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

// trivyDBDate reads the vulnerability database's update time from Trivy's
// own cache metadata. A missing or unreadable file means no database yet,
// reported as a zero time rather than an error.
func (m *Manager) trivyDBDate() time.Time {
	data, err := os.ReadFile(filepath.Join(m.vol.Root(), "trivy-cache", "db", "metadata.json"))
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

func (m *Manager) latestTrivyRelease(ctx context.Context) (ghRelease, error) {
	data, err := m.fetchBytes(ctx, m.githubAPI()+"/repos/"+trivyRepo+"/releases/latest")
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

func (m *Manager) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
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
	if _, err := io.Copy(f, resp.Body); err != nil {
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

func checksumFor(checksums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum for %q", name)
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
