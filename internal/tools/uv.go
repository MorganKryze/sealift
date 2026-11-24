package tools

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/MorganKryze/sealift/pip"
)

// DefaultPipIndex is the public package index uv comes from when no other
// is set.
const DefaultPipIndex = "https://pypi.org/simple/"

// ErrInvalidUvVersion reports a requested uv version that is not a plain
// X.Y.Z release number.
var ErrInvalidUvVersion = errors.New("invalid uv version")

const (
	// uvWheelLimit bounds the wheel download. A uv wheel runs about 20 MiB.
	uvWheelLimit = 64 << 20
	// uvBinaryLimit bounds the binary read out of the wheel. It runs about
	// 50 MiB once uncompressed.
	uvBinaryLimit = 128 << 20
	// The image uv runs in is Debian bookworm: glibc 2.36 and Python 3.11.2.
	uvHostGlibc  = "2.36"
	uvHostPython = "3.11.2"
)

// uvVersion is the store's rule for a target's uv version, so any version a
// target names can be installed. The version names a directory, so nothing
// else may pass.
var uvVersion = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)

// releaseTooRecent matches ErrReleaseTooRecent with a message that names
// the tool it refuses.
type releaseTooRecent struct{ msg string }

func (e releaseTooRecent) Error() string { return e.msg }
func (e releaseTooRecent) Unwrap() error { return ErrReleaseTooRecent }

// ParseIndexURL checks a package index URL. Empty gives DefaultPipIndex.
// The index must be https, or http on a loopback host, and carry no
// credentials. The error never repeats the value, which could hold them.
func ParseIndexURL(raw string) (string, error) {
	if raw == "" {
		return DefaultPipIndex, nil
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "", errors.New("the package index is not a readable URL")
	case u.User != nil:
		return "", errors.New("the package index URL must carry no credentials")
	case u.Scheme != "https" && u.Scheme != "http":
		return "", errors.New("the package index must be an https URL, or an http URL on a loopback host")
	case u.Host == "":
		return "", errors.New("the package index URL has no host")
	case u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("the package index URL must carry no query or fragment")
	case u.Scheme == "http" && !loopbackHost(u.Hostname()):
		return "", errors.New("an http package index must be on a loopback host: localhost, 127.0.0.1 or ::1")
	}
	return raw, nil
}

// ParseRegistryURL checks the npm registry pnpm and the analyses read.
// Empty keeps npm.DefaultRegistry. The registry must be https, or http on
// a loopback host, or http on any host when allowHTTP is set, which
// insecure then reports. Credentials may stand in the URL, so the error
// never repeats the value.
func ParseRegistryURL(raw string, allowHTTP bool) (u string, insecure bool, err error) {
	if raw == "" {
		return "", false, nil
	}
	parsed, perr := url.Parse(raw)
	switch {
	case perr != nil:
		return "", false, errors.New("the npm registry is not a readable URL")
	case parsed.Scheme != "https" && parsed.Scheme != "http":
		return "", false, errors.New("the npm registry must be an https URL, or an http URL on a loopback host")
	case parsed.Host == "":
		return "", false, errors.New("the npm registry URL has no host")
	case parsed.Scheme == "http" && !loopbackHost(parsed.Hostname()):
		if !allowHTTP {
			return "", false, errors.New("an http npm registry must be on a loopback host unless SEALIFT_ALLOW_HTTP_REGISTRY=true")
		}
		return raw, true, nil
	}
	return raw, false, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (m *Manager) pipIndex() string {
	if m.PipIndex != "" {
		return m.PipIndex
	}
	return DefaultPipIndex
}

// EnsureUv installs a uv release from the package index if it is not
// already present, and returns the path to tools/uv/<version>/uv. The
// wheel for this host is checked against the sha256 the index lists, and a
// release younger than Settings().MinReleaseAgeDays is refused. Only the uv binary is copied out of the wheel: nothing in it
// runs or is built.
func (m *Manager) EnsureUv(ctx context.Context, version string) (string, error) {
	if !uvVersion.MatchString(version) {
		return "", fmt.Errorf("%w: a release number such as 0.13.7 is expected", ErrInvalidUvVersion)
	}
	cpu, err := uvCPU(m.hostArch())
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	dir := filepath.Join(m.vol.Root(), "tools", "uv", version)
	bin := filepath.Join(dir, "uv")
	if info, err := os.Stat(bin); err == nil && info.Mode().IsRegular() {
		return bin, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	client := &pip.Client{Index: m.pipIndex(), HTTP: m.http}
	files, err := client.Files(ctx, "uv", version)
	if err != nil {
		return "", fmt.Errorf("uv %s: %w", version, err)
	}
	wheel, blocked := pip.ChooseWheel(files, pip.Platform{Python: uvHostPython, OS: "linux", CPU: cpu, Glibc: uvHostGlibc})
	if blocked != "" {
		return "", fmt.Errorf("uv %s: the index has no wheel for linux %s (%s)", version, cpu, blocked)
	}
	if err := m.checkUvAge(version, wheel.UploadTime); err != nil {
		return "", err
	}
	name, err := pip.ParseWheelName(wheel.Filename)
	if err != nil {
		return "", fmt.Errorf("uv %s: %w", version, err)
	}
	if wheel.Size > uvWheelLimit {
		return "", fmt.Errorf("uv %s: the index lists a wheel larger than %d MiB", version, uvWheelLimit>>20)
	}

	tmp, err := os.MkdirTemp("", "sealift-uv-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	wheelPath := filepath.Join(tmp, "uv.whl")
	sum, err := m.downloadWheel(ctx, wheel.URL, wheelPath)
	if err != nil {
		return "", fmt.Errorf("uv %s: %w", version, err)
	}
	if sum != wheel.Sha256 {
		return "", fmt.Errorf("uv %s: the wheel's sha256 is %s, the index lists %s", version, sum, wheel.Sha256)
	}

	entry := name.Name + "-" + name.Version + ".data/scripts/uv"
	if err := installDir(dir, func(target string) error {
		if err := os.MkdirAll(target, 0o770); err != nil {
			return err
		}
		return copyWheelEntry(wheelPath, entry, filepath.Join(target, "uv"))
	}); err != nil {
		return "", fmt.Errorf("uv %s: %w", version, err)
	}
	return bin, nil
}

// checkUvAge refuses a release younger than the minimum age, or one whose
// age the index does not give. The refusal says what the operator can do
// now, since no route installs a tool on demand.
func (m *Manager) checkUvAge(version string, uploaded time.Time) error {
	days := m.vol.Settings().MinReleaseAgeDays
	minAge := time.Duration(days) * 24 * time.Hour
	if minAge <= 0 {
		return nil
	}
	if uploaded.IsZero() {
		return releaseTooRecent{fmt.Sprintf("uv %s: the index gives no upload time, so its age against the minimum release age of %d days is unknown; pin an older uv in the project's target or the policy file", version, days)}
	}
	if age := time.Since(uploaded); age < minAge {
		return releaseTooRecent{fmt.Sprintf("uv %s was uploaded %s ago, under the minimum release age of %d days; pin an older uv in the project's target or the policy file, or wait until it is %d days old", version, age.Round(time.Hour), days, days)}
	}
	return nil
}

// downloadWheel writes the body at url to path and returns its sha256. It
// refuses a body larger than uvWheelLimit and never retries.
func (m *Manager) downloadWheel(ctx context.Context, url, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, uvWheelLimit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > uvWheelLimit {
		return "", fmt.Errorf("the wheel is larger than %d MiB", uvWheelLimit>>20)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyWheelEntry copies the one entry named entry out of the wheel at
// wheelPath to dst, mode 0755, under uvBinaryLimit. No other entry is read.
func copyWheelEntry(wheelPath, entry, dst string) error {
	f, err := os.Open(wheelPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	// An entry named outside the archive only endangers a reader that
	// writes every entry; this one looks up a single exact name.
	zr, err := zip.NewReader(f, info.Size())
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return fmt.Errorf("the wheel is not a readable zip: %w", err)
	}
	var found *zip.File
	for _, zf := range zr.File {
		if zf.Name != entry {
			continue
		}
		if found != nil {
			return fmt.Errorf("the wheel holds %s more than once", entry)
		}
		found = zf
	}
	switch {
	case found == nil:
		return fmt.Errorf("the wheel holds no %s", entry)
	case !found.Mode().IsRegular():
		return fmt.Errorf("%s in the wheel is not a regular file", entry)
	case found.UncompressedSize64 > uvBinaryLimit:
		return fmt.Errorf("%s in the wheel is larger than %d MiB", entry, uvBinaryLimit>>20)
	}

	rc, err := found.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	n, err := io.CopyN(out, rc, uvBinaryLimit+1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("read %s from the wheel: %w", entry, err)
	}
	if n > uvBinaryLimit {
		return fmt.Errorf("%s in the wheel is larger than %d MiB", entry, uvBinaryLimit>>20)
	}
	// The umask may have narrowed the mode, and the tools account runs uv
	// through the data group.
	return os.Chmod(dst, 0o755)
}

// uvCPU names the host CPU the way wheel platform tags do.
func uvCPU(arch string) (string, error) {
	switch arch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported host architecture %q", arch)
	}
}

// InstalledUv lists every uv version present under tools/uv/, sorted,
// skipping the staging directories an install leaves while it runs.
func (m *Manager) InstalledUv() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(m.vol.Root(), "tools", "uv"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && uvVersion.MatchString(e.Name()) {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}
