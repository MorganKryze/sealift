package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MorganKryze/sealift/npm"
)

// errPnpmBinMissing reports a pnpm package that extracted without
// package/bin/pnpm.cjs, the file sealift runs to drive pnpm.
var errPnpmBinMissing = errors.New("pnpm package has no package/bin/pnpm.cjs")

// EnsurePnpm installs the given pnpm version from the npm registry if it is
// not already present, and returns the path to its package/bin/pnpm.cjs.
// A version the registry published less than Settings().MinReleaseAgeDays
// ago, or gives no publish time for, is refused with ErrReleaseTooRecent:
// a project target can name any pnpm, so the pin alone vouches for nothing.
//
// It takes the same lock UpdateTrivy and ActivateTrivy do: two concurrent
// installs of the same version would otherwise share the one fixed
// "<version>.tmp" staging directory installDir uses. Today the queue only
// ever runs one job at a time, which is the only caller, so this is not
// yet reachable; tools.Manager still needs to enforce its own safety
// rather than depend on that.
func (m *Manager) EnsurePnpm(ctx context.Context, version string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir := filepath.Join(m.vol.Root(), "tools", "pnpm", version)
	bin := filepath.Join(dir, "package", "bin", "pnpm.cjs")
	if _, err := os.Stat(bin); err == nil {
		return bin, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	client := &npm.Client{Registry: m.NPMRegistry, HTTP: m.http}
	pkg, err := client.Packument(ctx, "pnpm")
	if err != nil {
		return "", fmt.Errorf("pnpm packument: %w", err)
	}
	meta, ok := pkg.Versions[version]
	if !ok {
		return "", fmt.Errorf("pnpm %s: %w", version, npm.ErrNotFound)
	}
	published, _ := pkg.Published(version)
	if err := m.checkPnpmAge(version, published); err != nil {
		return "", err
	}

	tmp, err := os.MkdirTemp("", "sealift-pnpm-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	tarball := filepath.Join(tmp, "pnpm.tgz")
	if _, err := client.DownloadFile(ctx, "pnpm", version, meta.Dist.Integrity, tarball); err != nil {
		return "", fmt.Errorf("download pnpm %s: %w", version, err)
	}

	if err := installDir(dir, func(target string) error {
		f, err := os.Open(tarball)
		if err != nil {
			return err
		}
		defer f.Close()
		return extractTarGz(f, target)
	}); err != nil {
		return "", fmt.Errorf("extract pnpm %s: %w", version, err)
	}

	if _, err := os.Stat(bin); err != nil {
		return "", fmt.Errorf("pnpm %s: %w", version, errPnpmBinMissing)
	}
	return bin, nil
}

// InstalledPnpm lists every pnpm version present under tools/pnpm/, sorted,
// skipping the "<version>.tmp" and "<version>.old-<suffix>" staging
// directories installDir leaves while it runs.
func (m *Manager) InstalledPnpm() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(m.vol.Root(), "tools", "pnpm"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && !strings.HasSuffix(e.Name(), ".tmp") && !strings.Contains(e.Name(), ".old-") {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}

// checkPnpmAge is checkUvAge for pnpm, with the publish time from the
// registry's packument.
func (m *Manager) checkPnpmAge(version string, published time.Time) error {
	days := m.vol.Settings().MinReleaseAgeDays
	minAge := time.Duration(days) * 24 * time.Hour
	if minAge <= 0 {
		return nil
	}
	if published.IsZero() {
		return releaseTooRecent{fmt.Sprintf("pnpm %s: the registry gives no publish time, so its age against the minimum release age of %d days is unknown; pin an older pnpm in the project's target or the policy file", version, days)}
	}
	if age := time.Since(published); age < minAge {
		return releaseTooRecent{fmt.Sprintf("pnpm %s was published %s ago, under the minimum release age of %d days; pin an older pnpm in the project's target or the policy file, or wait until it is %d days old", version, age.Round(time.Hour), days, days)}
	}
	return nil
}
