package tools

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
)

func sriIntegrity(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// pnpmRegistry serves a packument with the given versions, each backed by
// its own tarball, and counts every request it receives.
func pnpmRegistry(t *testing.T, tarballs map[string][]byte) (*httptest.Server, *atomic.Int32) {
	return pnpmRegistryAt(t, tarballs, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))
}

// pnpmRegistryAt is pnpmRegistry with every version published at the given
// time; a zero time leaves the packument without a time field.
func pnpmRegistryAt(t *testing.T, tarballs map[string][]byte, published time.Time) (*httptest.Server, *atomic.Int32) {
	times := map[string]time.Time{}
	for version := range tarballs {
		times[version] = published
	}
	return pnpmRegistryTimes(t, tarballs, times)
}

// pnpmRegistryTimes is pnpmRegistry with each version published at its own
// time; a version with a zero time has no entry in the time field.
func pnpmRegistryTimes(t *testing.T, tarballs map[string][]byte, times map[string]time.Time) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32

	pkg := npm.Packument{Name: "pnpm", Versions: map[string]npm.VersionMeta{}, Time: map[string]json.RawMessage{}}
	for version, data := range tarballs {
		meta := npm.VersionMeta{Version: version}
		meta.Dist.Integrity = sriIntegrity(data)
		pkg.Versions[version] = meta
		if published := times[version]; !published.IsZero() {
			stamp, _ := json.Marshal(published)
			pkg.Time[version] = stamp
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pnpm", func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(pkg)
	})
	for version, data := range tarballs {
		path := fmt.Sprintf("/pnpm/-/pnpm-%s.tgz", version)
		body := data
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = w.Write(body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestEnsurePnpmDownloadsAndExtracts(t *testing.T) {
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"10.34.5"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\nconsole.log('pnpm')\n",
	})
	srv, requests := pnpmRegistry(t, map[string][]byte{"10.34.5": tarball})

	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	bin, err := m.EnsurePnpm(context.Background(), "10.34.5")
	if err != nil {
		t.Fatalf("EnsurePnpm: %v", err)
	}
	want := filepath.Join(root, "tools", "pnpm", "10.34.5", "package", "bin", "pnpm.cjs")
	if bin != want {
		t.Fatalf("bin = %q, want %q", bin, want)
	}
	content, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read installed bin: %v", err)
	}
	if string(content) != "#!/usr/bin/env node\nconsole.log('pnpm')\n" {
		t.Fatalf("installed bin content = %q", content)
	}

	before := requests.Load()
	bin2, err := m.EnsurePnpm(context.Background(), "10.34.5")
	if err != nil {
		t.Fatalf("second EnsurePnpm: %v", err)
	}
	if bin2 != bin {
		t.Fatalf("second EnsurePnpm bin = %q, want %q", bin2, bin)
	}
	if got := requests.Load(); got != before {
		t.Fatalf("second EnsurePnpm made %d more requests, want an already-installed version to skip the network", got-before)
	}
}

func TestEnsurePnpmMissingBinGivesClearError(t *testing.T) {
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"9.0.0"}`,
	})
	srv, _ := pnpmRegistry(t, map[string][]byte{"9.0.0": tarball})

	m := NewManager(fakeVolume{root: t.TempDir()}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	_, err := m.EnsurePnpm(context.Background(), "9.0.0")
	if err == nil {
		t.Fatal("EnsurePnpm with no package/bin/pnpm.cjs: want error, got nil")
	}
	if !errors.Is(err, errPnpmBinMissing) {
		t.Fatalf("EnsurePnpm error = %v, want it to wrap errPnpmBinMissing", err)
	}
}

// TestEnsurePnpmRetrySucceedsAfterBadExtraction proves installDir can
// replace an install a previous, failed EnsurePnpm call left on disk: the
// first tarball lacks package/bin/pnpm.cjs, so tools/pnpm/10.34.5 exists
// but is unusable; the retry must still succeed once the registry serves a
// complete tarball for the same version.
func TestEnsurePnpmRetrySucceedsAfterBadExtraction(t *testing.T) {
	badTarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm"}`,
	})
	goodTarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	badSrv, _ := pnpmRegistry(t, map[string][]byte{"10.34.5": badTarball})
	goodSrv, _ := pnpmRegistry(t, map[string][]byte{"10.34.5": goodTarball})

	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, http.DefaultClient, nil)

	m.NPMRegistry = badSrv.URL
	if _, err := m.EnsurePnpm(context.Background(), "10.34.5"); !errors.Is(err, errPnpmBinMissing) {
		t.Fatalf("first EnsurePnpm error = %v, want errPnpmBinMissing", err)
	}

	m.NPMRegistry = goodSrv.URL
	bin, err := m.EnsurePnpm(context.Background(), "10.34.5")
	if err != nil {
		t.Fatalf("retry EnsurePnpm: %v", err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("stat installed bin after retry: %v", err)
	}
}

func TestEnsurePnpmUnknownVersion(t *testing.T) {
	srv, _ := pnpmRegistry(t, map[string][]byte{})
	m := NewManager(fakeVolume{root: t.TempDir(), settings: store.Settings{}}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	if _, err := m.EnsurePnpm(context.Background(), "0.0.1"); err == nil {
		t.Fatal("EnsurePnpm with an unpublished version: want error, got nil")
	}
}

// TestEnsurePnpmConcurrentCallsDoNotRace exercises Manager's mutex: two
// calls installing the same version from separate goroutines share the
// one fixed "<version>.tmp" staging directory installDir uses. go test
// -race is what actually catches a missing lock here; this only gives it
// something concurrent to catch.
func TestEnsurePnpmConcurrentCallsDoNotRace(t *testing.T) {
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"10.34.5"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\nconsole.log('pnpm')\n",
	})
	srv, _ := pnpmRegistry(t, map[string][]byte{"10.34.5": tarball})

	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, srv.Client(), nil)
	m.NPMRegistry = srv.URL

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.EnsurePnpm(context.Background(), "10.34.5"); err != nil {
				t.Errorf("EnsurePnpm: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestInstalledPnpmListsExtractedVersions(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, http.DefaultClient, nil)

	got, err := m.InstalledPnpm()
	if err != nil {
		t.Fatalf("InstalledPnpm on an empty store: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("InstalledPnpm = %v, want none", got)
	}

	for _, v := range []string{"10.34.5", "9.15.0"} {
		if err := os.MkdirAll(filepath.Join(root, "tools", "pnpm", v), 0o770); err != nil {
			t.Fatalf("mkdir %s: %v", v, err)
		}
	}
	got, err = m.InstalledPnpm()
	if err != nil {
		t.Fatalf("InstalledPnpm: %v", err)
	}
	want := []string{"10.34.5", "9.15.0"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("InstalledPnpm = %v, want %v (sorted)", got, want)
	}
}

func TestInstalledPnpmSkipsStagingFolders(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, http.DefaultClient, nil)
	for _, dir := range []string{"10.34.5", "10.34.5.tmp", "9.15.0", "9.15.0.old-1732441200"} {
		if err := os.MkdirAll(filepath.Join(root, "tools", "pnpm", dir), 0o770); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.InstalledPnpm()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.34.5", "9.15.0"}; !slices.Equal(got, want) {
		t.Errorf("InstalledPnpm() = %v, want %v", got, want)
	}
}

// TestEnsurePnpmRefusesAReleaseUnderTheMinimumAge holds pnpm to the
// minimum release age as uv is: a version the registry published two days
// ago, or one it gives no publish time for, is refused before any download,
// and the refusal names the version, its age and what to do. The registry
// also serves an older version, so the age must come from the version asked
// for and not from another entry of the packument.
func TestEnsurePnpmRefusesAReleaseUnderTheMinimumAge(t *testing.T) {
	oldTarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"10.30.0"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"10.40.0"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	tarballs := map[string][]byte{"10.30.0": oldTarball, "10.40.0": tarball}
	cases := []struct {
		name      string
		published time.Time
		want      []string
	}{
		{"two days old", time.Now().Add(-48 * time.Hour), []string{"pnpm 10.40.0", "48h0m0s ago", "14 days", "pin an older pnpm"}},
		{"no publish time", time.Time{}, []string{"pnpm 10.40.0", "no publish time", "14 days", "pin an older pnpm"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			times := map[string]time.Time{"10.30.0": time.Now().Add(-30 * 24 * time.Hour), "10.40.0": c.published}
			srv, requests := pnpmRegistryTimes(t, tarballs, times)
			root := t.TempDir()
			m := NewManager(fakeVolume{root: root, settings: store.Settings{MinReleaseAgeDays: 14}}, srv.Client(), nil)
			m.NPMRegistry = srv.URL

			_, err := m.EnsurePnpm(context.Background(), "10.40.0")
			if !errors.Is(err, ErrReleaseTooRecent) {
				t.Fatalf("EnsurePnpm = %v, want ErrReleaseTooRecent", err)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not say %q", err, w)
				}
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("registry got %d requests, want the packument only", got)
			}
			if _, err := os.Stat(filepath.Join(root, "tools", "pnpm", "10.40.0")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused pnpm left tools/pnpm/10.40.0: %v", err)
			}
			if _, err := m.EnsurePnpm(context.Background(), "10.30.0"); err != nil {
				t.Errorf("EnsurePnpm(10.30.0) on the same registry: %v", err)
			}
		})
	}
}

// TestEnsurePnpmAcceptsAReleaseOverTheMinimumAge installs a version the
// registry published long before the minimum age.
func TestEnsurePnpmAcceptsAReleaseOverTheMinimumAge(t *testing.T) {
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"10.40.0"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	srv, _ := pnpmRegistryAt(t, map[string][]byte{"10.40.0": tarball}, time.Now().Add(-15*24*time.Hour))
	m := NewManager(fakeVolume{root: t.TempDir(), settings: store.Settings{MinReleaseAgeDays: 14}}, srv.Client(), nil)
	m.NPMRegistry = srv.URL
	if _, err := m.EnsurePnpm(context.Background(), "10.40.0"); err != nil {
		t.Fatalf("EnsurePnpm: %v", err)
	}
}

func TestPnpmMinimumAgeBoundary(t *testing.T) {
	m := NewManager(fakeVolume{root: t.TempDir(), settings: store.Settings{MinReleaseAgeDays: 14}}, nil, nil)
	var tooRecent releaseTooRecent
	if err := m.checkPnpmAge("10.40.0", time.Now().Add(-13*24*time.Hour)); !errors.As(err, &tooRecent) {
		t.Errorf("13 days old: got %v, want a refusal", err)
	}
	if err := m.checkPnpmAge("10.40.0", time.Now().Add(-14*24*time.Hour-time.Hour)); err != nil {
		t.Errorf("14 days and one hour old: got %v, want nil", err)
	}
}
