package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// trivyTestVersion is the release version every trivyRelease server
// advertises as latest.
const trivyTestVersion = "0.55.0"

// trivyRelease builds an httptest server that serves a single GitHub
// release for aquasecurity/trivy, tagged trivyTestVersion: the
// release-latest endpoint, the Linux-64bit tarball, and its checksums
// file. When badChecksum is true, the checksums file lists a checksum
// that does not match the tarball, so callers can exercise the mismatch
// path. The returned counter counts requests for the tarball asset, so a
// caller can assert a second install skipped the download.
func trivyRelease(t *testing.T, publishedAt time.Time, badChecksum bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var assetRequests atomic.Int32
	const version = trivyTestVersion
	tarball := buildTarGz(t, map[string]string{
		"trivy":       "#!/bin/sh\necho fake trivy\n",
		"LICENSE":     "fake license\n",
		"contrib/x.y": "unused\n",
	})
	assetName := fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", version)
	checksumsName := fmt.Sprintf("trivy_%s_checksums.txt", version)

	sum := sha256.Sum256(tarball)
	hexSum := hex.EncodeToString(sum[:])
	if badChecksum {
		hexSum = hex.EncodeToString(sha256.New().Sum(nil))
	}
	checksums := fmt.Sprintf("%s  %s\n", hexSum, assetName)

	// srv is assigned below; the handler reads its URL lazily on each
	// request, once the server is listening.
	var srv *httptest.Server
	mux := http.NewServeMux()
	release := func() ghRelease {
		return ghRelease{
			TagName:     "v" + version,
			PublishedAt: publishedAt,
			Assets: []ghAsset{
				{Name: assetName, BrowserDownloadURL: srv.URL + "/" + assetName, Size: int64(len(tarball))},
				{Name: checksumsName, BrowserDownloadURL: srv.URL + "/" + checksumsName},
			},
		}
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		data, _ := json.Marshal(v)
		_, _ = w.Write(data)
	}
	mux.HandleFunc("/repos/aquasecurity/trivy/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, release())
	})
	mux.HandleFunc("/repos/aquasecurity/trivy/releases/tags/v"+version, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, release())
	})
	// The release list, newest first as GitHub orders it: this release,
	// a prerelease and a draft that must never be recommended, then an
	// older release past any minimum age.
	mux.HandleFunc("/repos/aquasecurity/trivy/releases", func(w http.ResponseWriter, _ *http.Request) {
		old := time.Now().Add(-60 * 24 * time.Hour)
		writeJSON(w, []ghRelease{
			release(),
			{TagName: "v0.54.9-rc.1", PublishedAt: old, Prerelease: true},
			{TagName: "v0.54.8", PublishedAt: old, Draft: true},
			{TagName: "v0.54.0", PublishedAt: old},
			// Published before v0.54.0 but numbered higher, as a patch on
			// an older line can be: the recommendation follows the number.
			{TagName: "v0.54.1", PublishedAt: old.Add(-24 * time.Hour)},
		})
	})
	mux.HandleFunc("/"+assetName, func(w http.ResponseWriter, _ *http.Request) {
		assetRequests.Add(1)
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc("/"+checksumsName, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &assetRequests
}

func newTestManager(t *testing.T, srv *httptest.Server) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root, settings: store.Settings{MinReleaseAgeDays: 7}}, srv.Client(), nil)
	m.GitHubAPI = srv.URL
	m.Arch = "amd64"
	return m, root
}

func TestUpdateTrivyRefusesRecentReleaseWithoutForce(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-1*time.Hour), false)
	m, root := newTestManager(t, srv)

	_, err := m.UpdateTrivy(context.Background(), "", false)
	if !errors.Is(err, ErrReleaseTooRecent) {
		t.Fatalf("UpdateTrivy(force=false) error = %v, want ErrReleaseTooRecent", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", "0.55.0")); !os.IsNotExist(err) {
		t.Fatalf("a refused release must not be installed, stat error = %v", err)
	}
}

func TestUpdateTrivyInstallsRecentReleaseWithForce(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-1*time.Hour), false)
	m, root := newTestManager(t, srv)

	version, err := m.UpdateTrivy(context.Background(), "", true)
	if err != nil {
		t.Fatalf("UpdateTrivy(force=true): %v", err)
	}
	if version != "0.55.0" {
		t.Fatalf("version = %q, want 0.55.0", version)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", "0.55.0", "trivy")); err != nil {
		t.Fatalf("installed trivy binary missing: %v", err)
	}

	active, err := m.activeTrivy()
	if err != nil {
		t.Fatalf("activeTrivy: %v", err)
	}
	if active != "0.55.0" {
		t.Fatalf("active version = %q, want 0.55.0", active)
	}
}

func TestUpdateTrivyChecksumMismatchInstallsNothing(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-30*24*time.Hour), true)
	m, root := newTestManager(t, srv)

	_, err := m.UpdateTrivy(context.Background(), "", false)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("UpdateTrivy error = %v, want ErrChecksumMismatch", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", "0.55.0")); !os.IsNotExist(err) {
		t.Fatalf("a checksum mismatch must not be installed, stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", "0.55.0.tmp")); !os.IsNotExist(err) {
		t.Fatalf("a checksum mismatch must not leave a partial extraction, stat error = %v", err)
	}
}

func TestActivateTrivyRollsBack(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, root := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), "", false); err != nil {
		t.Fatalf("install 0.55.0: %v", err)
	}

	// A second version installed by hand, as a later UpdateTrivy would.
	oldDir := filepath.Join(root, "tools", "trivy", "0.54.0")
	if err := os.MkdirAll(oldDir, 0o770); err != nil {
		t.Fatalf("mkdir 0.54.0: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "trivy"), []byte("old"), 0o755); err != nil {
		t.Fatalf("write 0.54.0/trivy: %v", err)
	}

	if err := m.ActivateTrivy("0.54.0"); err != nil {
		t.Fatalf("rollback to 0.54.0: %v", err)
	}
	active, err := m.activeTrivy()
	if err != nil {
		t.Fatalf("activeTrivy: %v", err)
	}
	if active != "0.54.0" {
		t.Fatalf("active version after rollback = %q, want 0.54.0", active)
	}

	installed, err := m.InstalledTrivy()
	if err != nil {
		t.Fatalf("InstalledTrivy: %v", err)
	}
	want := []string{"0.54.0", "0.55.0"}
	if len(installed) != len(want) || installed[0] != want[0] || installed[1] != want[1] {
		t.Fatalf("InstalledTrivy = %v, want %v", installed, want)
	}
}

func TestActivateTrivyRefusesUninstalledVersion(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now(), false)
	m, _ := newTestManager(t, srv)
	if err := m.ActivateTrivy("9.9.9"); err == nil {
		t.Fatal("ActivateTrivy on a version never installed: want error, got nil")
	}
}

// A version is a path element: one that is not a release number could
// point the active link at any directory, inside the volume or out of it.
func TestActivateTrivyRefusesAPathAsVersion(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now(), false)
	m, root := newTestManager(t, srv)
	if err := os.MkdirAll(filepath.Join(root, "elsewhere"), 0o770); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"../../elsewhere", "/tmp", "0.76.2/../../../elsewhere"} {
		if err := m.ActivateTrivy(v); !errors.Is(err, ErrInvalidTrivyVersion) {
			t.Errorf("ActivateTrivy(%q) = %v, want ErrInvalidTrivyVersion", v, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "tools", "trivy", "current")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the active link exists after refused versions: %v", err)
	}
}

func TestTrivyStateReportsDBDate(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, root := newTestManager(t, srv)

	dbDir := filepath.Join(root, "trivy-cache", "db")
	if err := os.MkdirAll(dbDir, 0o770); err != nil {
		t.Fatalf("mkdir trivy-cache/db: %v", err)
	}
	updatedAt := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	metadata := fmt.Sprintf(`{"Version":2,"UpdatedAt":%q}`, updatedAt.Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dbDir, "metadata.json"), []byte(metadata), 0o664); err != nil {
		t.Fatalf("write metadata.json: %v", err)
	}

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if !state.DBDate.Equal(updatedAt) {
		t.Fatalf("DBDate = %v, want %v", state.DBDate, updatedAt)
	}
	if state.Latest != "0.55.0" {
		t.Fatalf("Latest = %q, want 0.55.0", state.Latest)
	}
}

// TestTrivyStateReportsLatestSizeBytes proves TrivyState reports the size
// of the release asset this host would actually download, not the
// release's total footprint across every platform.
func TestTrivyStateReportsLatestSizeBytes(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now(), false)
	m, _ := newTestManager(t, srv)

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if state.LatestSizeBytes <= 0 {
		t.Fatalf("LatestSizeBytes = %d, want a positive size", state.LatestSizeBytes)
	}
}

// TestManagerReady proves Ready names Trivy and its database, whichever
// is still missing, without ever reaching the network: an analysis only
// needs what is already on the data volume.
func TestManagerReady(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, nil, nil)
	m.GitHubAPI = "http://127.0.0.1:1"

	if ready, missing := m.Ready(); ready || len(missing) != 2 {
		t.Fatalf("Ready on a fresh volume = (%v, %v), want (false, [trivy trivy-db])", ready, missing)
	}

	if err := os.MkdirAll(filepath.Join(root, "tools", "trivy", "0.55.0"), 0o770); err != nil {
		t.Fatalf("mkdir trivy version: %v", err)
	}
	if err := os.Symlink("0.55.0", filepath.Join(root, "tools", "trivy", "current")); err != nil {
		t.Fatalf("symlink current: %v", err)
	}
	if ready, missing := m.Ready(); ready || len(missing) != 1 || missing[0] != "trivy-db" {
		t.Fatalf("Ready with trivy active = (%v, %v), want (false, [trivy-db])", ready, missing)
	}

	dbDir := filepath.Join(root, "trivy-cache", "db")
	if err := os.MkdirAll(dbDir, 0o770); err != nil {
		t.Fatalf("mkdir trivy-cache/db: %v", err)
	}
	metadata := fmt.Sprintf(`{"UpdatedAt":%q}`, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dbDir, "metadata.json"), []byte(metadata), 0o664); err != nil {
		t.Fatalf("write metadata.json: %v", err)
	}
	if ready, missing := m.Ready(); !ready || len(missing) != 0 {
		t.Fatalf("Ready once everything is in place = (%v, %v), want (true, [])", ready, missing)
	}
}

func TestTrivyStateWithNoDBIsZeroTime(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now(), false)
	m, _ := newTestManager(t, srv)

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if !state.DBDate.IsZero() {
		t.Fatalf("DBDate = %v, want zero", state.DBDate)
	}
	if len(state.Installed) != 0 {
		t.Fatalf("Installed = %v, want empty", state.Installed)
	}
	if state.Active != "" {
		t.Fatalf("Active = %q, want empty", state.Active)
	}
}

// TestUpdateTrivyChecksumsBodyOverLimitFailsInstall proves fetchBytes caps
// the checksums body instead of buffering it whole: a body padded well past
// checksumsSizeLimit loses the real checksum line to truncation, so the
// install fails instead of succeeding on an unbounded read.
func TestUpdateTrivyChecksumsBodyOverLimitFailsInstall(t *testing.T) {
	const version = trivyTestVersion
	tarball := buildTarGz(t, map[string]string{"trivy": "#!/bin/sh\necho fake trivy\n"})
	assetName := fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", version)
	checksumsName := fmt.Sprintf("trivy_%s_checksums.txt", version)

	oversized := bytes.Repeat([]byte("0"), checksumsSizeLimit+1024)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/aquasecurity/trivy/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		rel := ghRelease{
			TagName:     "v" + version,
			PublishedAt: time.Now().Add(-30 * 24 * time.Hour),
			Assets: []ghAsset{
				{Name: assetName, BrowserDownloadURL: srv.URL + "/" + assetName, Size: int64(len(tarball))},
				{Name: checksumsName, BrowserDownloadURL: srv.URL + "/" + checksumsName},
			},
		}
		data, _ := json.Marshal(rel)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/"+assetName, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc("/"+checksumsName, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(oversized)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m, root := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), "", false); err == nil {
		t.Fatal("UpdateTrivy with an oversized checksums body: want error, got nil")
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", version)); !os.IsNotExist(err) {
		t.Fatalf("a rejected checksums body must not be installed, stat error = %v", err)
	}
}

// TestTrivyStateSurvivesGitHubUnreachable proves a GitHub outage does not
// fail TrivyState outright: the installed and active versions, and the
// database date, all come from the data volume alone and stay reportable.
func TestTrivyStateSurvivesGitHubUnreachable(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root, settings: store.Settings{MinReleaseAgeDays: 7}}, &http.Client{Timeout: time.Second}, nil)
	m.GitHubAPI = "http://127.0.0.1:1" // nothing listens here

	if err := os.MkdirAll(filepath.Join(root, "tools", "trivy", trivyTestVersion), 0o770); err != nil {
		t.Fatalf("mkdir installed version: %v", err)
	}
	if err := m.ActivateTrivy(trivyTestVersion); err != nil {
		t.Fatalf("ActivateTrivy: %v", err)
	}

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState with GitHub unreachable: %v, want it to succeed with partial data", err)
	}
	if state.Active != trivyTestVersion {
		t.Errorf("Active = %q, want %q", state.Active, trivyTestVersion)
	}
	if len(state.Installed) != 1 || state.Installed[0] != trivyTestVersion {
		t.Errorf("Installed = %v, want [%q]", state.Installed, trivyTestVersion)
	}
	if state.Latest != "" || state.LatestAge != 0 {
		t.Errorf("Latest/LatestAge = %q/%v, want both zero since GitHub could not be reached", state.Latest, state.LatestAge)
	}
}

func TestUpdateTrivyInstallingSameVersionTwiceDownloadsOnce(t *testing.T) {
	srv, assetRequests := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, _ := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), "", false); err != nil {
		t.Fatalf("first UpdateTrivy: %v", err)
	}
	if got := assetRequests.Load(); got != 1 {
		t.Fatalf("asset requests after first install = %d, want 1", got)
	}

	if _, err := m.UpdateTrivy(context.Background(), "", false); err != nil {
		t.Fatalf("second UpdateTrivy: %v", err)
	}
	if got := assetRequests.Load(); got != 1 {
		t.Fatalf("asset requests after second install = %d, want still 1: a version already installed must not download again", got)
	}

	active, err := m.activeTrivy()
	if err != nil {
		t.Fatalf("activeTrivy: %v", err)
	}
	if active != trivyTestVersion {
		t.Fatalf("active version = %q, want %q", active, trivyTestVersion)
	}
}

func TestTrivyStateRecommendsAnOlderReleaseWhileTheLatestIsTooRecent(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-1*time.Hour), false)
	m, _ := newTestManager(t, srv)

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if state.Recommended != "0.54.1" {
		t.Fatalf("Recommended = %q, want 0.54.1: the highest version past the minimum age, whatever the list order, skipping the prerelease and the draft", state.Recommended)
	}
}

func TestTrivyStateRecommendsNothingWhileTheLatestIsOldEnough(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, _ := newTestManager(t, srv)

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if state.Recommended != "" {
		t.Fatalf("Recommended = %q, want empty when the latest release is old enough", state.Recommended)
	}
}

func TestUpdateTrivyInstallsANamedRelease(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, _ := newTestManager(t, srv)

	version, err := m.UpdateTrivy(context.Background(), trivyTestVersion, false)
	if err != nil {
		t.Fatalf("UpdateTrivy(%s): %v", trivyTestVersion, err)
	}
	if version != trivyTestVersion {
		t.Fatalf("installed %q, want %q", version, trivyTestVersion)
	}
}

func TestUpdateTrivyRefusesANamedRecentReleaseWithoutForce(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-1*time.Hour), false)
	m, _ := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), trivyTestVersion, false); !errors.Is(err, ErrReleaseTooRecent) {
		t.Fatalf("UpdateTrivy error = %v, want ErrReleaseTooRecent", err)
	}
}

func TestUpdateTrivyRejectsAVersionThatIsNotPlainSemver(t *testing.T) {
	srv, _ := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, _ := newTestManager(t, srv)

	for _, version := range []string{"../../../evil/repo/releases/tags/v1.0.0", "0.55.0/../latest", "v0.55.0-rc.1", "latest"} {
		if _, err := m.UpdateTrivy(context.Background(), version, true); !errors.Is(err, ErrInvalidTrivyVersion) {
			t.Errorf("UpdateTrivy(%q) error = %v, want ErrInvalidTrivyVersion", version, err)
		}
	}
}

func TestUpdateTrivyReportsAnUnreachableReleaseSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	m, _ := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), "", false); !errors.Is(err, ErrReleaseSourceUnavailable) {
		t.Fatalf("UpdateTrivy error = %v, want ErrReleaseSourceUnavailable", err)
	}
}

// authSpy wraps a release server's handler and records the Authorization
// header of every request, keyed by path.
func authSpy(t *testing.T, publishedAt time.Time) (*httptest.Server, func() map[string]string) {
	t.Helper()
	inner, _ := trivyRelease(t, publishedAt, false)
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		// The inner server's asset URLs point at itself: proxy by path.
		resp, err := http.Get(inner.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		// Rewrite the asset host so downloads come back to this server.
		body = bytes.ReplaceAll(body, []byte(inner.URL), []byte("http://"+r.Host))
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]string{}
		for k, v := range seen {
			out[k] = v
		}
		return out
	}
}

const testToken = "ghp_test_secret_token_value"

func TestGitHubTokenSentOnReleaseLookups(t *testing.T) {
	srv, seen := authSpy(t, time.Now().Add(-30*24*time.Hour))
	m, _ := newTestManager(t, srv)
	m.GitHubToken = testToken

	if _, err := m.latestTrivyRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.trivyReleaseByTag(context.Background(), "0.55.0"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.recommendedTrivyRelease(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/repos/aquasecurity/trivy/releases/latest",
		"/repos/aquasecurity/trivy/releases/tags/v0.55.0",
		"/repos/aquasecurity/trivy/releases",
	} {
		if got, want := seen()[path], "Bearer "+testToken; got != want {
			t.Errorf("Authorization on %s = %q, want %q", path, got, want)
		}
	}
}

func TestGitHubTokenAbsentWhenUnset(t *testing.T) {
	srv, seen := authSpy(t, time.Now().Add(-30*24*time.Hour))
	m, _ := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), "", false); err != nil {
		t.Fatal(err)
	}
	for path, got := range seen() {
		if got != "" {
			t.Errorf("Authorization on %s = %q, want none", path, got)
		}
	}
}

// The test server serves the assets on the API's own origin, the worst
// case: only the request kind decides, never the address.
func TestGitHubTokenNotSentOnAssetDownloads(t *testing.T) {
	srv, seen := authSpy(t, time.Now().Add(-30*24*time.Hour))
	m, _ := newTestManager(t, srv)
	m.GitHubToken = testToken

	if _, err := m.UpdateTrivy(context.Background(), "", false); err != nil {
		t.Fatal(err)
	}
	got := seen()
	for _, path := range []string{
		"/trivy_0.55.0_Linux-64bit.tar.gz",
		"/trivy_0.55.0_checksums.txt",
	} {
		if _, ok := got[path]; !ok {
			t.Fatalf("%s was never requested", path)
		}
		if got[path] != "" {
			t.Errorf("Authorization on asset %s = %q, want none", path, got[path])
		}
	}
	if got["/repos/aquasecurity/trivy/releases/latest"] == "" {
		t.Error("the release lookup carried no token")
	}
}

func TestGitHubTokenNeverInErrorsOrLogs(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// A server that echoes the credential into its body, as a
				// hostile or buggy mirror could.
				http.Error(w, r.Header.Get("Authorization"), status)
			}))
			t.Cleanup(srv.Close)
			var logs bytes.Buffer
			log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			m := NewManager(fakeVolume{root: t.TempDir(), settings: store.Settings{MinReleaseAgeDays: 7}}, srv.Client(), log)
			m.GitHubAPI = srv.URL
			m.GitHubToken = testToken

			_, err := m.UpdateTrivy(context.Background(), "", false)
			if err == nil {
				t.Fatal("UpdateTrivy succeeded against a failing API")
			}
			if !errors.Is(err, ErrReleaseSourceUnavailable) {
				t.Errorf("error = %v, want ErrReleaseSourceUnavailable", err)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error text carries the token: %q", err)
			}
			if _, err := m.TrivyState(context.Background()); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(logs.String(), testToken) {
				t.Errorf("log carries the token: %q", logs.String())
			}
		})
	}
}
