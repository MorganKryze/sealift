package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
// path.
func trivyRelease(t *testing.T, publishedAt time.Time, badChecksum bool) *httptest.Server {
	t.Helper()
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
	mux.HandleFunc("/repos/aquasecurity/trivy/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		rel := ghRelease{
			TagName:     "v" + version,
			PublishedAt: publishedAt,
			Assets: []ghAsset{
				{Name: assetName, BrowserDownloadURL: srv.URL + "/" + assetName},
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
		_, _ = w.Write([]byte(checksums))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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
	srv := trivyRelease(t, time.Now().Add(-1*time.Hour), false)
	m, root := newTestManager(t, srv)

	_, err := m.UpdateTrivy(context.Background(), false)
	if !errors.Is(err, ErrReleaseTooRecent) {
		t.Fatalf("UpdateTrivy(force=false) error = %v, want ErrReleaseTooRecent", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", "0.55.0")); !os.IsNotExist(err) {
		t.Fatalf("a refused release must not be installed, stat error = %v", err)
	}
}

func TestUpdateTrivyInstallsRecentReleaseWithForce(t *testing.T) {
	srv := trivyRelease(t, time.Now().Add(-1*time.Hour), false)
	m, root := newTestManager(t, srv)

	version, err := m.UpdateTrivy(context.Background(), true)
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
	srv := trivyRelease(t, time.Now().Add(-30*24*time.Hour), true)
	m, root := newTestManager(t, srv)

	_, err := m.UpdateTrivy(context.Background(), false)
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
	srv := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
	m, root := newTestManager(t, srv)

	if _, err := m.UpdateTrivy(context.Background(), false); err != nil {
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
	m, _ := newTestManager(t, trivyRelease(t, time.Now(), false))
	if err := m.ActivateTrivy("9.9.9"); err == nil {
		t.Fatal("ActivateTrivy on a version never installed: want error, got nil")
	}
}

func TestTrivyStateReportsDBDate(t *testing.T) {
	srv := trivyRelease(t, time.Now().Add(-30*24*time.Hour), false)
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

func TestTrivyStateWithNoDBIsZeroTime(t *testing.T) {
	srv := trivyRelease(t, time.Now(), false)
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
