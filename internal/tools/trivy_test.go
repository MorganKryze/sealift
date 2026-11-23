package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// trivyTestVersion is the release every fake release server serves and
// every test pin names.
const trivyTestVersion = "0.55.0"

// fakeTrivyRelease stands in for GitHub: the pinned tag's release, both
// Linux tarballs and the release's checksums file, on one origin. It
// records the path and the Authorization header of every request.
type fakeTrivyRelease struct {
	srv *httptest.Server
	// pin holds the sha256 of the tarballs as built, before any tampering.
	pin    TrivyPin
	served string // sha256 of the amd64 tarball the server sends

	mu    sync.Mutex
	paths []string
	auth  map[string]string
}

// newFakeTrivyRelease builds the release. With tampered set, the server
// sends other amd64 bytes than the pin's, and the release's checksums file
// lists those bytes' digest, as a swapped release would.
func newFakeTrivyRelease(t *testing.T, tampered bool) *fakeTrivyRelease {
	t.Helper()
	const version = trivyTestVersion
	amd64 := buildTarGz(t, map[string]string{"trivy": "#!/bin/sh\necho fake trivy amd64\n", "LICENSE": "fake license\n"})
	arm64 := buildTarGz(t, map[string]string{"trivy": "#!/bin/sh\necho fake trivy arm64\n", "LICENSE": "fake license\n"})
	f := &fakeTrivyRelease{
		pin:  TrivyPin{Version: version, SHA256: map[string]string{"amd64": sha256Hex(amd64), "arm64": sha256Hex(arm64)}},
		auth: map[string]string{},
	}
	if tampered {
		amd64 = buildTarGz(t, map[string]string{"trivy": "#!/bin/sh\necho swapped\n"})
	}
	f.served = sha256Hex(amd64)
	amd64Name := fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", version)
	arm64Name := fmt.Sprintf("trivy_%s_Linux-ARM64.tar.gz", version)
	checksumsName := fmt.Sprintf("trivy_%s_checksums.txt", version)
	checksums := fmt.Sprintf("%s  %s\n%s  %s\n", sha256Hex(amd64), amd64Name, sha256Hex(arm64), arm64Name)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/aquasecurity/trivy/releases/tags/v"+version, func(w http.ResponseWriter, _ *http.Request) {
		rel := ghRelease{
			TagName: "v" + version,
			Assets: []ghAsset{
				{Name: amd64Name, BrowserDownloadURL: f.srv.URL + "/" + amd64Name},
				{Name: arm64Name, BrowserDownloadURL: f.srv.URL + "/" + arm64Name},
				{Name: checksumsName, BrowserDownloadURL: f.srv.URL + "/" + checksumsName},
			},
		}
		data, _ := json.Marshal(rel)
		_, _ = w.Write(data)
	})
	for name, body := range map[string][]byte{amd64Name: amd64, arm64Name: arm64, checksumsName: []byte(checksums)} {
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.auth[r.URL.Path] = r.Header.Get("Authorization")
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTrivyRelease) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.paths)
}

func (f *fakeTrivyRelease) authorization(path string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.auth[path]
	return v, ok
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// newTestManager returns a Manager on a fresh volume that asks srv for
// releases, on an amd64 host, running pin.
func newTestManager(t *testing.T, srv *httptest.Server, pin TrivyPin) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root, settings: store.Settings{MinReleaseAgeDays: 7}}, srv.Client(), nil)
	m.GitHubAPI = srv.URL
	m.Arch = "amd64"
	m.Trivy = pin
	return m, root
}

// plantTrivy installs a version by hand, and makes it the active one when
// active is set, as an older sealift would have left it.
func plantTrivy(t *testing.T, root, version string, active bool) {
	t.Helper()
	dir := filepath.Join(root, "tools", "trivy", version)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if active {
		link := filepath.Join(root, "tools", "trivy", "current")
		_ = os.Remove(link)
		if err := os.Symlink(version, link); err != nil {
			t.Fatal(err)
		}
	}
}

func plantTrivyDB(t *testing.T, root string, updatedAt time.Time) {
	t.Helper()
	dbDir := filepath.Join(root, "trivy-cache", "db")
	if err := os.MkdirAll(dbDir, 0o770); err != nil {
		t.Fatal(err)
	}
	metadata := fmt.Sprintf(`{"Version":2,"UpdatedAt":%q}`, updatedAt.UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dbDir, "metadata.json"), []byte(metadata), 0o664); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedTrivyIsWellFormed(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(PinnedTrivy.Version) {
		t.Errorf("PinnedTrivy.Version = %q, want a release number such as 0.76.2", PinnedTrivy.Version)
	}
	digest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if len(PinnedTrivy.SHA256) != 2 {
		t.Errorf("PinnedTrivy.SHA256 has %d entries, want amd64 and arm64 only", len(PinnedTrivy.SHA256))
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if !digest.MatchString(PinnedTrivy.SHA256[arch]) {
			t.Errorf("PinnedTrivy.SHA256[%q] = %q, want 64 lowercase hex characters", arch, PinnedTrivy.SHA256[arch])
		}
	}
}

func TestEnsureTrivyInstallsThePinnedRelease(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, root := newTestManager(t, f.srv, f.pin)

	version, err := m.EnsureTrivy(context.Background())
	if err != nil {
		t.Fatalf("EnsureTrivy: %v", err)
	}
	if version != trivyTestVersion {
		t.Fatalf("version = %q, want %q", version, trivyTestVersion)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", trivyTestVersion, "trivy")); err != nil {
		t.Fatalf("installed trivy binary missing: %v", err)
	}
	if active, err := m.activeTrivy(); err != nil || active != trivyTestVersion {
		t.Fatalf("active = %q, %v, want %q", active, err, trivyTestVersion)
	}
}

func TestEnsureTrivyRefusesBytesThatDoNotMatchThePin(t *testing.T) {
	f := newFakeTrivyRelease(t, true)
	m, root := newTestManager(t, f.srv, f.pin)
	plantTrivy(t, root, "0.54.0", true)

	_, err := m.EnsureTrivy(context.Background())
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("EnsureTrivy error = %v, want ErrChecksumMismatch", err)
	}
	for _, digest := range []string{f.pin.SHA256["amd64"], f.served} {
		if !strings.Contains(err.Error(), digest) {
			t.Errorf("error %q does not name the digest %s", err, digest)
		}
	}
	for _, dir := range []string{trivyTestVersion, trivyTestVersion + ".tmp"} {
		if _, err := os.Stat(filepath.Join(root, "tools", "trivy", dir)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("tools/trivy/%s exists after a refused download: %v", dir, err)
		}
	}
	if active, err := m.activeTrivy(); err != nil || active != "0.54.0" {
		t.Errorf("active = %q, %v, want 0.54.0 unchanged", active, err)
	}
	if installed, _ := m.InstalledTrivy(); !slices.Equal(installed, []string{"0.54.0"}) {
		t.Errorf("InstalledTrivy = %v, want [0.54.0] kept after a refused download", installed)
	}
}

func TestEnsureTrivyAsksGitHubForThePinnedTagOnly(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, _ := newTestManager(t, f.srv, f.pin)

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatalf("EnsureTrivy: %v", err)
	}
	want := []string{
		"/repos/aquasecurity/trivy/releases/tags/v" + trivyTestVersion,
		"/trivy_" + trivyTestVersion + "_Linux-64bit.tar.gz",
	}
	if got := f.requests(); !slices.Equal(got, want) {
		t.Errorf("requests = %v, want exactly %v", got, want)
	}
}

func TestEnsureTrivyDoesNothingWhenThePinIsInstalled(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, root := newTestManager(t, f.srv, f.pin)
	plantTrivy(t, root, trivyTestVersion, true)

	version, err := m.EnsureTrivy(context.Background())
	if err != nil {
		t.Fatalf("EnsureTrivy: %v", err)
	}
	if version != trivyTestVersion {
		t.Errorf("version = %q, want %q", version, trivyTestVersion)
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("requests = %v, want none while the pin is installed and active", got)
	}
}

func TestEnsureTrivyActivatesAnInstalledPinWithoutDownloading(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, root := newTestManager(t, f.srv, f.pin)
	plantTrivy(t, root, trivyTestVersion, false)
	plantTrivy(t, root, "0.54.0", true)

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatalf("EnsureTrivy: %v", err)
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("requests = %v, want none while the pin is on the volume", got)
	}
	if active, _ := m.activeTrivy(); active != trivyTestVersion {
		t.Errorf("active = %q, want %q", active, trivyTestVersion)
	}
	if installed, _ := m.InstalledTrivy(); !slices.Equal(installed, []string{trivyTestVersion}) {
		t.Errorf("InstalledTrivy = %v, want the pin alone", installed)
	}
}

func TestEnsureTrivyRemovesOtherVersions(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, root := newTestManager(t, f.srv, f.pin)
	plantTrivy(t, root, "0.53.1", false)
	plantTrivy(t, root, "0.54.0", true)

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatalf("EnsureTrivy: %v", err)
	}
	installed, err := m.InstalledTrivy()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(installed, []string{trivyTestVersion}) {
		t.Errorf("InstalledTrivy = %v, want [%s] once the pin is active", installed, trivyTestVersion)
	}
	if active, _ := m.activeTrivy(); active != trivyTestVersion {
		t.Errorf("active = %q, want %q", active, trivyTestVersion)
	}
}

// A version the account cannot remove stays on the volume: the pin is
// active all the same, and the log names what was left.
func TestEnsureTrivyLogsAVersionItCannotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes a read-only directory's files")
	}
	f := newFakeTrivyRelease(t, false)
	var logs bytes.Buffer
	m, root := newTestManager(t, f.srv, f.pin)
	m.log = slog.New(slog.NewTextHandler(&logs, nil))
	plantTrivy(t, root, "0.54.0", true)
	locked := filepath.Join(root, "tools", "trivy", "0.54.0", "contrib")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatalf("EnsureTrivy: %v, want the pin active despite the leftover", err)
	}
	if active, _ := m.activeTrivy(); active != trivyTestVersion {
		t.Errorf("active = %q, want %q", active, trivyTestVersion)
	}
	if !strings.Contains(logs.String(), "0.54.0") {
		t.Errorf("log %q does not name the version left on the volume", logs.String())
	}
}

func TestEnsureTrivyRefusesAPinItCannotUse(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	for _, tc := range []struct {
		name, arch, want string
		pin              TrivyPin
	}{
		{"no digest for the host", "arm64", `no pinned digest for "arm64"`, TrivyPin{Version: trivyTestVersion, SHA256: map[string]string{"amd64": f.pin.SHA256["amd64"]}}},
		{"a path as version", "amd64", ErrInvalidTrivyVersion.Error(), TrivyPin{Version: "../../evil", SHA256: f.pin.SHA256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestManager(t, f.srv, tc.pin)
			m.Arch = tc.arch
			if _, err := m.EnsureTrivy(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("EnsureTrivy error = %v, want it to say %q", err, tc.want)
			}
		})
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("requests = %v, want none for a pin that cannot be used", got)
	}
}

func TestEnsureTrivyReportsAnUnreachableReleaseSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	m, _ := newTestManager(t, srv, newFakeTrivyRelease(t, false).pin)

	if _, err := m.EnsureTrivy(context.Background()); !errors.Is(err, ErrReleaseSourceUnavailable) {
		t.Fatalf("EnsureTrivy error = %v, want ErrReleaseSourceUnavailable", err)
	}
}

// A release answer past releaseJSONLimit is cut, so it fails to parse
// instead of being buffered whole.
func TestEnsureTrivyRefusesAnOversizedReleaseAnswer(t *testing.T) {
	oversized := append([]byte(`{"tag_name":"v`+trivyTestVersion+`","x":"`), bytes.Repeat([]byte("0"), releaseJSONLimit+1024)...)
	oversized = append(oversized, []byte(`"}`)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(oversized) }))
	t.Cleanup(srv.Close)
	m, root := newTestManager(t, srv, newFakeTrivyRelease(t, false).pin)

	if _, err := m.EnsureTrivy(context.Background()); err == nil {
		t.Fatal("EnsureTrivy with an oversized release answer: want error, got nil")
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "trivy", trivyTestVersion)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing may be installed, stat error = %v", err)
	}
}

func TestReadyWantsThePinnedTrivyActive(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, nil, nil)
	m.GitHubAPI = "http://127.0.0.1:1"
	m.Trivy = TrivyPin{Version: trivyTestVersion, SHA256: map[string]string{"amd64": strings.Repeat("0", 64)}}

	if ready, missing := m.Ready(); ready || !slices.Equal(missing, []string{"trivy", "trivy-db"}) {
		t.Fatalf("Ready on a fresh volume = (%v, %v), want (false, [trivy trivy-db])", ready, missing)
	}
	plantTrivyDB(t, root, time.Now())
	plantTrivy(t, root, "0.54.0", true)
	if ready, missing := m.Ready(); ready || !slices.Equal(missing, []string{"trivy"}) {
		t.Fatalf("Ready with another version active = (%v, %v), want (false, [trivy])", ready, missing)
	}
	plantTrivy(t, root, trivyTestVersion, true)
	if ready, missing := m.Ready(); !ready || len(missing) != 0 {
		t.Fatalf("Ready with the pin active = (%v, %v), want (true, [])", ready, missing)
	}
}

func TestTrivyStateReadsTheVolumeOnly(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, root := newTestManager(t, f.srv, f.pin)
	plantTrivy(t, root, "0.54.0", true)
	updatedAt := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	plantTrivyDB(t, root, updatedAt)

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if state.Active != "0.54.0" || !slices.Equal(state.Installed, []string{"0.54.0"}) {
		t.Errorf("Active, Installed = %q, %v, want 0.54.0, [0.54.0]", state.Active, state.Installed)
	}
	if state.Pinned != trivyTestVersion {
		t.Errorf("Pinned = %q, want %q", state.Pinned, trivyTestVersion)
	}
	if !state.DBDate.Equal(updatedAt) {
		t.Errorf("DBDate = %v, want %v", state.DBDate, updatedAt)
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("TrivyState made requests %v, want none", got)
	}
}

func TestTrivyStateWithNoDBIsZeroTime(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, _ := newTestManager(t, f.srv, f.pin)

	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatalf("TrivyState: %v", err)
	}
	if !state.DBDate.IsZero() || len(state.Installed) != 0 || state.Active != "" {
		t.Fatalf("TrivyState on a fresh volume = %+v, want no database, nothing installed, nothing active", state)
	}
}

// A Manager whose Trivy is left zero runs the pin built into sealift.
func TestTrivyStateNamesTheBuiltInPinByDefault(t *testing.T) {
	m := NewManager(fakeVolume{root: t.TempDir()}, nil, nil)
	state, err := m.TrivyState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Pinned != PinnedTrivy.Version {
		t.Errorf("Pinned = %q, want %q", state.Pinned, PinnedTrivy.Version)
	}
}

func TestActivateTrivyRollsBack(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, nil, nil)
	plantTrivy(t, root, "0.54.0", false)
	plantTrivy(t, root, trivyTestVersion, true)

	if err := m.ActivateTrivy("0.54.0"); err != nil {
		t.Fatalf("rollback to 0.54.0: %v", err)
	}
	if active, err := m.activeTrivy(); err != nil || active != "0.54.0" {
		t.Fatalf("active version after rollback = %q, %v, want 0.54.0", active, err)
	}
	if installed, _ := m.InstalledTrivy(); !slices.Equal(installed, []string{"0.54.0", trivyTestVersion}) {
		t.Fatalf("InstalledTrivy = %v, want [0.54.0 %s]", installed, trivyTestVersion)
	}
}

func TestActivateTrivyRefusesUninstalledVersion(t *testing.T) {
	m := NewManager(fakeVolume{root: t.TempDir()}, nil, nil)
	if err := m.ActivateTrivy("9.9.9"); err == nil {
		t.Fatal("ActivateTrivy on a version never installed: want error, got nil")
	}
}

// A version is a path element: one that is not a release number could
// point the active link at any directory, inside the volume or out of it.
func TestActivateTrivyRefusesAPathAsVersion(t *testing.T) {
	root := t.TempDir()
	m := NewManager(fakeVolume{root: root}, nil, nil)
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

const testToken = "ghp_test_secret_token_value"

func TestGitHubTokenSentOnTheReleaseLookup(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, _ := newTestManager(t, f.srv, f.pin)
	m.GitHubToken = testToken

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := "/repos/aquasecurity/trivy/releases/tags/v" + trivyTestVersion
	if got, _ := f.authorization(path); got != "Bearer "+testToken {
		t.Errorf("Authorization on %s = %q, want the bearer token", path, got)
	}
}

func TestGitHubTokenAbsentWhenUnset(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, _ := newTestManager(t, f.srv, f.pin)

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range f.requests() {
		if got, _ := f.authorization(path); got != "" {
			t.Errorf("Authorization on %s = %q, want none", path, got)
		}
	}
}

// The fake serves the assets on the API's own origin, the worst case: only
// the request kind decides, never the address.
func TestGitHubTokenNotSentOnAssetDownloads(t *testing.T) {
	f := newFakeTrivyRelease(t, false)
	m, _ := newTestManager(t, f.srv, f.pin)
	m.GitHubToken = testToken

	if _, err := m.EnsureTrivy(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := "/trivy_" + trivyTestVersion + "_Linux-64bit.tar.gz"
	got, ok := f.authorization(path)
	if !ok {
		t.Fatalf("%s was never requested", path)
	}
	if got != "" {
		t.Errorf("Authorization on asset %s = %q, want none", path, got)
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
			m.Arch = "amd64"

			_, err := m.EnsureTrivy(context.Background())
			if !errors.Is(err, ErrReleaseSourceUnavailable) {
				t.Errorf("error = %v, want ErrReleaseSourceUnavailable", err)
			}
			if err != nil && strings.Contains(err.Error(), testToken) {
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

// Trivy runs as the tools account, which can write its cache. A FIFO or a
// link at the database's metadata.json reads as no database yet, at once.
func TestTrivyStateRefusesAFIFOOrALinkAtTheDBMetadata(t *testing.T) {
	for _, plant := range []struct {
		name string
		do   func(t *testing.T, path string)
	}{
		{"FIFO", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o660); err != nil {
				t.Fatal(err)
			}
		}},
		{"link", func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "metadata.json")
			if err := os.WriteFile(target, []byte(`{"Version":2,"UpdatedAt":"2026-09-10T12:00:00Z"}`), 0o664); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(plant.name, func(t *testing.T) {
			root := t.TempDir()
			m := NewManager(fakeVolume{root: root}, nil, nil)
			dbDir := filepath.Join(root, "trivy-cache", "db")
			if err := os.MkdirAll(dbDir, 0o770); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dbDir, "metadata.json")
			plant.do(t, path)

			var state TrivyState
			var err error
			done := make(chan struct{})
			go func() {
				defer close(done)
				state, err = m.TrivyState(context.Background())
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				for {
					if w, werr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); werr == nil {
						_ = w.Close()
					}
					select {
					case <-done:
						t.Fatal("TrivyState waited on a FIFO")
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
			if err != nil {
				t.Fatalf("TrivyState: %v", err)
			}
			if !state.DBDate.IsZero() {
				t.Errorf("DBDate = %v, want none read", state.DBDate)
			}
		})
	}
}
