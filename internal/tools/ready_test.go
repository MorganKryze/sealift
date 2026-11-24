package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/internal/store"
)

const (
	preparePnpm = "10.34.5"
	prepareKey  = "3f9a0c1d3f9a0c1d3f9a0c1d3f9a0c1d3f9a0c1d3f9a0c1d3f9a0c1d3f9a0c1d"
)

// fakeDB stands in for Trivy's database download. It writes the database's
// metadata as Trivy does unless fail returns an error for that call, and a
// call waits on hold first when hold is set.
type fakeDB struct {
	root string
	at   time.Time
	fail func(call int) error
	hold chan struct{}

	mu    sync.Mutex
	calls int
}

func (d *fakeDB) UpdateDB(ctx context.Context) (string, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	if d.hold != nil && call > 1 {
		select {
		case <-d.hold:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if d.fail != nil {
		if err := d.fail(call); err != nil {
			return "", err
		}
	}
	dir := filepath.Join(d.root, "trivy-cache", "db")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return "", err
	}
	meta := fmt.Sprintf(`{"Version":2,"UpdatedAt":%q}`, d.at.UTC().Format(time.RFC3339))
	return "", os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(meta), 0o664)
}

func (d *fakeDB) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// preparation is a Preparer on a fresh volume whose GitHub, npm registry
// and package index are local fakes, all serving what it asks for.
type preparation struct {
	p    *Preparer
	m    *Manager
	db   *fakeDB
	root string
	logs *syncBuffer
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newPreparation(t *testing.T, uvUploaded time.Time) *preparation {
	t.Helper()
	gh := newFakeTrivyRelease(t, false)
	tarball := buildTarGz(t, map[string]string{
		"package/package.json": `{"name":"pnpm","version":"` + preparePnpm + `"}`,
		"package/bin/pnpm.cjs": "#!/usr/bin/env node\n",
	})
	registry, _ := pnpmRegistry(t, map[string][]byte{preparePnpm: tarball})
	index := newUvIndex(t, uvUploaded)

	root := t.TempDir()
	logs := &syncBuffer{}
	m := NewManager(fakeVolume{root: root, settings: store.Settings{MinReleaseAgeDays: 14}}, &http.Client{Timeout: 10 * time.Second}, nil)
	m.GitHubAPI = gh.srv.URL
	m.NPMRegistry = registry.URL
	m.PipIndex = index.URL()
	m.Arch = "amd64"
	m.Trivy = gh.pin
	db := &fakeDB{root: root, at: time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)}
	p := NewPreparer(m, db, func() string { return prepareKey }, preparePnpm, uvTestVersion, slog.New(slog.NewJSONHandler(logs, nil)))
	p.RetryEvery = 10 * time.Millisecond
	return &preparation{p: p, m: m, db: db, root: root, logs: logs}
}

// run starts the preparer and stops it when the test ends.
func (pr *preparation) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); pr.p.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

// waitState polls the preparer until ok holds, and fails the test with the
// last state after five seconds.
func waitState(t *testing.T, p *Preparer, what string, ok func(Readiness) bool) Readiness {
	t.Helper()
	var r Readiness
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if r = p.State(); ok(r) {
			return r
		}
	}
	t.Fatalf("never %s; last state %+v", what, r)
	return r
}

func item(r Readiness, name string) Item {
	for _, it := range r.Items {
		if it.Name == name {
			return it
		}
	}
	return Item{}
}

func isReady(r Readiness) bool { return r.Ready }

func TestPreparerBecomesReadyWhenEveryItemIs(t *testing.T) {
	pr := newPreparation(t, monthOld)
	if r := pr.p.State(); r.Ready {
		t.Fatalf("State before Run = %+v, want not ready", r)
	}
	pr.run(t)
	r := waitState(t, pr.p, "ready", isReady)

	want := []Item{
		{Name: "trivy", Version: trivyTestVersion, State: ItemReady},
		{Name: "trivy-db", Version: "2026-11-23T06:00:00Z", State: ItemReady},
		{Name: "signing-key", Version: prepareKey, State: ItemReady},
		{Name: "pnpm", Version: preparePnpm, State: ItemReady},
		{Name: "uv", Version: uvTestVersion, State: ItemReady},
	}
	if len(r.Items) != len(want) {
		t.Fatalf("items = %+v, want %+v", r.Items, want)
	}
	for i, it := range r.Items {
		if it != want[i] {
			t.Errorf("item %d = %+v, want %+v", i, it, want[i])
		}
	}
	if r.Warning != "" {
		t.Errorf("warning = %q, want none", r.Warning)
	}
	if ready, missing := pr.m.Ready(); !ready {
		t.Errorf("the manager still misses %v once the preparer is ready", missing)
	}
	for _, path := range []string{"tools/pnpm/" + preparePnpm + "/package/bin/pnpm.cjs", "tools/uv/" + uvTestVersion + "/uv"} {
		if _, err := os.Stat(filepath.Join(pr.root, path)); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestPreparerKeepsTheCauseAndRetries(t *testing.T) {
	pr := newPreparation(t, monthOld)
	pr.db.fail = func(call int) error {
		if call == 1 {
			return errors.New("database download failed: 429 Too Many Requests")
		}
		return nil
	}
	pr.db.hold = make(chan struct{})
	pr.run(t)

	start := time.Now()
	r := waitState(t, pr.p, "a failed database", func(r Readiness) bool { return item(r, "trivy-db").State == ItemFailed })
	db := item(r, "trivy-db")
	if !strings.Contains(db.Reason, "429 Too Many Requests") {
		t.Errorf("reason = %q, want the download's cause", db.Reason)
	}
	if db.NextTry.Before(start) {
		t.Errorf("next try = %v, want one after the failure", db.NextTry)
	}
	if r.Ready {
		t.Error("ready while the database failed")
	}
	logged := false
	for line := range strings.Lines(pr.logs.String()) {
		var entry struct{ Item, Cause string }
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Item == "trivy-db" && strings.Contains(entry.Cause, "429 Too Many Requests") {
			logged = true
		}
	}
	if !logged {
		t.Errorf("no log line names the database's cause:\n%s", pr.logs.String())
	}

	close(pr.db.hold)
	waitState(t, pr.p, "ready after the retry", isReady)
	if n := pr.db.callCount(); n != 2 {
		t.Errorf("database tried %d times, want 2", n)
	}
	if got := item(pr.p.State(), "trivy-db"); got.Reason != "" || !got.NextTry.IsZero() {
		t.Errorf("ready database = %+v, want no cause and no next try", got)
	}
}

func TestPreparerReadyWithAWarningWhenARefreshFailsOnAnExistingDatabase(t *testing.T) {
	pr := newPreparation(t, monthOld)
	plantTrivyDB(t, pr.root, time.Date(2026, 11, 2, 6, 0, 0, 0, time.UTC))
	pr.db.fail = func(int) error { return errors.New("connection reset by peer") }
	pr.run(t)

	r := waitState(t, pr.p, "ready", isReady)
	if db := item(r, "trivy-db"); db.State != ItemReady || db.Version != "2026-11-02T06:00:00Z" {
		t.Errorf("database = %+v, want ready with the existing database's date", db)
	}
	for _, part := range []string{"connection reset by peer", "2026-11-02"} {
		if !strings.Contains(r.Warning, part) {
			t.Errorf("warning = %q, want it to hold %q", r.Warning, part)
		}
	}
}

func TestPreparerStaysNotReadyWithoutADatabase(t *testing.T) {
	cases := map[string]func(int) error{
		"the refresh fails":              func(int) error { return errors.New("connection reset by peer") },
		"the refresh leaves no database": nil,
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			pr := newPreparation(t, monthOld)
			db := &noDatabase{fail: fail}
			pr.p.db = db
			pr.run(t)
			waitState(t, pr.p, "three tries", func(Readiness) bool { return db.callCount() >= 3 })
			r := pr.p.State()
			if r.Ready {
				t.Fatalf("ready with no database: %+v", r)
			}
			if got := item(r, "trivy-db"); got.State != ItemFailed || got.Reason == "" {
				t.Errorf("database = %+v, want failed with a cause", got)
			}
		})
	}
}

// noDatabase is a database download that writes nothing, and fails when
// fail is set.
type noDatabase struct {
	fail  func(int) error
	mu    sync.Mutex
	calls int
}

func (d *noDatabase) UpdateDB(context.Context) (string, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	if d.fail != nil {
		return "", d.fail(call)
	}
	return "", nil
}

func (d *noDatabase) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func TestPreparerCutsAndStripsACause(t *testing.T) {
	const token = "ghp_plantedTokenValue0123456789"
	pr := newPreparation(t, monthOld)
	pr.m.GitHubToken = token
	cause := strings.Repeat("x", 100) + "\x1b[31m Bearer " + token + "\x00\x07 line\nbreak \u202edone " + strings.Repeat("y", 2048)
	pr.db.fail = func(int) error { return errors.New(cause) }
	pr.run(t)

	r := waitState(t, pr.p, "a failed database", func(r Readiness) bool { return item(r, "trivy-db").State == ItemFailed })
	reason := item(r, "trivy-db").Reason
	if n := utf8.RuneCountInString(reason); n > 300 {
		t.Errorf("reason holds %d characters, want 300 at most", n)
	}
	if !strings.Contains(reason, strings.Repeat("x", 100)+"[31m Bearer [redacted] line break done y") {
		t.Errorf("reason = %q, want the cause's start, stripped", reason)
	}
	if strings.Contains(reason, token) {
		t.Errorf("reason = %q holds the token", reason)
	}
	for _, c := range reason {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			t.Errorf("reason = %q holds the control character %U", reason, c)
		}
	}
	if strings.Contains(pr.logs.String(), token) {
		t.Error("the log holds the token")
	}
}

func TestPreparerNamesAYoungUvAsTheCause(t *testing.T) {
	pr := newPreparation(t, time.Now().Add(-24*time.Hour))
	pr.run(t)

	r := waitState(t, pr.p, "a failed uv", func(r Readiness) bool { return item(r, "uv").State == ItemFailed })
	reason := item(r, "uv").Reason
	for _, part := range []string{"uv " + uvTestVersion, "minimum release age of 14 days"} {
		if !strings.Contains(reason, part) {
			t.Errorf("reason = %q, want it to hold %q", reason, part)
		}
	}
	r = waitState(t, pr.p, "every other item ready", func(r Readiness) bool {
		return item(r, "trivy-db").State == ItemReady && item(r, "pnpm").State == ItemReady
	})
	if r.Ready {
		t.Error("ready with a uv too young to install")
	}
}

func TestPreparerStopsWithItsContext(t *testing.T) {
	pr := newPreparation(t, monthOld)
	pr.db.fail = func(int) error { return errors.New("unreachable") }
	pr.p.RetryEvery = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); pr.p.Run(ctx) }()
	waitState(t, pr.p, "a failed database", func(r Readiness) bool { return item(r, "trivy-db").State == ItemFailed })

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestPreparerRedactsTheRegistryCredentials(t *testing.T) {
	cases := map[string]struct {
		userinfo string
		secrets  []string
	}{
		"a percent-encoded password": {"user:s3cr%40t", []string{"s3cr%40t", "s3cr@t", "user"}},
		"a token as the username":    {"npmTok3nValue", []string{"npmTok3nValue"}},
		"an encoded username":        {"np%6dTok3n:pa55word", []string{"np%6dTok3n", "npmTok3n", "pa55word"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "down", http.StatusInternalServerError)
			}))
			t.Cleanup(failing.Close)
			pr := newPreparation(t, monthOld)
			pr.m.NPMRegistry = strings.Replace(failing.URL, "://", "://"+c.userinfo+"@", 1)
			pr.run(t)

			r := waitState(t, pr.p, "a failed pnpm", func(r Readiness) bool { return item(r, "pnpm").State == ItemFailed })
			reason := item(r, "pnpm").Reason
			if !strings.Contains(reason, "500 Internal Server Error") || !strings.Contains(reason, "[redacted]@127.0.0.1") {
				t.Errorf("reason = %q, want the registry's answer with its credentials redacted", reason)
			}
			logs := pr.logs.String()
			for _, secret := range c.secrets {
				if strings.Contains(reason, secret) {
					t.Errorf("reason = %q holds %q", reason, secret)
				}
				if strings.Contains(logs, secret) {
					t.Errorf("the log holds %q:\n%s", secret, logs)
				}
			}
		})
	}
}

func TestPreparerCutsAndStripsARefreshWarning(t *testing.T) {
	const token = "ghp_plantedTokenValue0123456789"
	pr := newPreparation(t, monthOld)
	pr.m.GitHubToken = token
	plantTrivyDB(t, pr.root, time.Date(2026, 11, 2, 6, 0, 0, 0, time.UTC))
	cause := strings.Repeat("x", 100) + "\x1b[31m Bearer " + token + "\x00\x07 line\nbreak \u202edone " + strings.Repeat("y", 2048)
	pr.db.fail = func(int) error { return errors.New(cause) }
	pr.run(t)

	r := waitState(t, pr.p, "ready", isReady)
	if n := utf8.RuneCountInString(r.Warning); n > 300 {
		t.Errorf("warning holds %d characters, want 300 at most", n)
	}
	if !strings.Contains(r.Warning, strings.Repeat("x", 100)+"[31m Bearer [redacted] line break done y") {
		t.Errorf("warning = %q, want the cause's start, stripped", r.Warning)
	}
	for _, c := range r.Warning {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			t.Errorf("warning = %q holds the control character %U", r.Warning, c)
		}
	}
	logs := pr.logs.String()
	if strings.Contains(logs, token) {
		t.Error("the log holds the token")
	}
	logged := false
	for line := range strings.Lines(logs) {
		var entry struct{ Msg, Cause string }
		if json.Unmarshal([]byte(line), &entry) != nil || entry.Msg != "vulnerability database not refreshed" {
			continue
		}
		logged = true
		if entry.Cause != r.Warning {
			t.Errorf("logged cause = %q, want the warning %q", entry.Cause, r.Warning)
		}
	}
	if !logged {
		t.Errorf("no log line reports the failed refresh:\n%s", logs)
	}
}

func TestPreparerWaitsForTheSigningKey(t *testing.T) {
	pr := newPreparation(t, monthOld)
	var mu sync.Mutex
	asked := 0
	present := false
	pr.p.keySHA256 = func() string {
		mu.Lock()
		defer mu.Unlock()
		asked++
		if present {
			return prepareKey
		}
		return ""
	}
	pr.run(t)

	waitState(t, pr.p, "three looks at the key", func(Readiness) bool {
		mu.Lock()
		defer mu.Unlock()
		return asked >= 3
	})
	r := pr.p.State()
	if r.Ready {
		t.Fatalf("ready without a signing key: %+v", r)
	}
	if key := item(r, "signing-key"); key.State != ItemFailed || key.Reason != "no signing key on the data volume" || key.NextTry.IsZero() {
		t.Errorf("signing key = %+v, want failed with its cause and a next try", key)
	}
	for _, name := range []string{"trivy", "trivy-db", "pnpm", "uv"} {
		if it := item(r, name); it.State != ItemPreparing {
			t.Errorf("%s = %+v, want still preparing while the key is missing", name, it)
		}
	}
	if n := pr.db.callCount(); n != 0 {
		t.Errorf("database downloaded %d times without a signing key, want none", n)
	}
	if _, err := os.Stat(filepath.Join(pr.root, "tools")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tools installed without a signing key (stat: %v)", err)
	}

	mu.Lock()
	present = true
	mu.Unlock()
	waitState(t, pr.p, "ready once the key exists", isReady)
}
