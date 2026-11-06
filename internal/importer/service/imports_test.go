package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/token"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

const (
	archiveKey  = base + "a/packages_npm.tar.gz"
	manifestKey = base + "a/manifest.json"
	otherKey    = base + "b/packages_npm.tar.gz"
	otherMan    = base + "b/manifest.json"
)

var leftPad = testPkg{"left-pad", "1.3.0"}

// expiring is a verifier whose tokens stop passing once expire is called.
type expiring struct {
	fakeVerifier
	expired bool
}

func (e *expiring) Verify(ctx context.Context, raw string) (token.Claims, error) {
	if e.expired {
		return nil, &token.Rejected{Check: "exp"}
	}
	return e.fakeVerifier.Verify(ctx, raw)
}

// importRig is a service with a real store and queue over a fake MinIO and a fake Nexus.
type importRig struct {
	rig
	minio    *fakeMinio
	nexus    *fakeNexus
	store    *imports.Store
	queue    *imports.Queue
	verifier *expiring
	data     string
	entered  chan string // import ids as their runs begin, when held
	release  chan struct{}
}

type rigOptions struct {
	links []string
	hold  bool // runs wait for the test before they read anything
	pkgs  []testPkg
}

func newImportRig(t *testing.T, o rigOptions) *importRig {
	t.Helper()
	if o.pkgs == nil {
		o.pkgs = []testPkg{leftPad}
	}
	nx, ca := newFakeNexus(t, o.pkgs...)
	r := &importRig{
		minio: newFakeMinio(), nexus: nx, data: filepath.Join(t.TempDir(), "data"),
		verifier: &expiring{fakeVerifier: fakeVerifier{claims: map[string]token.Claims{"t": named("alice"), "b": named("bob")}}},
		entered:  make(chan string, 16), release: make(chan struct{}),
	}
	st, err := imports.Open(r.data, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.store = st
	r.rig = newRigConfig(t, Config{
		Verifier: r.verifier, MinIO: r.minio, UnencryptedLinks: o.links,
		Store: st, Submit: func(user, id string) bool { return r.queue.Submit(user, id) },
		Settings: nx.settings(t, ca), NewPublisher: newPublisher, ImportVersion: "0.3.0",
	})
	run := func(ctx context.Context, imp imports.Import, dir string, p importer.Progress) (importer.Report, *imports.Removal) {
		if o.hold {
			r.entered <- imp.ID
			select {
			case <-r.release:
			case <-ctx.Done():
			}
		}
		return r.handlers.RunAttempt(ctx, imp, dir, p)
	}
	r.queue = imports.NewQueue(st, run, slog.New(slog.NewJSONHandler(r.logs, nil)))
	t.Cleanup(r.queue.Close)
	return r
}

// seed puts a bundle in alice's folder at the archive and manifest keys.
func (r *importRig) seed(archiveAt, manifestAt string, b testBundle) {
	r.minio.putData(archiveAt, b.archive)
	r.minio.putData(manifestAt, b.manifest)
}

func (r *importRig) post(tok, body string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/imports", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set(TokenHeader, tok)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return r.do(req)
}

func (r *importRig) start(tok, key string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(StartImport{Archive: key})
	return r.post(tok, string(b))
}

func importOf(t *testing.T, rec *httptest.ResponseRecorder, status int) Import {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	var imp Import
	if err := json.Unmarshal(rec.Body.Bytes(), &imp); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return imp
}

// waitEnded waits for the latest attempt of an import to end. It yields to
// the queue's goroutine and gives up after a generous deadline.
func waitEnded(t *testing.T, st *imports.Store, id string) imports.Import {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		imp, err := st.Get("alice", id)
		if err != nil {
			t.Fatal(err)
		}
		if a := imp.Attempts[len(imp.Attempts)-1]; a.Status == imports.StatusEnded {
			return imp
		}
		if time.Now().After(deadline) {
			t.Fatalf("import %s never ended: %s", id, imp.Outcome())
		}
		runtime.Gosched()
	}
}

func waitEntered(t *testing.T, r *importRig) string {
	t.Helper()
	select {
	case id := <-r.entered:
		return id
	case <-time.After(10 * time.Second):
		t.Fatal("no run began")
		return ""
	}
}

func TestStartAnswers202(t *testing.T) {
	r := newImportRig(t, rigOptions{hold: true})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))

	imp := importOf(t, r.start("t", archiveKey), http.StatusAccepted)
	if imp.Id == "" || imp.Archive.Key != archiveKey || imp.Manifest.Key != manifestKey {
		t.Fatalf("answer = %+v", imp)
	}
	stored, err := r.store.Get("alice", imp.Id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.User != "alice" || stored.Archive.ETag != r.minio.etagOf(archiveKey) || stored.Manifest.ETag != r.minio.etagOf(manifestKey) {
		t.Errorf("stored = %+v", stored)
	}
	if stored.Archive.Size != int64(len(buildBundle(t, leftPad).archive)) && stored.Archive.Size == 0 {
		t.Errorf("stored size = %d", stored.Archive.Size)
	}
	if got := waitEntered(t, r); got != imp.Id {
		t.Errorf("the run began for %s, want %s", got, imp.Id)
	}
	if list, _ := r.store.List("bob"); len(list) != 0 {
		t.Errorf("bob has %d imports", len(list))
	}
}

func TestStartExpectedSHA256(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)

	t.Run("a wrong value ends refused naming both digests", func(t *testing.T) {
		wrong := strings.Repeat("0", 64)
		rec := r.post("t", `{"archive":"`+archiveKey+`","expectedSha256":"`+strings.ToUpper(wrong)+`"}`)
		imp := waitEnded(t, r.store, importOf(t, rec, http.StatusAccepted).Id)
		a := imp.Attempts[0]
		if a.Outcome != importer.OutcomeRefused || !strings.Contains(a.Report.Reason, wrong) || !strings.Contains(a.Report.Reason, b.sha256) {
			t.Errorf("outcome %q, reason %q; want refused naming %s and %s", a.Outcome, a.Report.Reason, b.sha256, wrong)
		}
		if r.nexus.uploadCount() != 0 {
			t.Error("a refused archive was uploaded")
		}
	})
	for _, bad := range []string{"xyz", strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		t.Run("malformed "+bad[:3], func(t *testing.T) {
			before, _ := r.store.List("alice")
			rec := r.post("t", `{"archive":"`+archiveKey+`","expectedSha256":"`+bad+`"}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			problemOf(t, rec)
			if after, _ := r.store.List("alice"); len(after) != len(before) {
				t.Error("a malformed value created an import")
			}
		})
	}
}

func TestStartRefusesForeignKeys(t *testing.T) {
	for name, key := range map[string]string{
		"another prefix":    "packages/pip/a/packages_npm.tar.gz",
		"dot dot":           base + "../x/packages_npm.tar.gz",
		"leading slash":     "/" + archiveKey,
		"encoded dot dot":   base + "%2e%2e/packages_npm.tar.gz",
		"encoded slash":     base + "a%2f..%2fb%2fc.tar.gz",
		"another bucket":    "user-bob/" + archiveKey,
		"outside":           "other/packages_npm.tar.gz",
		"too deep":          base + "a/b/packages_npm.tar.gz",
		"wrong suffix":      base + "a/manifest.json",
		"empty":             "",
		"control character": base + "a/x\n.tar.gz",
	} {
		t.Run(name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			r.minio.calls = nil
			b, _ := json.Marshal(StartImport{Archive: key})
			rec := r.post("t", string(b))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			if p := problemOf(t, rec); key != "" && strings.Contains(detailOf(p), "bob") {
				t.Errorf("detail %q repeats the key", detailOf(p))
			}
			if calls := r.minio.recorded(); len(calls) != 0 {
				t.Errorf("%d MinIO calls for a foreign key: %+v", len(calls), calls)
			}
			if list, _ := r.store.List("alice"); len(list) != 0 {
				t.Error("a foreign key created an import")
			}
		})
	}
}

func TestStartAnswers404ForAnObjectThatIsNotThere(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	rec := r.start("t", base+"a/other.tar.gz")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	problemOf(t, rec)
	if rec := r.start("b", archiveKey); rec.Code != http.StatusNotFound {
		t.Errorf("bob started alice's key: status %d, want 404", rec.Code)
	}
}

func TestStartRefusesAnAmbiguousFolder(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)
	r.minio.putData(base+"a/second.tar.gz", b.archive)
	rec := r.start("t", archiveKey)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), reasonSeveral) {
		t.Errorf("body %s does not say %q", rec.Body, reasonSeveral)
	}
}

func TestStartRefusesCrossSite(t *testing.T) {
	good := `{"archive":"` + archiveKey + `"}`
	tests := []struct {
		name   string
		header []string
		want   int
	}{
		{"foreign origin", []string{"Origin", "https://evil.example"}, http.StatusForbidden},
		{"origin with another port", []string{"Origin", "http://example.com:8081"}, http.StatusForbidden},
		{"null origin", []string{"Origin", "null"}, http.StatusForbidden},
		{"unreadable origin", []string{"Origin", "http://%zz"}, http.StatusForbidden},
		{"cross-site fetch", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"plain text", []string{"Content-Type", "text/plain"}, http.StatusForbidden},
		{"form", []string{"Content-Type", "application/x-www-form-urlencoded"}, http.StatusForbidden},
		{"no content type", []string{"Content-Type", ""}, http.StatusForbidden},
		{"own origin", []string{"Origin", "http://example.com"}, http.StatusAccepted},
		{"own origin in capitals", []string{"Origin", "http://EXAMPLE.com"}, http.StatusAccepted},
		{"same-origin fetch", []string{"Sec-Fetch-Site", "same-origin"}, http.StatusAccepted},
		{"a client with no origin", nil, http.StatusAccepted},
		{"json with a charset", []string{"Content-Type", "application/json; charset=utf-8"}, http.StatusAccepted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{hold: true})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			r.minio.calls = nil
			rec := r.post("t", good, tt.header...)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.want, rec.Body)
			}
			list, _ := r.store.List("alice")
			if tt.want == http.StatusForbidden {
				p := problemOf(t, rec)
				if len(list) != 0 || len(r.minio.recorded()) != 0 {
					t.Errorf("a refused request left %d imports and %d MinIO calls", len(list), len(r.minio.recorded()))
				}
				if d := detailOf(p); strings.Contains(d, "evil") || strings.Contains(d, "%zz") {
					t.Errorf("detail %q repeats the request", d)
				}
			} else if len(list) != 1 {
				t.Errorf("%d imports, want 1", len(list))
			}
		})
	}
	t.Run("a read is not guarded", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		if rec := r.get("/api/imports", "t", "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site"); rec.Code != http.StatusOK {
			t.Errorf("GET status = %d, want 200", rec.Code)
		}
	})
}

func TestStartConflicts409(t *testing.T) {
	r := newImportRig(t, rigOptions{hold: true})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)
	r.seed(otherKey, otherMan, b)

	running := importOf(t, r.start("t", archiveKey), http.StatusAccepted)
	waitEntered(t, r)
	queued := importOf(t, r.start("t", otherKey), http.StatusAccepted)

	conflictID := func(key string) string {
		t.Helper()
		rec := r.start("t", key)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body)
		}
		var c ImportConflict
		if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || c.ImportId == nil {
			t.Fatalf("body %q: %v", rec.Body, err)
		}
		return *c.ImportId
	}
	if got := conflictID(archiveKey); got != running.Id {
		t.Errorf("running archive: 409 names %s, want %s", got, running.Id)
	}
	if got := conflictID(otherKey); got != queued.Id {
		t.Errorf("queued archive: 409 names %s, want %s", got, queued.Id)
	}

	// Cut the archive so the first attempt ends incomplete.
	r.minio.mu.Lock()
	r.minio.cut[dataKey("user-alice", archiveKey)] = len(b.archive) / 2
	r.minio.mu.Unlock()
	close(r.release)
	first := waitEnded(t, r.store, running.Id)
	if first.Outcome() != importer.OutcomeIncomplete {
		t.Fatalf("first outcome %q, want incomplete", first.Outcome())
	}
	if got := conflictID(archiveKey); got != running.Id {
		t.Errorf("incomplete archive: 409 names %s, want %s", got, running.Id)
	}

	// The second import completes; a new start of it is accepted.
	done := waitEnded(t, r.store, queued.Id)
	if done.Outcome() != importer.OutcomeComplete {
		t.Fatalf("second outcome %q (%s), want complete", done.Outcome(), done.Attempts[0].Report.Reason)
	}
	// The complete import removed its archive; a user uploads it again.
	r.seed(otherKey, otherMan, b)
	again := importOf(t, r.start("t", otherKey), http.StatusAccepted)
	if again.Id == queued.Id {
		t.Error("the new start reused the finished import's id")
	}

	// An archive replaced in MinIO is another archive: its ETag differs.
	r.minio.change(archiveKey)
	importOf(t, r.start("t", archiveKey), http.StatusAccepted)
}

func TestImportOutcomes(t *testing.T) {
	good := buildBundle(t, leftPad, testPkg{"zeta", "2.0.0"})
	flipped := buildBundle(t, leftPad, testPkg{"zeta", "2.0.0"})
	flipped.archive = append([]byte(nil), flipped.archive...)
	flipped.archive[len(flipped.archive)/2] ^= 0xff

	tests := []struct {
		name      string
		bundle    testBundle
		cut       int
		outcome   string
		reasonHas string
		failed    int
		uploads   int
	}{
		{"complete", good, 0, importer.OutcomeComplete, "", 0, 2},
		{"refused", flipped, 0, importer.OutcomeRefused, "", 0, 0},
		{"cut in half", good, len(good.archive) / 2, importer.OutcomeIncomplete, "", 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, {"zeta", "2.0.0"}}})
			r.seed(archiveKey, manifestKey, tt.bundle)
			if tt.cut > 0 {
				r.minio.cut[dataKey("user-alice", archiveKey)] = tt.cut
			}
			start := importOf(t, r.start("t", archiveKey), http.StatusAccepted)
			waitEnded(t, r.store, start.Id)

			got := importOf(t, r.get("/api/imports/"+start.Id, "t"), http.StatusOK)
			wantRemoved := tt.outcome == importer.OutcomeComplete
			if got.Outcome != tt.outcome || got.ArchiveRemoved != wantRemoved {
				t.Fatalf("outcome %q removed %v, want %q and removed %v", got.Outcome, got.ArchiveRemoved, tt.outcome, wantRemoved)
			}
			a := got.Attempts[0]
			if a.Status != "ended" || a.Outcome != tt.outcome || a.Report.Outcome != tt.outcome || a.EndedAt == nil {
				t.Errorf("attempt = %+v", a)
			}
			if a.Report.Counts.Failed != tt.failed || r.nexus.uploadCount() != tt.uploads {
				t.Errorf("failed %d, uploads %d; want %d and %d", a.Report.Counts.Failed, r.nexus.uploadCount(), tt.failed, tt.uploads)
			}
			switch tt.outcome {
			case importer.OutcomeComplete:
				if a.Report.Counts.Published != 2 || len(a.Report.Packages) != 2 || a.Report.Packages[0].State != "published" {
					t.Errorf("report = %+v", a.Report)
				}
			case importer.OutcomeRefused:
				if !strings.Contains(a.Report.Reason, "differs") {
					t.Errorf("reason %q", a.Report.Reason)
				}
			case importer.OutcomeIncomplete:
				for _, p := range a.Report.Packages {
					if p.State != "failed" || p.Reason == "" {
						t.Errorf("package %+v, want failed with a reason", p)
					}
				}
			}
			_, inMinio := r.minio.buckets["user-alice"][archiveKey]
			if inMinio == wantRemoved {
				t.Errorf("the archive is in MinIO: %v, removed: %v", inMinio, wantRemoved)
			}
			if d := r.deletes(); !wantRemoved && len(d) != 0 {
				t.Errorf("deletes reached MinIO: %v", d)
			}
		})
	}
}

func TestImportOfAnotherUser(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	waitEnded(t, r.store, id)

	for name, tc := range map[string]struct{ tok, id string }{
		"bob reads alice's import": {"b", id},
		"a missing id":             {"t", "20260101T000000Z-00000000"},
		"a malformed id":           {"t", "..%2f..%2fx"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := r.get("/api/imports/"+tc.id, tc.tok)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			problemOf(t, rec)
			if strings.Contains(rec.Body.String(), id) {
				t.Errorf("body %q repeats the id", rec.Body)
			}
		})
	}
	if list := listOfImports(t, r.get("/api/imports", "b")); len(list.Imports) != 0 {
		t.Errorf("bob lists %d imports", len(list.Imports))
	}
}

func TestMalformedImportParameterIsAProblem(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	// A string parameter always binds, so a malformed id reaches the store and answers 404.
	for _, path := range []string{"/api/imports/%25zz-secret", "/api/imports/%00secret", "/api/imports/secret%0d%0ainjected"} {
		rec := r.get(path, "t")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, rec.Code)
		}
		problemOf(t, rec)
		if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "zz") {
			t.Errorf("body %q repeats the value", rec.Body)
		}
	}
}

func TestBadParameterRepeatsNothing(t *testing.T) {
	rec := httptest.NewRecorder()
	badParameter(rec, httptest.NewRequest(http.MethodGet, "/api/imports/x", nil), &InvalidParamFormatError{ParamName: "importId", Err: errors.New("bad value secret-value")})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	problemOf(t, rec)
	if strings.Contains(rec.Body.String(), "secret-value") {
		t.Errorf("body %q repeats the value", rec.Body)
	}
}

func listOfImports(t *testing.T, rec *httptest.ResponseRecorder) ImportList {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var l ImportList
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return l
}

func TestListShowsLatestImport(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)
	r.seed(otherKey, otherMan, b)
	if got := byKey(listOf(t, r.get("/api/archives", "t")))[archiveKey]; got.LatestImport != nil {
		t.Fatalf("latestImport before any import = %+v", got.LatestImport)
	}

	r.minio.cut[dataKey("user-alice", archiveKey)] = len(b.archive) / 2
	first := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	waitEnded(t, r.store, first)
	list := byKey(listOf(t, r.get("/api/archives", "t")))
	if li := list[archiveKey].LatestImport; li == nil || li.Id != first || li.Outcome != importer.OutcomeIncomplete {
		t.Errorf("latestImport = %+v, want %s incomplete", li, first)
	}
	if list[otherKey].LatestImport != nil {
		t.Error("an archive with no import shows one")
	}

	// A new ETag is a new archive and a new import. The store orders by whole
	// seconds, so two imports made within one second may come in either order.
	delete(r.minio.cut, dataKey("user-alice", archiveKey))
	r.minio.change(archiveKey)
	r.minio.failDelete[archiveKey] = errors.New("kept for the listing")
	second := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	waitEnded(t, r.store, second)
	want := map[string]string{first: importer.OutcomeIncomplete, second: importer.OutcomeComplete}
	if li := byKey(listOf(t, r.get("/api/archives", "t")))[archiveKey].LatestImport; li == nil || want[li.Id] != li.Outcome || li.Outcome == "" {
		t.Errorf("latestImport = %+v, want one of %v", li, want)
	}
	imps := listOfImports(t, r.get("/api/imports", "t")).Imports
	if got := ids(imps); len(got) != 2 || want[got[0]] == "" || want[got[1]] == "" || got[0] == got[1] {
		t.Errorf("imports = %v, want %s and %s", got, first, second)
	}
	if bobs := byKey(listOf(t, r.get("/api/archives", "b"))); len(bobs) != 0 {
		t.Errorf("bob sees %d archives", len(bobs))
	}
}

// A listed archive shows an import only when that import read the objects
// now in MinIO: the folder's names stay the same from one export to the next.
func TestListLatestImportNeedsTheSameObjects(t *testing.T) {
	for name, replaced := range map[string]string{"archive": archiveKey, "manifest": manifestKey} {
		t.Run(name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			r.minio.failDelete[archiveKey] = errors.New("kept for the listing")
			first := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
			if done := waitEnded(t, r.store, first); done.Outcome() != importer.OutcomeComplete {
				t.Fatalf("outcome %q, want complete", done.Outcome())
			}
			if li := byKey(listOf(t, r.get("/api/archives", "t")))[archiveKey].LatestImport; li == nil || li.Id != first {
				t.Fatalf("latestImport = %+v, want %s", li, first)
			}

			r.minio.change(replaced)
			if li := byKey(listOf(t, r.get("/api/archives", "t")))[archiveKey].LatestImport; li != nil {
				t.Errorf("latestImport = %+v after the %s was replaced, want none", li, name)
			}

			second := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
			waitEnded(t, r.store, second)
			if li := byKey(listOf(t, r.get("/api/archives", "t")))[archiveKey].LatestImport; li == nil || li.Id != second {
				t.Errorf("latestImport = %+v, want the new import %s", li, second)
			}
		})
	}
}

// A manifest replaced between the start and the run refuses that import. The
// next start is another import of the objects now in MinIO, not a 409.
func TestChangedManifestAllowsANewStart(t *testing.T) {
	r := newImportRig(t, rigOptions{hold: true})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	first := importOf(t, r.start("t", archiveKey), http.StatusAccepted)
	waitEntered(t, r)
	r.minio.change(manifestKey)
	close(r.release)
	done := waitEnded(t, r.store, first.Id)
	if done.Outcome() != importer.OutcomeRefused || done.Attempts[0].Report.Reason != "the manifest changed in MinIO; start a new import" {
		t.Fatalf("outcome %q, reason %q; want refused naming the manifest", done.Outcome(), done.Attempts[0].Report.Reason)
	}

	second := importOf(t, r.start("t", archiveKey), http.StatusAccepted)
	if second.Id == first.Id {
		t.Error("the new start reused the refused import")
	}
	if got := waitEnded(t, r.store, second.Id).Outcome(); got != importer.OutcomeComplete {
		t.Errorf("second outcome %q, want complete", got)
	}
}

func ids(imps []Import) []string {
	out := []string{}
	for _, i := range imps {
		out = append(out, i.Id)
	}
	return out
}

func TestImportOutlivesTheToken(t *testing.T) {
	r := newImportRig(t, rigOptions{hold: true})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	waitEntered(t, r)

	r.verifier.expired = true
	if rec := r.get("/api/imports/"+id, "t"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET with the expired token = %d, want 401", rec.Code)
	}
	close(r.release)
	done := waitEnded(t, r.store, id)
	if done.Outcome() != importer.OutcomeComplete {
		t.Errorf("outcome %q (%s), want complete", done.Outcome(), done.Attempts[0].Report.Reason)
	}
}

func TestReportMarksUnencryptedLinks(t *testing.T) {
	for name, links := range map[string][]string{"none": nil, "minio": {"minio"}, "key set": {"keySet"}} {
		t.Run(name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{links: links})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
			waitEnded(t, r.store, id)
			got := importOf(t, r.get("/api/imports/"+id, "t"), http.StatusOK)
			if want := len(links) > 0; got.Attempts[0].Report.Unencrypted != want {
				t.Errorf("unencrypted = %v, want %v", got.Attempts[0].Report.Unencrypted, want)
			}
		})
	}
}

func TestImportFlowNeverLeaksCredentials(t *testing.T) {
	r := newImportRig(t, rigOptions{links: []string{"minio"}})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)
	r.seed(otherKey, otherMan, b)
	r.minio.cut[dataKey("user-alice", otherKey)] = len(b.archive) / 2

	var seen strings.Builder
	record := func(rec *httptest.ResponseRecorder) {
		seen.WriteString(rec.Body.String())
		for k, v := range rec.Header() {
			seen.WriteString(k + strings.Join(v, ""))
		}
	}
	for _, key := range []string{archiveKey, otherKey} {
		rec := r.start("t", key)
		record(rec)
		id := importOf(t, rec, http.StatusAccepted).Id
		waitEnded(t, r.store, id)
		record(r.get("/api/imports/"+id, "t", "Authorization", "Bearer t"))
	}
	record(r.get("/api/imports", "t"))
	record(r.get("/api/archives", "t"))
	record(r.start("t", archiveKey))
	seen.WriteString(r.logs.String())
	err := filepath.WalkDir(r.data, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		seen.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testMinioKey, testPassword, testSigKey, "test-access-id", "Bearer"} {
		if strings.Contains(seen.String(), secret) {
			t.Errorf("a response, the log or a file under -data holds %q", secret)
		}
	}
	if !strings.Contains(seen.String(), "outcome") || r.logs.Len() == 0 {
		t.Error("nothing was scanned")
	}
}
