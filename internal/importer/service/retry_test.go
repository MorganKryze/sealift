package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/store/imports"
	"github.com/MorganKryze/sealift/npm"
)

var zeta = testPkg{"zeta", "2.0.0"}

func (r *importRig) retry(tok, id string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/imports/"+id+"/retry", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set(TokenHeader, tok)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return r.do(req)
}

// endedImport records an import of alice's whose only attempt ended with the
// outcome, without running anything. Its objects carry MinIO's current ETags.
func (r *importRig) endedImport(t *testing.T, outcome string) string {
	t.Helper()
	imp, err := r.store.Create("alice",
		imports.Object{Key: archiveKey, ETag: r.minio.etagOf(archiveKey), Size: 1},
		imports.Object{Key: manifestKey, ETag: r.minio.etagOf(manifestKey), Size: 1},
		&imports.Object{Key: signatureKey, ETag: r.minio.etagOf(signatureKey), Size: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.store.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	rep := importer.Report{Outcome: outcome, Reason: "earlier " + outcome, Packages: []importer.Result{}}
	if err := r.store.Finish("alice", imp.ID, 1, rep, nil); err != nil {
		t.Fatal(err)
	}
	return imp.ID
}

func (r *importRig) deletes() []string {
	var keys []string
	for _, c := range r.minio.recorded() {
		if c.Op == "delete" {
			keys = append(keys, c.Key)
		}
	}
	return keys
}

// completeKept runs an import to a complete end whose archive delete fails, so the archive stays.
func (r *importRig) completeKept(t *testing.T) string {
	t.Helper()
	r.minio.failDelete[archiveKey] = errors.New("storage busy")
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	if got := waitEnded(t, r.store, id); got.Outcome() != importer.OutcomeComplete || got.ArchiveRemoved() {
		t.Fatalf("setup: outcome %q removed %v", got.Outcome(), got.ArchiveRemoved())
	}
	delete(r.minio.failDelete, archiveKey)
	return id
}

func TestRetryAccepted(t *testing.T) {
	for _, outcome := range []string{"complete, archive kept", importer.OutcomeIncomplete, importer.OutcomeRefused, imports.OutcomeInterrupted} {
		t.Run(outcome, func(t *testing.T) {
			r := newImportRig(t, rigOptions{})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			var id string
			if strings.HasPrefix(outcome, "complete") {
				id = r.completeKept(t)
			} else {
				id = r.endedImport(t, outcome)
			}
			imp := importOf(t, r.retry("t", id), http.StatusAccepted)
			if imp.Id != id || len(imp.Attempts) != 2 || imp.Attempts[1].N != 2 {
				t.Fatalf("answer = %+v", imp)
			}
			if imp.Attempts[0].Report.Reason == "" && outcome != "complete, archive kept" {
				t.Errorf("the earlier attempt lost its report: %+v", imp.Attempts[0])
			}
			done := waitEnded(t, r.store, id)
			if done.Outcome() != importer.OutcomeComplete || !done.ArchiveRemoved() {
				t.Errorf("after the retry: outcome %q (%s) removed %v", done.Outcome(), done.Attempts[1].Report.Reason, done.ArchiveRemoved())
			}
		})
	}
}

func TestRetryConflicts409(t *testing.T) {
	t.Run("an attempt running or queued", func(t *testing.T) {
		r := newImportRig(t, rigOptions{hold: true})
		b := buildBundle(t, leftPad)
		r.seed(archiveKey, manifestKey, b)
		r.seed(otherKey, otherMan, b)
		running := importOf(t, r.start("t", archiveKey), http.StatusAccepted)
		waitEntered(t, r)
		queued := importOf(t, r.start("t", otherKey), http.StatusAccepted)
		for name, id := range map[string]string{"running": running.Id, "queued": queued.Id} {
			rec := r.retry("t", id)
			if rec.Code != http.StatusConflict {
				t.Fatalf("%s: status = %d, want 409; body %s", name, rec.Code, rec.Body)
			}
			if d := detailOf(problemOf(t, rec)); !strings.Contains(d, "queued or running") {
				t.Errorf("%s: detail %q", name, d)
			}
			got, _ := r.store.Get("alice", id)
			if len(got.Attempts) != 1 {
				t.Errorf("%s: a refused retry left %d attempts", name, len(got.Attempts))
			}
		}
		close(r.release)
	})

	t.Run("the archive is no longer in MinIO", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
		id := r.endedImport(t, importer.OutcomeIncomplete)
		r.minio.mu.Lock()
		delete(r.minio.buckets[bucketAlice], archiveKey)
		r.minio.mu.Unlock()
		rec := r.retry("t", id)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body)
		}
		if d := detailOf(problemOf(t, rec)); d != "the archive is no longer in MinIO" {
			t.Errorf("detail %q", d)
		}
		if got, _ := r.store.Get("alice", id); len(got.Attempts) != 1 {
			t.Errorf("a refused retry left %d attempts", len(got.Attempts))
		}
	})

	t.Run("another user's import is not found", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
		id := r.endedImport(t, importer.OutcomeIncomplete)
		if rec := r.retry("b", id); rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
		if rec := r.retry("t", "nope"); rec.Code != http.StatusNotFound {
			t.Errorf("bad id: status = %d, want 404", rec.Code)
		}
	})

	t.Run("a service with no MinIO", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.handlers.objects = nil
		rec := r.retry("t", r.endedImport(t, importer.OutcomeIncomplete))
		if rec.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409", rec.Code)
		}
	})
}

func TestRetryRefusesCrossSite(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		want   int
	}{
		{"foreign origin", []string{"Origin", "https://evil.example"}, http.StatusForbidden},
		{"null origin", []string{"Origin", "null"}, http.StatusForbidden},
		{"cross-site fetch", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"plain text", []string{"Content-Type", "text/plain"}, http.StatusForbidden},
		{"own origin", []string{"Origin", "http://example.com"}, http.StatusAccepted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{hold: true})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			id := r.endedImport(t, importer.OutcomeIncomplete)
			r.minio.mu.Lock()
			r.minio.calls = nil
			r.minio.mu.Unlock()
			rec := r.retry("t", id, tt.header...)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.want, rec.Body)
			}
			got, _ := r.store.Get("alice", id)
			if tt.want == http.StatusForbidden {
				problemOf(t, rec)
				if len(got.Attempts) != 1 || len(r.minio.recorded()) != 0 {
					t.Errorf("a refused request left %d attempts and %d MinIO calls", len(got.Attempts), len(r.minio.recorded()))
				}
			} else if len(got.Attempts) != 2 {
				t.Errorf("%d attempts, want 2", len(got.Attempts))
			}
		})
	}
}

func TestRetryArchiveChanged(t *testing.T) {
	for _, tt := range []struct{ name, key, reason string }{
		{"archive", archiveKey, "the archive changed in MinIO; start a new import"},
		{"manifest", manifestKey, "the manifest changed in MinIO; start a new import"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			id := r.endedImport(t, importer.OutcomeIncomplete)
			r.minio.change(tt.key)
			importOf(t, r.retry("t", id), http.StatusAccepted)
			done := waitEnded(t, r.store, id)
			a := done.Attempts[1]
			if a.Outcome != importer.OutcomeRefused || a.Report.Reason != tt.reason {
				t.Errorf("attempt 2: outcome %q reason %q; want refused %q", a.Outcome, a.Report.Reason, tt.reason)
			}
			if n := r.nexus.uploadCount(); n != 0 {
				t.Errorf("%d uploads, want 0", n)
			}
			if d := r.deletes(); len(d) != 0 {
				t.Errorf("deletes %v after a refusal", d)
			}
		})
	}
}

// twoPackages runs an import of two packages whose archive stays, ready to retry.
func twoPackages(t *testing.T) (*importRig, string) {
	t.Helper()
	r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad, zeta))
	return r, r.completeKept(t)
}

func TestRetryReadsEveryPackage(t *testing.T) {
	r, id := twoPackages(t)
	before := map[testPkg]int{leftPad: r.nexus.readCount(leftPad), zeta: r.nexus.readCount(zeta)}
	if first := waitEnded(t, r.store, id); first.Attempts[0].Report.Counts.Published != 2 {
		t.Fatalf("attempt 1 report = %+v", first.Attempts[0].Report.Counts)
	}
	importOf(t, r.retry("t", id), http.StatusAccepted)
	done := waitEnded(t, r.store, id)
	a := done.Attempts[1]
	if a.Outcome != importer.OutcomeComplete || a.Report.Counts.Present != 2 || a.Report.Counts.Published != 0 {
		t.Fatalf("attempt 2 = %s %+v", a.Outcome, a.Report.Counts)
	}
	for p, was := range before {
		if r.nexus.readCount(p) <= was {
			t.Errorf("%s: Nexus was not read again in the retry (%d reads before, %d after)", p.name, was, r.nexus.readCount(p))
		}
	}
	if !done.ArchiveRemoved() {
		t.Error("the archive stayed after a complete retry")
	}
}

func TestRetryRepublishesWhatNexusLost(t *testing.T) {
	r, id := twoPackages(t)
	uploads := r.nexus.uploadCount()
	r.nexus.lose(zeta)
	importOf(t, r.retry("t", id), http.StatusAccepted)
	done := waitEnded(t, r.store, id)
	a := done.Attempts[1]
	states := map[string]importer.State{}
	for _, p := range a.Report.Packages {
		states[p.Name] = p.State
	}
	if a.Outcome != importer.OutcomeComplete || states["left-pad"] != importer.Present || states["zeta"] != importer.Published {
		t.Errorf("attempt 2 = %s %v", a.Outcome, states)
	}
	if got := r.nexus.uploadCount() - uploads; got != 1 {
		t.Errorf("the retry uploaded %d packages, want 1", got)
	}
}

func TestCompleteRemovesBoth(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	done := waitEnded(t, r.store, id)
	if done.Outcome() != importer.OutcomeComplete {
		t.Fatalf("outcome %q (%s)", done.Outcome(), done.Attempts[0].Report.Reason)
	}
	if d := r.deletes(); len(d) != 3 || d[0] != archiveKey || d[1] != manifestKey || d[2] != signatureKey {
		t.Fatalf("deletes = %v, want the archive, the manifest, then the signature", d)
	}
	// All three objects are headed after the last read and before the first delete.
	calls := r.minio.recorded()
	firstDelete, heads := -1, map[string]bool{}
	lastGet := -1
	for i, c := range calls {
		switch c.Op {
		case "get":
			lastGet = i
		case "delete":
			if firstDelete < 0 {
				firstDelete = i
			}
		case "head":
			if firstDelete < 0 && i > lastGet && lastGet >= 0 {
				heads[c.Key] = true
			}
		}
	}
	if !heads[archiveKey] || !heads[manifestKey] || !heads[signatureKey] {
		t.Errorf("the objects were not all headed between the read and the delete: %v", heads)
	}
	if _, ok := r.minio.buckets[bucketAlice][archiveKey]; ok {
		t.Error("the archive is still in MinIO")
	}
	if _, ok := r.minio.buckets[bucketAlice][manifestKey]; ok {
		t.Error("the manifest is still in MinIO")
	}
	if _, ok := r.minio.buckets[bucketAlice][signatureKey]; ok {
		t.Error("the signature is still in MinIO")
	}
	got := importOf(t, r.get("/api/imports/"+id, "t"), http.StatusOK)
	a := got.Attempts[0]
	if !got.ArchiveRemoved || a.Removal == nil || !a.Removal.Removed || a.Removal.Reason != "" {
		t.Errorf("removed %v, removal %+v", got.ArchiveRemoved, a.Removal)
	}
	if len(a.Report.Packages) != 1 || a.Report.Packages[0].State != "published" || got.Outcome != importer.OutcomeComplete {
		t.Errorf("the report is not readable after the removal: %+v", a.Report)
	}
}

func TestRemovalChecksObjects(t *testing.T) {
	tests := []struct {
		name   string
		replay func(r *importRig, readArchive *atomic.Bool)
		reason string
	}{
		{"manifest replaced during the attempt", func(r *importRig, _ *atomic.Bool) {
			r.minio.hook = func(op, key string) {
				if op == "get" && key == archiveKey {
					r.minio.change(manifestKey)
				}
			}
		}, "the manifest changed in MinIO"},
		{"archive replaced during the attempt", func(r *importRig, readArchive *atomic.Bool) {
			r.minio.hook = func(op, key string) {
				switch {
				case op == "get" && key == archiveKey:
					readArchive.Store(true)
				case op == "head" && key == archiveKey && readArchive.Load():
					r.minio.change(archiveKey)
				}
			}
		}, "the archive changed in MinIO"},
		{"manifest gone during the attempt", func(r *importRig, _ *atomic.Bool) {
			r.minio.hook = func(op, key string) {
				if op == "get" && key == archiveKey {
					r.minio.vanish(manifestKey)
				}
			}
		}, "the manifest is no longer in MinIO"},
		{"archive gone during the attempt", func(r *importRig, readArchive *atomic.Bool) {
			r.minio.hook = func(op, key string) {
				switch {
				case op == "get" && key == archiveKey:
					readArchive.Store(true)
				case op == "head" && key == archiveKey && readArchive.Load():
					r.minio.vanish(archiveKey)
				}
			}
		}, "the archive is no longer in MinIO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			var readArchive atomic.Bool
			tt.replay(r, &readArchive)
			id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
			done := waitEnded(t, r.store, id)
			a := done.Attempts[0]
			if a.Outcome != importer.OutcomeComplete || a.Removal == nil || a.Removal.Removed || !strings.Contains(a.Removal.Reason, tt.reason) {
				t.Fatalf("outcome %q, removal %+v; want complete, kept, reason with %q", a.Outcome, a.Removal, tt.reason)
			}
			if d := r.deletes(); len(d) != 0 {
				t.Errorf("deletes %v on a changed object", d)
			}
			if done.ArchiveRemoved() {
				t.Error("archiveRemoved is true")
			}
		})
	}
}

func TestEveryPackageIn(t *testing.T) {
	pkg := func(s importer.State) importer.Result {
		return importer.Result{Name: "left-pad", Version: "1.3.0", State: s}
	}
	tests := []struct {
		name string
		rep  importer.Report
		want bool
	}{
		{"published and present", importer.Report{Outcome: importer.OutcomeComplete, Packages: []importer.Result{pkg(importer.Published), pkg(importer.Present)}}, true},
		{"a pending package", importer.Report{Outcome: importer.OutcomeComplete, Packages: []importer.Result{pkg(importer.Published), pkg(importer.Pending)}}, false},
		{"a failed package", importer.Report{Outcome: importer.OutcomeComplete, Packages: []importer.Result{pkg(importer.Published), pkg(importer.Failed)}}, false},
		{"a failed count with every package published", importer.Report{Outcome: importer.OutcomeComplete, Counts: importer.Counts{Failed: 1}, Packages: []importer.Result{pkg(importer.Published)}}, false},
		{"an incomplete outcome", importer.Report{Outcome: importer.OutcomeIncomplete, Packages: []importer.Result{pkg(importer.Published)}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := everyPackageIn(tt.rep); got != tt.want {
				t.Errorf("everyPackageIn = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArchiveKeptUnlessComplete(t *testing.T) {
	good := buildBundle(t, leftPad)
	flipped := buildBundle(t, leftPad)
	flipped.archive = append([]byte(nil), flipped.archive...)
	flipped.archive[len(flipped.archive)/2] ^= 0xff

	tests := []struct {
		name    string
		bundle  testBundle
		prepare func(r *importRig)
		hold    bool
		outcome string
	}{
		{"incomplete", good, func(r *importRig) { r.minio.cut[dataKey(bucketAlice, archiveKey)] = len(good.archive) / 2 }, false, importer.OutcomeIncomplete},
		{"refused", flipped, func(*importRig) {}, false, importer.OutcomeRefused},
		{"interrupted", good, func(*importRig) {}, true, imports.OutcomeInterrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{hold: tt.hold})
			r.seed(archiveKey, manifestKey, tt.bundle)
			tt.prepare(r)
			id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
			if tt.hold {
				waitEntered(t, r)
				r.queue.Close()
			}
			done := waitEnded(t, r.store, id)
			if done.Outcome() != tt.outcome {
				t.Fatalf("outcome %q (%s), want %q", done.Outcome(), done.Attempts[0].Report.Reason, tt.outcome)
			}
			if d := r.deletes(); len(d) != 0 || done.ArchiveRemoved() || done.Attempts[0].Removal != nil {
				t.Errorf("deletes %v, removed %v, removal %+v", d, done.ArchiveRemoved(), done.Attempts[0].Removal)
			}
			for _, k := range []string{archiveKey, manifestKey} {
				if _, ok := r.minio.buckets[bucketAlice][k]; !ok {
					t.Errorf("%s left MinIO", k)
				}
			}
		})
	}
}

func TestRemovalFailureKeepsArchive(t *testing.T) {
	t.Run("the archive delete fails", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
		id := r.completeKept(t)
		a := waitEnded(t, r.store, id).Attempts[0]
		if a.Removal == nil || a.Removal.Removed || !strings.Contains(a.Removal.Reason, "could not remove the archive") {
			t.Fatalf("removal = %+v", a.Removal)
		}
		if d := r.deletes(); len(d) != 1 || d[0] != archiveKey {
			t.Errorf("deletes = %v, want the archive's only", d)
		}
		if _, ok := r.minio.buckets[bucketAlice][manifestKey]; !ok {
			t.Error("the manifest was removed with its archive kept")
		}
		got := importOf(t, r.get("/api/imports/"+id, "t"), http.StatusOK)
		if got.Outcome != importer.OutcomeComplete || got.ArchiveRemoved {
			t.Errorf("outcome %q removed %v", got.Outcome, got.ArchiveRemoved)
		}

		before := r.nexus.readCount(leftPad)
		importOf(t, r.retry("t", id), http.StatusAccepted)
		done := waitEnded(t, r.store, id)
		if r.nexus.readCount(leftPad) <= before {
			t.Error("the retry did not check the package again")
		}
		if !done.ArchiveRemoved() || done.Attempts[1].Removal == nil || !done.Attempts[1].Removal.Removed {
			t.Errorf("after the retry: removed %v, removal %+v", done.ArchiveRemoved(), done.Attempts[1].Removal)
		}
	})

	t.Run("the manifest delete fails after the archive went", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
		r.minio.failDelete[manifestKey] = errors.New("storage busy")
		id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
		done := waitEnded(t, r.store, id)
		a := done.Attempts[0]
		if a.Removal == nil || !a.Removal.Removed || !strings.Contains(a.Removal.Reason, "manifest") {
			t.Fatalf("removal = %+v", a.Removal)
		}
		if !done.ArchiveRemoved() {
			t.Error("archiveRemoved is false though the archive went")
		}
		if _, ok := r.minio.buckets[bucketAlice][archiveKey]; ok {
			t.Error("the archive is still in MinIO")
		}
	})

	t.Run("a MinIO error repeats no credential", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
		r.minio.failDelete[archiveKey] = errors.New("denied for " + testMinioKey + "\x1b[31m")
		id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
		a := waitEnded(t, r.store, id).Attempts[0]
		if a.Removal == nil || a.Removal.Removed || !strings.Contains(a.Removal.Reason, "could not remove the archive") {
			t.Fatalf("removal = %+v", a.Removal)
		}
		for what, text := range map[string]string{"the reason": a.Removal.Reason, "the log": r.logs.String()} {
			if strings.Contains(text, testMinioKey) || strings.ContainsAny(text, "\x1b") {
				t.Errorf("%s repeats the credential or a control character: %q", what, text)
			}
		}
	})
}

func TestArchiveRemovedField(t *testing.T) {
	r := newImportRig(t, rigOptions{hold: true})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	waitEntered(t, r)

	field := func() bool {
		t.Helper()
		rec := r.get("/api/imports/"+id, "t")
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		v, ok := raw["archiveRemoved"]
		if !ok {
			t.Fatalf("no archiveRemoved in %s", rec.Body)
		}
		return string(v) == "true"
	}
	if field() {
		t.Error("archiveRemoved is true while the attempt runs")
	}
	close(r.release)
	waitEnded(t, r.store, id)
	if !field() {
		t.Error("archiveRemoved is false after a complete attempt removed the archive")
	}
}

func TestStartAndRetryAfterShutdown(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	id := r.endedImport(t, importer.OutcomeIncomplete)
	r.queue.Close()

	rec := r.retry("t", id)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("retry: status = %d, want 503; body %s", rec.Code, rec.Body)
	}
	problemOf(t, rec)
	got, _ := r.store.Get("alice", id)
	if len(got.Attempts) != 2 || got.Attempts[1].Status != imports.StatusEnded || got.Attempts[1].Outcome != imports.OutcomeInterrupted {
		t.Errorf("the attempt that will never run: %+v", got.Attempts)
	}

	r.seed(otherKey, otherMan, buildBundle(t, leftPad))
	if rec = r.start("t", otherKey); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("start: status = %d, want 503; body %s", rec.Code, rec.Body)
	}
}

func TestRemovalTakesThreeObjects(t *testing.T) {
	t.Run("the order is archive, manifest, signature", func(t *testing.T) {
		r := newImportRig(t, rigOptions{})
		r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
		done := waitEnded(t, r.store, importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id)
		if rem := done.Attempts[0].Removal; rem == nil || !rem.Removed || rem.Reason != "" {
			t.Fatalf("removal = %+v", rem)
		}
		if d := r.deletes(); strings.Join(d, " ") != strings.Join([]string{archiveKey, manifestKey, signatureKey}, " ") {
			t.Errorf("deletes = %v", d)
		}
	})
	for _, tt := range []struct {
		name   string
		act    func(r *importRig)
		reason string
	}{
		{"the signature changed during the attempt", func(r *importRig) { r.minio.change(signatureKey) },
			"the signature changed in MinIO after the import read it; nothing was removed"},
		{"the signature went during the attempt", func(r *importRig) { r.minio.vanish(signatureKey) },
			"the signature is no longer in MinIO; nothing was removed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newImportRig(t, rigOptions{})
			r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
			r.minio.hook = func(op, key string) {
				if op == "get" && key == archiveKey {
					tt.act(r)
				}
			}
			done := waitEnded(t, r.store, importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id)
			a := done.Attempts[0]
			if a.Outcome != importer.OutcomeComplete || a.Removal == nil || a.Removal.Removed || a.Removal.Reason != tt.reason {
				t.Fatalf("outcome %q, removal %+v; want complete, kept, reason %q", a.Outcome, a.Removal, tt.reason)
			}
			if d := r.deletes(); len(d) != 0 {
				t.Errorf("deletes %v on a changed signature", d)
			}
		})
	}
}

func TestRemovalKeepsAStuckSignature(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	r.seed(archiveKey, manifestKey, buildBundle(t, leftPad))
	r.minio.failDelete[signatureKey] = errors.New("storage busy")
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	done := waitEnded(t, r.store, id)
	want := "the archive and the manifest were removed, but manifest.json.sig could not be and stays in the folder: MinIO could not be reached"
	if rem := done.Attempts[0].Removal; rem == nil || !rem.Removed || rem.Reason != want {
		t.Fatalf("removal = %+v, want removed with %q", rem, want)
	}
	if !done.ArchiveRemoved() {
		t.Error("archiveRemoved is false though the archive went")
	}
	if _, ok := r.minio.buckets[bucketAlice][signatureKey]; !ok {
		t.Error("the signature is gone although its delete failed")
	}
	for _, k := range []string{archiveKey, manifestKey} {
		if _, ok := r.minio.buckets[bucketAlice][k]; ok {
			t.Errorf("%s is still in MinIO", k)
		}
	}
}

func TestRetryChecksTheSignatureAgain(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	b := buildBundle(t, leftPad)
	r.seed(archiveKey, manifestKey, b)
	r.minio.cut[dataKey(bucketAlice, archiveKey)] = len(b.archive) / 2
	id := importOf(t, r.start("t", archiveKey), http.StatusAccepted).Id
	if first := waitEnded(t, r.store, id); first.Outcome() != importer.OutcomeIncomplete {
		t.Fatalf("setup: outcome %q (%s)", first.Outcome(), first.Attempts[0].Report.Reason)
	}
	delete(r.minio.cut, dataKey(bucketAlice, archiveKey))

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.handlers.settings.PublicKey, r.handlers.settings.PublicKeySHA256 = other, archive.PublicKeySHA256(other)
	importOf(t, r.retry("t", id), http.StatusAccepted)
	a := waitEnded(t, r.store, id).Attempts[1]
	want := "the manifest is signed by another key, public key sha256 " + archive.PublicKeySHA256(testPub) + "; this import trusts " + archive.PublicKeySHA256(other) + "."
	if a.Outcome != importer.OutcomeRefused || !strings.Contains(a.Report.Reason, want) {
		t.Fatalf("attempt 2: outcome %q, reason %q; want refused containing %q", a.Outcome, a.Report.Reason, want)
	}
	if a.Report.PublicKeySHA256 != archive.PublicKeySHA256(other) {
		t.Errorf("report key %q, want the trusted one", a.Report.PublicKeySHA256)
	}
	if n := r.nexus.uploadCount(); n != 0 {
		t.Errorf("%d uploads after a refusal", n)
	}
	if d := r.deletes(); len(d) != 0 {
		t.Errorf("deletes %v after a refusal", d)
	}
}

// A record of sealift 0.4 holds no signature: it stays readable and its retry
// is accepted, then refused as unsigned without a MinIO read or an upload.
func TestOldImportRetryIsUnsigned(t *testing.T) {
	r := newImportRig(t, rigOptions{})
	const fixtureID = "20261106T110000Z-7c2e55aa"
	b := buildBundle(t, leftPad)
	archiveAt, manifestAt := base+"b/packages_npm.tar.gz", base+"b/manifest.json"
	r.minio.putData(archiveAt, b.archive)
	r.minio.putData(manifestAt, b.manifest)
	raw, err := os.ReadFile(filepath.Join("..", "..", "store", "imports", "testdata", "import-v0.4.0-incomplete.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec["archive"].(map[string]any)["etag"] = r.minio.etagOf(archiveAt)
	rec["manifest"].(map[string]any)["etag"] = r.minio.etagOf(manifestAt)
	raw, _ = json.Marshal(rec)
	dir := filepath.Join(r.data, "alice", fixtureID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "import.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got := importOf(t, r.get("/api/imports/"+fixtureID, "t"), http.StatusOK)
	if got.Outcome != importer.OutcomeIncomplete || len(got.Attempts) != 1 {
		t.Fatalf("the old record reads as %+v", got)
	}
	if list := listOfImports(t, r.get("/api/imports", "t")).Imports; len(list) != 1 || list[0].Id != fixtureID {
		t.Fatalf("the list holds %v, want the old record", ids(list))
	}

	importOf(t, r.retry("t", fixtureID), http.StatusAccepted)
	a := waitEnded(t, r.store, fixtureID).Attempts[1]
	want := archive.Unsigned("manifest.json.sig").Reason
	if a.Outcome != importer.OutcomeRefused || a.Report.Reason != want {
		t.Fatalf("attempt 2: outcome %q, reason %q; want refused with %q", a.Outcome, a.Report.Reason, want)
	}
	if r.nexus.uploadCount() != 0 || len(r.deletes()) != 0 {
		t.Errorf("%d uploads, deletes %v: nothing may be published or removed", r.nexus.uploadCount(), r.deletes())
	}
}

var mocha = testPkg{"mocha", "10.0.0"}

func fileOf(t *testing.T, p testPkg) string {
	t.Helper()
	file, err := npm.PackFileName(p.name, p.version)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// inNexus puts the package's tarball in Nexus, as an earlier upload would have.
func (r *importRig) inNexus(t *testing.T, p testPkg) {
	t.Helper()
	body := tarballOf(t, p.name, p.version)
	r.nexus.mu.Lock()
	defer r.nexus.mu.Unlock()
	r.nexus.tarballs[npm.TarballURL("/repository/"+testRepo, p.name, p.version)] = body
}

// failedFirst seeds b and records an import of it whose first attempt failed
// the packages of kinds, each with the reason "earlier <kind>", and found every
// other package in Nexus, which holds them.
func (r *importRig) failedFirst(t *testing.T, b testBundle, kinds map[testPkg]importer.Kind) string {
	t.Helper()
	r.seed(archiveKey, manifestKey, b)
	imp, err := r.store.Create("alice",
		imports.Object{Key: archiveKey, ETag: r.minio.etagOf(archiveKey), Size: int64(len(b.archive))},
		imports.Object{Key: manifestKey, ETag: r.minio.etagOf(manifestKey), Size: int64(len(b.manifest))},
		&imports.Object{Key: signatureKey, ETag: r.minio.etagOf(signatureKey), Size: int64(len(b.signature))}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.store.Begin("alice", imp.ID); err != nil {
		t.Fatal(err)
	}
	rep := importer.Report{Outcome: importer.OutcomeIncomplete, Packages: []importer.Result{}}
	for _, p := range b.pkgs {
		res := importer.Result{Name: p.name, Version: p.version, File: fileOf(t, p), State: importer.Present}
		if kind, ok := kinds[p]; ok {
			res.State, res.Kind, res.Reason = importer.Failed, kind, "earlier "+string(kind)
			rep.Counts.Failed++
		} else {
			r.inNexus(t, p)
			rep.Counts.Present++
		}
		rep.Packages = append(rep.Packages, res)
	}
	if err := r.store.Finish("alice", imp.ID, 1, rep, nil); err != nil {
		t.Fatal(err)
	}
	return imp.ID
}

// retryBody sends a retry with body as alice.
func (r *importRig) retryBody(id, body string) *httptest.ResponseRecorder {
	return r.postTo("/api/imports/"+id+"/retry", "t", body)
}

func retryOf(t *testing.T, files ...string) string {
	t.Helper()
	b, err := json.Marshal(RetryImport{Packages: &files})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func resultsByName(rep importer.Report) map[string]importer.Result {
	out := map[string]importer.Result{}
	for _, p := range rep.Packages {
		out[p.Name] = p
	}
	return out
}

func TestRetryOfOneCause(t *testing.T) {
	t.Run("uploads only the files of the retried cause", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta, mocha}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta, mocha), map[testPkg]importer.Kind{
			leftPad: importer.KindNexus, zeta: importer.KindNexus, mocha: importer.KindConflict,
		})
		answer := importOf(t, r.retryBody(id, retryOf(t, fileOf(t, leftPad), fileOf(t, zeta))), http.StatusAccepted)
		if got := answer.Attempts[1].Retry; got == nil || len(*got) != 2 || (*got)[0] != fileOf(t, leftPad) || (*got)[1] != fileOf(t, zeta) {
			t.Errorf("the answer's list = %v", got)
		}
		done := waitEnded(t, r.store, id)
		a := done.Attempts[1]
		if len(a.Retry) != 2 {
			t.Errorf("the stored list = %v", a.Retry)
		}
		got := resultsByName(a.Report)
		if got["left-pad"].State != importer.Published || got["zeta"].State != importer.Published {
			t.Errorf("the retried packages = %+v", a.Report.Packages)
		}
		if n := r.nexus.uploadCount(); n != 2 {
			t.Errorf("%d uploads, want 2", n)
		}
		if a.Outcome != importer.OutcomeIncomplete || a.Report.Counts.Published != 2 || a.Report.Counts.Failed != 1 {
			t.Errorf("attempt 2 = %s %+v", a.Outcome, a.Report.Counts)
		}
	})

	t.Run("keeps an unlisted package Nexus lacks failed with its earlier cause", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{
			leftPad: importer.KindNexus, zeta: importer.KindConflict,
		})
		reads := r.nexus.readCount(zeta)
		importOf(t, r.retryBody(id, retryOf(t, fileOf(t, leftPad))), http.StatusAccepted)
		a := waitEnded(t, r.store, id).Attempts[1]
		z := resultsByName(a.Report)["zeta"]
		if z.State != importer.Failed || z.Kind != importer.KindConflict || z.Reason != "earlier conflict" || z.File != fileOf(t, zeta) {
			t.Errorf("zeta = %+v, want failed as conflict with the earlier reason", z)
		}
		if r.nexus.readCount(zeta) <= reads {
			t.Error("zeta was not read from Nexus")
		}
		if n := r.nexus.uploadCount(); n != 1 {
			t.Errorf("%d uploads, want 1", n)
		}
		if a.Outcome != importer.OutcomeIncomplete || a.Report.Counts.Failed != 1 {
			t.Errorf("attempt 2 = %s %+v", a.Outcome, a.Report.Counts)
		}
	})

	t.Run("keeps the new cause of a listed package that fails again", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{
			leftPad: importer.KindNexus, zeta: importer.KindConflict,
		})
		// Since the first attempt, Nexus took other bytes under left-pad's version.
		r.nexus.mu.Lock()
		r.nexus.tarballs[npm.TarballURL("/repository/"+testRepo, leftPad.name, leftPad.version)] = []byte("other bytes")
		r.nexus.mu.Unlock()
		importOf(t, r.retryBody(id, retryOf(t, fileOf(t, leftPad))), http.StatusAccepted)
		got := resultsByName(waitEnded(t, r.store, id).Attempts[1].Report)
		if l := got["left-pad"]; l.State != importer.Failed || l.Kind != importer.KindConflict || !strings.HasPrefix(l.Reason, "nexus holds this version with other bytes") {
			t.Errorf("left-pad = %+v, want failed as conflict with this attempt's reason", l)
		}
		if z := got["zeta"]; z.Kind != importer.KindConflict || z.Reason != "earlier conflict" {
			t.Errorf("zeta = %+v, want its earlier cause", z)
		}
	})

	t.Run("fails an unlisted package Nexus lost since the earlier attempt", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{leftPad: importer.KindNexus})
		r.nexus.lose(zeta)
		importOf(t, r.retryBody(id, retryOf(t, fileOf(t, leftPad))), http.StatusAccepted)
		done := waitEnded(t, r.store, id)
		z := resultsByName(done.Attempts[1].Report)["zeta"]
		if z.State != importer.Failed || z.Kind != importer.KindNexus || z.Reason == "" {
			t.Errorf("zeta = %+v, want failed", z)
		}
		if done.ArchiveRemoved() || len(r.deletes()) != 0 {
			t.Error("the archive left MinIO with a package missing from Nexus")
		}
	})

	t.Run("reads an unlisted package from Nexus and never uploads it", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{
			leftPad: importer.KindNexus, zeta: importer.KindConflict,
		})
		r.inNexus(t, zeta)
		reads := r.nexus.readCount(zeta)
		importOf(t, r.retryBody(id, retryOf(t, fileOf(t, leftPad))), http.StatusAccepted)
		a := waitEnded(t, r.store, id).Attempts[1]
		if z := resultsByName(a.Report)["zeta"]; z.State != importer.Present {
			t.Errorf("zeta = %+v, want present", z)
		}
		if r.nexus.readCount(zeta) <= reads {
			t.Error("zeta was not read from Nexus")
		}
		if n := r.nexus.uploadCount(); n != 1 {
			t.Errorf("%d uploads, want only left-pad's", n)
		}
	})

	t.Run("removes the archive only when a retry of one cause leaves every package in Nexus", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{
			leftPad: importer.KindNexus, zeta: importer.KindConflict,
		})
		importOf(t, r.retryBody(id, retryOf(t, fileOf(t, leftPad))), http.StatusAccepted)
		if got := waitEnded(t, r.store, id); got.ArchiveRemoved() || len(r.deletes()) != 0 {
			t.Fatalf("the archive left MinIO while zeta is not in Nexus: %v", r.deletes())
		}
		r.inNexus(t, zeta)
		importOf(t, r.retryBody(id, retryOf(t, fileOf(t, zeta))), http.StatusAccepted)
		done := waitEnded(t, r.store, id)
		if a := done.Attempts[2]; a.Outcome != importer.OutcomeComplete || !done.ArchiveRemoved() || len(r.deletes()) != 3 {
			t.Errorf("attempt 3 = %s %+v, removed %v, deletes %v", a.Outcome, a.Report.Counts, done.ArchiveRemoved(), r.deletes())
		}
	})

	t.Run("refuses a file that names no failed package with no echo", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{leftPad: importer.KindNexus})
		for name, body := range map[string]string{
			"an unknown file":    retryOf(t, "evil-9.9.9.tgz"),
			"a package in Nexus": retryOf(t, fileOf(t, zeta)),
			"more than listed":   retryOf(t, fileOf(t, leftPad), "evil-1.tgz", "evil-2.tgz"),
		} {
			rec := r.retryBody(id, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400; body %s", name, rec.Code, rec.Body)
			}
			if d := detailOf(problemOf(t, rec)); d != "the packages to retry must be failed packages of the latest attempt" {
				t.Errorf("%s: detail %q", name, d)
			}
			if raw := rec.Body.String() + r.logs.String(); strings.Contains(raw, "evil") || strings.Contains(raw, "zeta") {
				t.Errorf("%s: the answer or the log repeats the list", name)
			}
		}
		if got, _ := r.store.Get("alice", id); len(got.Attempts) != 1 {
			t.Errorf("a refused list left %d attempts", len(got.Attempts))
		}
		if n := r.nexus.uploadCount(); n != 0 {
			t.Errorf("a refused list uploaded %d packages", n)
		}
	})

	t.Run("refuses a duplicate", func(t *testing.T) {
		r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
		id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{leftPad: importer.KindNexus, zeta: importer.KindNexus})
		rec := r.retryBody(id, retryOf(t, fileOf(t, leftPad), fileOf(t, leftPad)))
		if rec.Code != http.StatusBadRequest || detailOf(problemOf(t, rec)) != "the packages to retry must be failed packages of the latest attempt" {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}
		if got, _ := r.store.Get("alice", id); len(got.Attempts) != 1 {
			t.Errorf("a refused list left %d attempts", len(got.Attempts))
		}
	})

	t.Run("retries the whole import on an empty body", func(t *testing.T) {
		for _, body := range []string{"{}", `{"packages":[]}`} {
			r := newImportRig(t, rigOptions{pkgs: []testPkg{leftPad, zeta}})
			id := r.failedFirst(t, buildBundle(t, leftPad, zeta), map[testPkg]importer.Kind{leftPad: importer.KindNexus, zeta: importer.KindConflict})
			if answer := importOf(t, r.retryBody(id, body), http.StatusAccepted); answer.Attempts[1].Retry != nil {
				t.Errorf("%s: the answer lists %v", body, *answer.Attempts[1].Retry)
			}
			done := waitEnded(t, r.store, id)
			a := done.Attempts[1]
			if a.Retry != nil || a.Outcome != importer.OutcomeComplete || a.Report.Counts.Published != 2 || !done.ArchiveRemoved() {
				t.Errorf("%s: attempt 2 = %s %+v list %v removed %v", body, a.Outcome, a.Report.Counts, a.Retry, done.ArchiveRemoved())
			}
		}
	})
}
