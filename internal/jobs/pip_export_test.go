package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/report"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// pipExportSet is the resolved set of the analysis most pip export tests
// start from, sorted as the analysis sorts it.
var pipExportSet = resolved("certifi", "2024.8.30", "idna", "3.10", "requests", "2.32.3")

// pipFixture is a done pip analysis, the store that holds it and the
// Service that ran it.
type pipFixture struct {
	svc     *Service
	st      *store.Store
	project store.Project
	ref     PipAnalysisRef
}

// runPipAnalysis runs a real pip analysis of requirements through the
// Service, with a fake uv that resolves set and a Trivy that finds
// nothing, against the index at indexURL, and returns it once its "end"
// event has gone out.
func runPipAnalysis(t *testing.T, indexURL, requirements string, set []runner.Resolved) pipFixture {
	t.Helper()
	return runScannedPipAnalysis(t, indexURL, requirements, set, pipTrivyReport())
}

// runScannedPipAnalysis is runPipAnalysis with a Trivy that answers every
// scan with report.
func runScannedPipAnalysis(t *testing.T, indexURL, requirements string, set []runner.Resolved, report string) pipFixture {
	t.Helper()
	svc, st := newTestService(t)
	svc.trivy = &exportTrivy{cannedTrivy: &cannedTrivy{report: report}}
	svc.tools.PipIndex = indexURL
	svc.tools.Arch = "amd64"
	svc.SetPip(&fakeUv{lock: "x==1\n", set: set}, &pip.Client{Index: indexURL})
	bin := filepath.Join(st.Root(), "tools", "uv", store.DefaultPipTarget.UvVer, "uv")
	if err := os.MkdirAll(filepath.Dir(bin), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	project, err := st.CreatePipProject("Data tools", []store.RequirementsFile{reqFile("requirements.txt", requirements)}, store.DefaultPipTarget)
	if err != nil {
		t.Fatalf("CreatePipProject: %v", err)
	}

	events, unsubscribe := svc.Subscribe()
	defer unsubscribe()
	queued, err := svc.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	for e := range events {
		if e.Kind == "end" && e.StoreID == queued.ID {
			break
		}
	}

	info, err := st.AnalysisInfo(project.ID, queued.ID)
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if info.State != store.Done {
		t.Fatalf("analysis state = %s (%+v), want done", info.State, info.Failure)
	}
	var result PipResult
	if err := json.Unmarshal(info.PipResult, &result); err != nil {
		t.Fatalf("decode pip-result.json: %v", err)
	}
	return pipFixture{svc: svc, st: st, project: project, ref: PipAnalysisRef{
		ID: queued.ID, Dir: filepath.Join(project.Dir, "analyses", queued.ID), Result: result,
	}}
}

// donePipAnalysis publishes pipExportSet on ix as py3-none-any wheels and
// returns a done analysis of it.
func donePipAnalysis(t *testing.T, ix *piptest.Index) pipFixture {
	t.Helper()
	for _, p := range pipExportSet {
		ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
	}
	return runPipAnalysis(t, ix.URL, "requests==2.32.3\n", pipExportSet)
}

// newPipExport reserves an export directory for the fixture's analysis.
func (f pipFixture) newPipExport(t *testing.T) *PipExport {
	t.Helper()
	pending, err := f.st.NewDir("exports", f.project.ID)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	return &PipExport{
		Store:    f.st,
		Index:    &pip.Client{},
		Trivy:    &exportTrivy{cannedTrivy: &cannedTrivy{report: pipTrivyReport()}},
		Project:  f.project,
		Settings: f.st.Settings(),
		Analysis: f.ref,
		Dir:      pending.Path(),
		ID:       pending.ID(),
	}
}

// stepRecorder keeps the events of a run and the steps they report, as
// Export.Run records them for status.json.
type stepRecorder struct {
	mu     sync.Mutex
	events []Event
	steps  []stepRecord
}

func (r *stepRecorder) emit(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	if ev.Kind == "step" {
		var d stepData
		if json.Unmarshal(ev.Data, &d) == nil {
			r.steps = append(r.steps, stepRecord{Name: d.Name, State: string(d.State), DurationMs: d.DurationMs, Error: d.Error})
		}
	}
}

func (r *stepRecorder) progress() []progressData {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []progressData
	for _, ev := range r.events {
		if ev.Kind != "progress" {
			continue
		}
		var d progressData
		if json.Unmarshal(ev.Data, &d) == nil {
			out = append(out, d)
		}
	}
	return out
}

// download runs package-list then download.
func (e *PipExport) download(t *testing.T, rec *stepRecorder) ([]pipWheelFile, error) {
	t.Helper()
	pkgs, err := e.packageList(rec.emit)
	if err != nil {
		return nil, err
	}
	return e.downloadAll(context.Background(), rec.emit, pkgs)
}

func fileRequests(ix *piptest.Index, pkgs []PipPackage) map[string]int {
	out := map[string]int{}
	for _, p := range pkgs {
		out[p.Wheel.File] = ix.Requests("/files/" + p.Wheel.File)
	}
	return out
}

func TestPipExportPackageListReadsTheRecordedSet(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	rec := &stepRecorder{}
	pkgs, err := e.packageList(rec.emit)
	if err != nil {
		t.Fatalf("packageList: %v", err)
	}
	if !reflect.DeepEqual(pkgs, f.ref.Result.Packages) {
		t.Errorf("packages = %+v, want the analysis's %+v", pkgs, f.ref.Result.Packages)
	}
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	if want := []string{"certifi", "idna", "requests"}; !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
	if want := []string{"package-list:running", "package-list:done"}; !slices.Equal(stepNames(rec.steps), want) {
		t.Errorf("steps = %v, want %v", stepNames(rec.steps), want)
	}
}

func TestPipExportFetchesNoIndexPage(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	pages := func() int {
		n := ix.Requests("/simple/")
		for _, p := range pipExportSet {
			n += ix.Requests("/simple/" + pip.Normalize(p.Name) + "/")
		}
		return n
	}
	before := pages()
	if before == 0 {
		t.Fatal("the analysis read no index page, so this test proves nothing")
	}
	e := f.newPipExport(t)
	if _, err := e.download(t, &stepRecorder{}); err != nil {
		t.Fatalf("download: %v", err)
	}
	if n := pages() - before; n != 0 {
		t.Errorf("the export read %d index pages, want 0", n)
	}
	for file, n := range fileRequests(ix, f.ref.Result.Packages) {
		if n != 1 {
			t.Errorf("%s was requested %d times, want 1", file, n)
		}
	}
}

func TestPipExportRefusesAPackageWithoutAWheel(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	pkgs := slices.Clone(f.ref.Result.Packages)
	pkgs[1].Wheel = nil
	f.ref.Result.Packages = pkgs
	e := f.newPipExport(t)
	rec := &stepRecorder{}
	_, err := e.packageList(rec.emit)
	if err == nil || !strings.Contains(err.Error(), "idna==3.10") || !strings.Contains(err.Error(), "no wheel") {
		t.Fatalf("packageList = %v, want a refusal naming idna==3.10 and its missing wheel", err)
	}
	if len(rec.steps) != 2 || rec.steps[1].State != string(store.Failed) || rec.steps[1].Error != err.Error() {
		t.Errorf("steps = %+v, want package-list failed with the error", rec.steps)
	}
}

// clonePipPackages copies pkgs and their wheels, so a test can edit the
// copy without touching the recorded result.
func clonePipPackages(pkgs []PipPackage) []PipPackage {
	out := slices.Clone(pkgs)
	for i := range out {
		if out[i].Wheel != nil {
			w := *out[i].Wheel
			out[i].Wheel = &w
		}
	}
	return out
}

// treeSums maps each file under root to the sha256 of its bytes and each
// other entry to its type, leaving out the tree under skip.
func treeSums(t *testing.T, root, skip string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == skip {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			out[p] = d.Type().String()
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Each value package-list checks is checked before a path joins it: a row
// fails the first step with its reason, and no file outside the export
// changes. A refusal quotes no value that failed its check.
func TestPipExportPackageListRefusesARecordedValue(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	// A sha256 of ../../victim would put the cache entry here.
	victim := filepath.Join(f.st.Root(), "victim.whl")
	if err := os.WriteFile(victim, []byte("victim"), 0o664); err != nil {
		t.Fatal(err)
	}
	idna := f.ref.Result.Packages[1].Wheel
	tests := []struct {
		name   string
		edit   func(pkgs []PipPackage) []PipPackage
		reason string
		bad    string // the value the refusal must not quote
	}{
		{"a sha256 that leaves the cache", func(p []PipPackage) []PipPackage {
			p[1].Wheel.Sha256 = "../../victim"
			return p
		}, "idna==3.10: the wheel " + idna.File + " has no valid sha256", "victim"},
		{"an uppercase sha256", func(p []PipPackage) []PipPackage {
			p[1].Wheel.Sha256 = strings.ToUpper(idna.Sha256)
			return p
		}, "idna==3.10: the wheel " + idna.File + " has no valid sha256", strings.ToUpper(idna.Sha256)},
		{"a short sha256", func(p []PipPackage) []PipPackage {
			p[1].Wheel.Sha256 = idna.Sha256[:63]
			return p
		}, "idna==3.10: the wheel " + idna.File + " has no valid sha256", idna.Sha256[:63]},
		{"a wheel name with a path separator", func(p []PipPackage) []PipPackage {
			p[1].Wheel.File = "../../" + idna.File
			return p
		}, "idna==3.10: pip: wheel name has a path separator", "../"},
		{"a source distribution", func(p []PipPackage) []PipPackage {
			p[1].Wheel.File = "idna-3.10.tar.gz"
			return p
		}, "idna==3.10: pip: file is not a wheel", "idna-3.10.tar.gz"},
		{"an invalid package name", func(p []PipPackage) []PipPackage {
			p[1].Name = "idna/../x"
			return p
		}, "package 2 of the analysis has no valid name and version", "idna/../x"},
		{"a version range", func(p []PipPackage) []PipPackage {
			p[1].Version = ">=3.10"
			return p
		}, "package 2 of the analysis has no valid name and version", ">=3.10"},
		{"a package listed twice", func(p []PipPackage) []PipPackage {
			dup := p[1]
			dup.Name = "IDNA"
			return append(p, dup)
		}, "jobs: idna is listed twice", ""},
		{"the wheel of another package and version", func(p []PipPackage) []PipPackage {
			w := *p[0].Wheel
			p[1].Wheel = &w
			return p
		}, "idna==3.10: the wheel " + f.ref.Result.Packages[0].Wheel.File + " names another package", ""},
		{"the wheel of another package of the same version", func(p []PipPackage) []PipPackage {
			p[1].Wheel.File = "other-3.10-py3-none-any.whl"
			return p
		}, "idna==3.10: the wheel other-3.10-py3-none-any.whl names another package", ""},
		{"the wheel of another version", func(p []PipPackage) []PipPackage {
			p[1].Version = "3.9"
			return p
		}, "idna==3.9: the wheel " + idna.File + " names another package", ""},
		{"a wheel name past the archive's entry name bound", func(p []PipPackage) []PipPackage {
			// 252 bytes: ParseWheelName takes it, out/ plus it exceeds 255.
			p[1].Wheel.File = "idna-3.10-1" + strings.Repeat("a", 224) + "-py3-none-any.whl"
			return p
		}, "idna==3.10: the wheel name is longer than an archive entry name of 255 bytes allows", strings.Repeat("a", 224)},
		{"no recorded size", func(p []PipPackage) []PipPackage {
			p[1].Wheel.Size = 0
			return p
		}, "idna==3.10: the wheel " + idna.File + " is recorded at 0 bytes, outside 1 to 4294967296", ""},
		{"a size above the wheel bound", func(p []PipPackage) []PipPackage {
			p[1].Wheel.Size = pip.MaxDownloadBytes + 1
			return p
		}, "idna==3.10: the wheel " + idna.File + " is recorded at 4294967297 bytes, outside 1 to 4294967296", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := f.newPipExport(t)
			e.Analysis.Result.Packages = tc.edit(clonePipPackages(f.ref.Result.Packages))
			before := treeSums(t, f.st.Root(), e.Dir)
			requests := fileRequests(ix, f.ref.Result.Packages)

			rec := &stepRecorder{}
			_, err := e.download(t, rec)
			if err == nil {
				t.Fatal("download accepted the edited set")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("download = %v, want a refusal saying %q", err, tc.reason)
			}
			if tc.bad != "" && strings.Contains(err.Error(), tc.bad) {
				t.Errorf("refusal %q quotes %q", err, tc.bad)
			}
			if want := []string{"package-list:running", "package-list:failed"}; !slices.Equal(stepNames(rec.steps), want) {
				t.Errorf("steps = %v, want %v", stepNames(rec.steps), want)
			}
			if after := treeSums(t, f.st.Root(), e.Dir); !reflect.DeepEqual(after, before) {
				t.Errorf("files outside the export changed:\nbefore %v\nafter  %v", before, after)
			}
			if after := fileRequests(ix, f.ref.Result.Packages); !reflect.DeepEqual(after, requests) {
				t.Errorf("file requests went from %v to %v, want none", requests, after)
			}
		})
	}
}

// bulkIndex is a package index that lists, for any project, one
// py3-none-any wheel of version 1.0 with the recorded size given.
func bulkIndex(t *testing.T, size int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/simple/"), "/")
		if !pip.ValidName(name) {
			http.NotFound(w, r)
			return
		}
		file := name + "-1.0-py3-none-any.whl"
		sum := sha256.Sum256([]byte(file))
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"meta": map[string]string{"api-version": "1.0"},
			"name": name,
			"files": []map[string]any{{
				"filename": file, "url": "../../files/" + file, "size": size,
				"hashes":      map[string]string{"sha256": hex.EncodeToString(sum[:])},
				"upload-time": released.Format(time.RFC3339),
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/simple/"
}

func TestPipExportRefusesASetTheImportWouldRefuse(t *testing.T) {
	tests := []struct {
		name  string
		count int
		size  int64
		bound string
	}{
		{"too many wheels", archive.DefaultLimits.Entries, 100, fmt.Sprintf("%d entries", archive.DefaultLimits.Entries)},
		{"too many bytes", 3, pip.MaxDownloadBytes, fmt.Sprintf("%d bytes", archive.DefaultLimits.Unpacked)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set := make([]runner.Resolved, tc.count)
			for i := range set {
				set[i] = runner.Resolved{Name: fmt.Sprintf("p%05d", i), Version: "1.0"}
			}
			f := runPipAnalysis(t, bulkIndex(t, tc.size), "p00000==1.0\n", set)
			if got := len(f.ref.Result.Packages); got != tc.count {
				t.Fatalf("the analysis recorded %d packages, want %d", got, tc.count)
			}
			_, err := f.newPipExport(t).packageList(noopEmit)
			if err == nil || !strings.Contains(err.Error(), tc.bound) {
				t.Fatalf("packageList = %v, want a refusal naming %q", err, tc.bound)
			}
		})
	}
}

func TestPipExportDownloadsIntoTheWheelCache(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	first := f.newPipExport(t)
	wheels, err := first.download(t, &stepRecorder{})
	if err != nil {
		t.Fatalf("first download: %v", err)
	}
	for i, p := range f.ref.Result.Packages {
		want := filepath.Join(f.st.Root(), "cache", "wheels", p.Wheel.Sha256+".whl")
		if wheels[i].CachePath != want {
			t.Errorf("%s cache path = %s, want %s", p.Name, wheels[i].CachePath, want)
		}
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s is not in the wheel cache: %v", p.Name, err)
		}
	}
	before := fileRequests(ix, f.ref.Result.Packages)

	second := f.newPipExport(t)
	rec := &stepRecorder{}
	again, err := second.download(t, rec)
	if err != nil {
		t.Fatalf("second download: %v", err)
	}
	if after := fileRequests(ix, f.ref.Result.Packages); !reflect.DeepEqual(after, before) {
		t.Errorf("file requests went from %v to %v, want none from the cache", before, after)
	}
	if !reflect.DeepEqual(again, wheels) {
		t.Errorf("cached wheels = %+v, want %+v", again, wheels)
	}
	progress := rec.progress()
	total := len(f.ref.Result.Packages)
	if len(progress) != total {
		t.Fatalf("progress events = %d, want %d", len(progress), total)
	}
	last := progress[total-1]
	if last.Done != total || last.Total != total || last.CacheHits == nil || *last.CacheHits != total {
		t.Errorf("last progress = %+v, want every wheel counted as a cache hit", last)
	}
}

func TestPipExportDropsADamagedCacheEntry(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	target := f.ref.Result.Packages[0].Wheel
	cached := filepath.Join(f.st.Root(), "cache", "wheels", target.Sha256+".whl")
	if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, bytes.Repeat([]byte("x"), int(target.Size)), 0o664); err != nil {
		t.Fatal(err)
	}

	wheels, err := f.newPipExport(t).download(t, &stepRecorder{})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if n := ix.Requests("/files/" + target.File); n != 1 {
		t.Errorf("%s was requested %d times, want 1", target.File, n)
	}
	data, err := os.ReadFile(cached)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != target.Sha256 {
		t.Error("the cache still holds the damaged bytes")
	}
	if wheels[0].CachePath != cached {
		t.Errorf("cache path = %s, want %s", wheels[0].CachePath, cached)
	}
}

// The wheel cache is writable by the tools account. An entry it planted
// is neither read through nor waited on: it goes, and the wheel is
// downloaded again.
func TestPipExportReplacesACacheEntryThatIsNotAFile(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, cached string, body []byte) (check func(t *testing.T))
	}{
		{"a link to the wheel's bytes elsewhere", func(t *testing.T, cached string, body []byte) func(*testing.T) {
			// The target holds the right bytes, so only the entry's type refuses it.
			victim := filepath.Join(t.TempDir(), "elsewhere.whl")
			if err := os.WriteFile(victim, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, cached); err != nil {
				t.Fatal(err)
			}
			return func(t *testing.T) {
				if b, err := os.ReadFile(victim); err != nil || !bytes.Equal(b, body) {
					t.Errorf("the link's target changed: %v", err)
				}
			}
		}},
		{"a FIFO", func(t *testing.T, cached string, _ []byte) func(*testing.T) {
			if err := syscall.Mkfifo(cached, 0o660); err != nil {
				t.Fatal(err)
			}
			return func(*testing.T) {}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			f := donePipAnalysis(t, ix)
			target := f.ref.Result.Packages[0].Wheel
			resp, err := http.Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			cached := filepath.Join(f.st.Root(), "cache", "wheels", target.Sha256+".whl")
			if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
				t.Fatal(err)
			}
			check := tc.plant(t, cached, body)
			before := ix.Requests("/files/" + target.File)

			e := f.newPipExport(t)
			done := make(chan error, 1)
			go func() {
				_, err := e.download(t, &stepRecorder{})
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("download: %v", err)
				}
			case <-time.After(10 * time.Second):
				// An open blocked on the FIFO returns once a writer opens it.
				if w, err := os.OpenFile(cached, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = w.Close()
				}
				t.Fatal("download is still waiting on the cache entry after 10s")
			}

			if n := ix.Requests("/files/"+target.File) - before; n != 1 {
				t.Errorf("%s was requested %d times, want 1", target.File, n)
			}
			st, err := os.Lstat(cached)
			if err != nil {
				t.Fatal(err)
			}
			if !st.Mode().IsRegular() {
				t.Fatalf("cache entry mode = %s, want a regular file", st.Mode())
			}
			if b, err := os.ReadFile(cached); err != nil || !bytes.Equal(b, body) {
				t.Errorf("the cache entry does not hold the wheel: %v", err)
			}
			check(t)
		})
	}
}

// heldBody serves body at any path: its first half, then the rest once
// release is called.
func heldBody(t *testing.T, body []byte) (url string, release func()) {
	t.Helper()
	held := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(held) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		half := len(body) / 2
		_, _ = w.Write(body[:half])
		w.(http.Flusher).Flush()
		select {
		case <-held:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write(body[half:])
	}))
	t.Cleanup(srv.Close)
	// Runs before Close, which waits for a held handler.
	t.Cleanup(release)
	return srv.URL + "/wheel", release
}

// The tools account can rename entries in downloads/. A wheel whose .part
// file it swaps, while the body arrives, for a link to the signing key or
// for a FIFO fails its download, on one filesystem as across two, and
// leaves the wheel cache holding regular files only, none of them the key.
func TestPipExportRefusesAPartFileSwappedDuringTheBody(t *testing.T) {
	plants := []struct {
		name  string
		plant func(t *testing.T, path, key string)
	}{
		{"a link to the signing key", func(t *testing.T, path, key string) {
			if err := os.Symlink(key, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"a FIFO", func(t *testing.T, path, _ string) {
			if err := syscall.Mkfifo(path, 0o660); err != nil {
				t.Fatal(err)
			}
		}},
	}
	moves := []struct {
		name  string
		cross bool
	}{
		{"on one filesystem", false},
		{"across filesystems", true},
	}
	for _, mv := range moves {
		for _, pl := range plants {
			t.Run(pl.name+" "+mv.name, func(t *testing.T) {
				ix := piptest.NewIndex(t)
				f := donePipAnalysis(t, ix)
				if mv.cross {
					crossFilesystems(t)
				}
				keyPath := filepath.Join(f.st.Root(), "private", "signing-key.pem")
				key, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}

				e := f.newPipExport(t)
				pkgs := clonePipPackages(f.ref.Result.Packages)
				target := pkgs[0]
				resp, err := http.Get(target.Wheel.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				var release func()
				target.Wheel.URL, release = heldBody(t, body)
				e.Analysis.Result.Packages = pkgs

				type outcome struct {
					wheels []pipWheelFile
					err    error
				}
				rec := &stepRecorder{}
				done := make(chan outcome, 1)
				go func() {
					wheels, err := e.download(t, rec)
					done <- outcome{wheels, err}
				}()
				downloads := filepath.Join(e.Dir, "downloads")
				part := filepath.Join(downloads, target.Wheel.File+".part")
				deadline := time.Now().Add(10 * time.Second)
				for {
					if _, err := os.Lstat(part); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("no .part file appeared within 10s")
					}
					time.Sleep(time.Millisecond)
				}
				if err := os.Remove(part); err != nil {
					t.Fatal(err)
				}
				pl.plant(t, part, keyPath)
				release()

				cache := filepath.Join(f.st.Root(), "cache", "wheels")
				var got outcome
				select {
				case got = <-done:
				case <-time.After(10 * time.Second):
					// An open blocked on the FIFO returns once a writer opens it.
					for _, p := range []string{part, filepath.Join(downloads, target.Wheel.File), filepath.Join(cache, target.Wheel.Sha256+".whl")} {
						if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
							_ = w.Close()
						}
					}
					<-done
					t.Fatal("download was still waiting on the swapped file after 10s")
				}

				if got.err == nil {
					t.Errorf("download accepted the swapped file, %d wheels", len(got.wheels))
				} else {
					for _, want := range []string{target.Name + "==" + target.Version, target.Wheel.File} {
						if !strings.Contains(got.err.Error(), want) {
							t.Errorf("download error %q does not name %q", got.err, want)
						}
					}
				}
				entries, err := os.ReadDir(cache)
				if err != nil {
					t.Fatal(err)
				}
				for _, en := range entries {
					p := filepath.Join(cache, en.Name())
					st, err := os.Lstat(p)
					if err != nil {
						t.Fatal(err)
					}
					if !st.Mode().IsRegular() {
						t.Errorf("cache entry %s has mode %s, want a regular file", en.Name(), st.Mode())
						continue
					}
					if b, err := os.ReadFile(p); err == nil && bytes.Equal(b, key) {
						t.Errorf("cache entry %s holds the signing key", en.Name())
					}
				}
				if b, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(b, key) {
					t.Errorf("the signing key changed (%v)", err)
				}
			})
		}
	}
}

// tamperFirstWheel serves other bytes of the same length for the first
// package's wheel, and makes the export download one wheel at a time, so
// the others are still waiting when it fails.
func tamperFirstWheel(t *testing.T, ix *piptest.Index, f pipFixture, e *PipExport) PipPackage {
	t.Helper()
	p := f.ref.Result.Packages[0]
	ix.Serve(p.Wheel.File, bytes.Repeat([]byte("x"), int(p.Wheel.Size)))
	e.Settings.DownloadParallelism = 1
	return p
}

func TestPipExportFailsOnATamperedWheel(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	e := f.newPipExport(t)
	p := tamperFirstWheel(t, ix, f, e)

	rec := &stepRecorder{}
	_, err := e.download(t, rec)
	if err == nil {
		t.Fatal("download accepted a tampered wheel")
	}
	failed := rec.steps[len(rec.steps)-1]
	if failed.Name != "download" || failed.State != string(store.Failed) {
		t.Fatalf("last step = %+v, want download failed", failed)
	}
	for _, want := range []string{p.Name + "==" + p.Version, p.Wheel.File, "sha256"} {
		if !strings.Contains(failed.Error, want) {
			t.Errorf("step error %q does not name %q", failed.Error, want)
		}
	}
	for file, n := range fileRequests(ix, f.ref.Result.Packages) {
		want := 0
		if file == p.Wheel.File {
			want = 1
		}
		if n != want {
			t.Errorf("%s was requested %d times, want %d", file, n, want)
		}
	}

	// Every file the export can write, so failed has each one to remove.
	for _, name := range []string{archive.PipArchiveFile, "manifest.json", archive.SignatureFile, "report.trivy.json", "report.cdx.json", "findings.csv", "summary.md", "export.cdx-input.json"} {
		if err := os.WriteFile(filepath.Join(e.Dir, name), []byte("x"), 0o664); err != nil {
			t.Fatal(err)
		}
	}
	e.failed(context.Background(), rec.steps)
	entries, err := os.ReadDir(e.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "status.json" {
		var names []string
		for _, en := range entries {
			names = append(names, en.Name())
		}
		t.Fatalf("export directory holds %v, want only status.json", names)
	}
	var status exportStatusFile
	if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != store.Failed || status.AnalysisID != f.ref.ID {
		t.Errorf("status = %+v, want failed for analysis %s", status, f.ref.ID)
	}
	if n := len(status.Steps); n == 0 || status.Steps[n-1].Name != "download" || status.Steps[n-1].State != string(store.Failed) {
		t.Errorf("status steps = %+v, want the failed download last", status.Steps)
	}
}

// A cancel fails the download step with the context's error, whether it
// lands before the first wheel or between two, and failed then records
// the export as cancelled.
func TestPipExportCancelledDownloadIsNotDone(t *testing.T) {
	tests := []struct {
		name  string
		after int // wheels downloaded before the cancel
	}{
		{"before the first wheel", 0},
		{"after the first wheel", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			f := donePipAnalysis(t, ix)
			e := f.newPipExport(t)
			e.Settings.DownloadParallelism = 1
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rec := &stepRecorder{}
			pkgs, err := e.packageList(rec.emit)
			if err != nil {
				t.Fatalf("packageList: %v", err)
			}
			if tc.after == 0 {
				cancel()
			}
			emit := func(ev Event) {
				rec.emit(ev)
				if ev.Kind == "progress" && len(rec.progress()) == tc.after {
					cancel()
				}
			}

			wheels, err := e.downloadAll(ctx, emit, pkgs)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("downloadAll = %d wheels, %v; want context.Canceled", len(wheels), err)
			}
			if wheels != nil {
				t.Errorf("downloadAll returned %d wheels with its error, want none", len(wheels))
			}
			names := stepNames(rec.steps)
			if slices.Contains(names, "download:done") || names[len(names)-1] != "download:failed" {
				t.Errorf("steps = %v, want download failed and never done", names)
			}
			fetched := 0
			for _, n := range fileRequests(ix, f.ref.Result.Packages) {
				fetched += n
			}
			if fetched != tc.after {
				t.Errorf("%d wheels were requested, want %d", fetched, tc.after)
			}

			e.failed(ctx, rec.steps)
			var status exportStatusFile
			if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
				t.Fatal(err)
			}
			if status.State != store.Cancelled {
				t.Errorf("status state = %s, want cancelled", status.State)
			}
			if entries, err := os.ReadDir(e.Dir); err != nil || len(entries) != 1 {
				t.Errorf("export directory holds %d entries (%v), want only status.json", len(entries), err)
			}
		})
	}
}

func TestPipExportLogsNoPackageName(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes files in a read-only directory")
	}
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	e := f.newPipExport(t)
	tamperFirstWheel(t, ix, f, e)

	var logged bytes.Buffer
	var mu sync.Mutex
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{w: &logged, mu: &mu}, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	rec := &stepRecorder{}
	if _, err := e.download(t, rec); err == nil {
		t.Fatal("download accepted a tampered wheel")
	}
	// A file left in downloads/ that cannot be removed makes failed log
	// its cleanup failure.
	downloads := filepath.Join(e.Dir, "downloads")
	left := f.ref.Result.Packages[1].Wheel.File
	if err := os.WriteFile(filepath.Join(downloads, left), []byte("x"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(downloads, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(downloads, 0o770) })
	e.failed(context.Background(), rec.steps)

	mu.Lock()
	out := logged.String()
	mu.Unlock()
	if out == "" {
		t.Fatal("failed logged nothing, so this test proves nothing")
	}
	for _, p := range f.ref.Result.Packages {
		for _, word := range []string{p.Name, p.Wheel.File, p.Wheel.URL, ix.URL} {
			if strings.Contains(out, word) {
				t.Errorf("the log names %q:\n%s", word, out)
			}
		}
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// runPipExport runs e to its end and returns its error and the steps it
// reported.
func runPipExport(ctx context.Context, e *PipExport) (*stepRecorder, error) {
	rec := &stepRecorder{}
	return rec, e.Run(ctx, rec.emit)
}

// dirNames lists the names in dir, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, en := range entries {
		names = append(names, en.Name())
	}
	return names
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestPipExportWritesASignedArchive(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	rec, err := runPipExport(context.Background(), e)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantSteps := []string{
		"package-list:running", "package-list:done", "download:running", "download:done",
		"archive:running", "archive:done", "reports:running", "reports:done",
	}
	if !slices.Equal(stepNames(rec.steps), wantSteps) {
		t.Errorf("steps = %v, want %v", stepNames(rec.steps), wantSteps)
	}

	manifest := readFile(t, filepath.Join(e.Dir, "manifest.json"))
	sig := readFile(t, filepath.Join(e.Dir, archive.SignatureFile))
	if err := archive.CheckSignature(manifest, sig, publicKey(t, f.st.SigningKey())); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	eco, err := archive.ManifestEcosystem(manifest)
	if err != nil || eco != archive.Pip {
		t.Fatalf("ManifestEcosystem = %q, %v; want pip", eco, err)
	}
	m, err := archive.ParsePipManifest(manifest)
	if err != nil {
		t.Fatalf("ParsePipManifest: %v", err)
	}
	data := readFile(t, filepath.Join(e.Dir, archive.PipArchiveFile))
	checked, err := archive.VerifyPip(bytes.NewReader(data), m, archive.VerifyOptions{
		ExpectedSHA256: sha256Hex(data), Dir: t.TempDir(), Limits: archive.DefaultLimits,
	})
	if err != nil {
		t.Fatalf("VerifyPip: %v", err)
	}
	if len(checked) != len(f.ref.Result.Packages) {
		t.Errorf("VerifyPip accepted %d wheels, want %d", len(checked), len(f.ref.Result.Packages))
	}
}

func TestPipExportCarriesExactlyTheAnalysisSet(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	e := f.newPipExport(t)
	// The project's target moved on after the analysis.
	e.Project.PipTarget.Python = "3.13.1"
	e.Project.PipTarget.CPU = "aarch64"
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var m report.PipManifest
	if err := json.Unmarshal(readFile(t, filepath.Join(e.Dir, "manifest.json")), &m); err != nil {
		t.Fatal(err)
	}
	if m.Target != f.ref.Result.Target {
		t.Errorf("manifest target = %+v, want the analysis's %+v", m.Target, f.ref.Result.Target)
	}
	if m.FormatVersion != report.PipManifestFormatVersion || m.Ecosystem != store.Pip || m.AnalysisID != f.ref.ID {
		t.Errorf("manifest = format %d, ecosystem %q, analysis %q; want %d, pip, %s", m.FormatVersion, m.Ecosystem, m.AnalysisID, report.PipManifestFormatVersion, f.ref.ID)
	}

	entries := readArchive(t, readFile(t, filepath.Join(e.Dir, archive.PipArchiveFile)))
	want := make([]report.WheelEntry, 0, len(f.ref.Result.Packages))
	wantEntries := []string{"out/"}
	for _, p := range f.ref.Result.Packages {
		want = append(want, report.WheelEntry{Name: pip.Normalize(p.Name), Version: p.Version, File: p.Wheel.File, SHA256: p.Wheel.Sha256})
		wantEntries = append(wantEntries, "out/"+p.Wheel.File)
	}
	got := make([]report.WheelEntry, len(m.Packages))
	for i, w := range m.Packages {
		body, ok := entries["out/"+w.File]
		if !ok {
			t.Errorf("the archive has no entry for %s", w.File)
		}
		sum := sha512.Sum512([]byte(body))
		if w.ShippedSHA512 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: shippedSha512 does not match the archive's bytes", w.File)
		}
		w.ShippedSHA512 = ""
		got[i] = w
	}
	if !slices.Equal(got, want) {
		t.Errorf("manifest packages = %+v, want the analysis's %+v", got, want)
	}
	names := slices.Sorted(maps.Keys(entries))
	if slices.Sort(wantEntries); !slices.Equal(names, wantEntries) {
		t.Errorf("archive entries = %v, want %v", names, wantEntries)
	}
	for _, p := range f.ref.Result.Packages {
		if got := sha256Hex([]byte(entries["out/"+p.Wheel.File])); got != p.Wheel.Sha256 {
			t.Errorf("%s in the archive has sha256 %s, want the recorded %s", p.Wheel.File, got, p.Wheel.Sha256)
		}
	}
}

func TestPipExportTwiceGivesTheSameSha256(t *testing.T) {
	ix := piptest.NewIndex(t)
	f := donePipAnalysis(t, ix)
	first := f.newPipExport(t)
	if _, err := runPipExport(context.Background(), first); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	before := fileRequests(ix, f.ref.Result.Packages)
	second := f.newPipExport(t)
	if _, err := runPipExport(context.Background(), second); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if after := fileRequests(ix, f.ref.Result.Packages); !maps.Equal(before, after) {
		t.Errorf("the second export requested wheels (%v, then %v), want every one from the cache", before, after)
	}
	var sums []string
	for _, e := range []*PipExport{first, second} {
		var m report.PipManifest
		if err := json.Unmarshal(readFile(t, filepath.Join(e.Dir, "manifest.json")), &m); err != nil {
			t.Fatal(err)
		}
		if got := sha256Hex(readFile(t, filepath.Join(e.Dir, archive.PipArchiveFile))); got != m.Archive.SHA256 {
			t.Errorf("%s has sha256 %s, its manifest says %s", archive.PipArchiveFile, got, m.Archive.SHA256)
		}
		sums = append(sums, m.Archive.SHA256)
	}
	if sums[0] != sums[1] {
		t.Errorf("two exports of one analysis gave sha256 %s and %s", sums[0], sums[1])
	}
}

func TestPipExportIgnoresTheAnalysisAdvisories(t *testing.T) {
	ix := piptest.NewIndex(t)
	for _, p := range pipExportSet {
		ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
	}
	f := runScannedPipAnalysis(t, ix.URL, "requests==2.32.3\n", pipExportSet,
		pipTrivyReport([5]string{"requests", "2.32.3", "CVE-2024-47081", "MEDIUM", "2.32.4"}))
	path := filepath.Join(f.ref.Dir, "pip-result.json")
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, path), &doc); err != nil {
		t.Fatal(err)
	}

	var archives, manifests, summaries, csvs [2][]byte
	for i, keep := range []bool{false, true} {
		delete(doc, "advisories")
		if keep {
			table := map[string]Advisory{"CVE-2024-47081": {
				Title:     "requests: <b>a title</b> the export never quotes",
				Summary:   "Requests may leak `.netrc` credentials. See [the advisory](https://example.com).",
				Published: "2025-06-09T19:15:23Z",
			}}
			var err error
			if doc["advisories"], err = json.Marshal(table); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o664); err != nil {
			t.Fatal(err)
		}
		var result PipResult
		if err := json.Unmarshal(readFile(t, path), &result); err != nil {
			t.Fatal(err)
		}
		if keep != (len(result.Advisories) == 1) {
			t.Fatalf("export %d reads advisories %+v, want them only on the second export", i, result.Advisories)
		}
		e := f.newPipExport(t)
		e.Analysis.Result = result
		if _, err := runPipExport(context.Background(), e); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		archives[i] = readFile(t, filepath.Join(e.Dir, archive.PipArchiveFile))
		manifest := readFile(t, filepath.Join(e.Dir, "manifest.json"))
		if !createdAtLine.Match(manifest) {
			t.Fatalf("export %d: manifest.json has no createdAt line:\n%s", i, manifest)
		}
		manifests[i] = createdAtLine.ReplaceAll(manifest, nil)
		summaries[i] = summaryDateLines.ReplaceAll(readFile(t, filepath.Join(e.Dir, "summary.md")), nil)
		csvs[i] = readFile(t, filepath.Join(e.Dir, "findings.csv"))
	}
	if !bytes.Equal(archives[0], archives[1]) {
		t.Error("the archive's bytes changed with the analysis' advisories")
	}
	if !bytes.Equal(manifests[0], manifests[1]) {
		t.Errorf("manifest.json changed with the analysis' advisories:\n%s\nthen\n%s", manifests[0], manifests[1])
	}
	if !bytes.Equal(summaries[0], summaries[1]) {
		t.Errorf("summary.md changed with the analysis' advisories:\n%s\nthen\n%s", summaries[0], summaries[1])
	}
	if !bytes.Equal(csvs[0], csvs[1]) {
		t.Errorf("findings.csv changed with the analysis' advisories:\n%s\nthen\n%s", csvs[0], csvs[1])
	}
}

// summaryDateLines matches the lines of summary.md that date the analysis
// and its database, which two exports of one analysis may not share.
var summaryDateLines = regexp.MustCompile(`(?m)^- (Analysis|Trivy DB) date: .*\n`)

func TestPipExportNeverReadsAWheelsContent(t *testing.T) {
	ix := piptest.NewIndex(t)
	var file string
	for _, p := range pipExportSet {
		f := ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
		if p.Name == "idna" {
			file = f.Filename
		}
	}
	body := []byte("these bytes are no zip archive, and the export never opens one")
	ix.Serve(file, body)
	f := runPipAnalysis(t, ix.URL, "requests==2.32.3\n", pipExportSet)
	e := f.newPipExport(t)
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entries := readArchive(t, readFile(t, filepath.Join(e.Dir, archive.PipArchiveFile)))
	if got, ok := entries["out/"+file]; !ok || got != string(body) {
		t.Errorf("out/%s = %q (present %v), want the served bytes unchanged", file, got, ok)
	}
}

// rewriteWith returns a change to a cache entry that rewrites its bytes in
// place with change.
func rewriteWith(change func(data []byte) []byte) func(t *testing.T, path string) {
	return func(t *testing.T, path string) {
		if err := os.WriteFile(path, change(readFile(t, path)), 0o664); err != nil {
			t.Error(err)
		}
	}
}

// replaceWith returns a change that puts what plant makes at a cache
// entry's path, as the tools account can.
func replaceWith(plant func(t *testing.T, path string, data []byte) error) func(t *testing.T, path string) {
	return func(t *testing.T, path string) {
		data := readFile(t, path)
		if err := os.Remove(path); err != nil {
			t.Error(err)
			return
		}
		if err := plant(t, path, data); err != nil {
			t.Error(err)
		}
	}
}

func TestPipExportFailsWhenAWheelChangesBeforeTheArchive(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, path string)
	}{
		{"other bytes of the same length", rewriteWith(func(data []byte) []byte { return bytes.Repeat([]byte("x"), len(data)) })},
		{"one byte shorter", rewriteWith(func(data []byte) []byte { return data[:len(data)-1] })},
		{"one byte longer", rewriteWith(func(data []byte) []byte { return append(slices.Clone(data), 'x') })},
		// The link's target holds the downloaded bytes, so only the refusal
		// to follow it fails the step.
		{"a link to the same bytes", replaceWith(func(t *testing.T, path string, data []byte) error {
			target := filepath.Join(t.TempDir(), "elsewhere.whl")
			if err := os.WriteFile(target, data, 0o664); err != nil {
				return err
			}
			return os.Symlink(target, path)
		})},
		// No process writes to the FIFO, so an open that waits for a writer
		// never returns.
		{"a FIFO", replaceWith(func(_ *testing.T, path string, _ []byte) error { return syscall.Mkfifo(path, 0o660) })},
		{"a directory", replaceWith(func(_ *testing.T, path string, _ []byte) error { return os.Mkdir(path, 0o770) })},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := donePipAnalysis(t, piptest.NewIndex(t))
			e := f.newPipExport(t)
			w := *f.ref.Result.Packages[1].Wheel
			e.beforeArchive = func() {
				tc.change(t, filepath.Join(f.st.Root(), "cache", "wheels", w.Sha256+".whl"))
			}
			var rec *stepRecorder
			var err error
			ran := make(chan struct{})
			go func() {
				defer close(ran)
				rec, err = runPipExport(context.Background(), e)
			}()
			select {
			case <-ran:
			case <-time.After(20 * time.Second):
				t.Fatal("the export still runs after 20s: the changed entry holds the archive step")
			}
			if want := w.File + " changed after its download"; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Run = %v, want an error saying %q", err, want)
			}
			last := rec.steps[len(rec.steps)-1]
			if last.Name != "archive" || last.State != string(store.Failed) || last.Error != err.Error() {
				t.Errorf("last step = %+v, want archive failed with the error", last)
			}
			if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
				t.Errorf("export directory holds %v, want only status.json", names)
			}
			var status exportStatusFile
			if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
				t.Fatal(err)
			}
			if status.State != store.Failed {
				t.Errorf("status state = %s, want failed", status.State)
			}
		})
	}
}

// A change to the bytes moves both digests at once, so a recorded digest
// that differs is the only way to show that each one fails the read alone.
func TestCachedWheelFailsOnEitherDigest(t *testing.T) {
	data := []byte("the bytes the download checked")
	path := filepath.Join(t.TempDir(), "cached.whl")
	if err := os.WriteFile(path, data, 0o664); err != nil {
		t.Fatal(err)
	}
	sum512 := sha512.Sum512(data)
	good256, good512 := sha256Hex(data), hex.EncodeToString(sum512[:])
	other := func(digest string) string { return strings.Repeat("0", len(digest)) }
	tests := []struct {
		name           string
		sha256, sha512 string
		changed        bool
	}{
		{"both digests of the bytes", good256, good512, false},
		{"another sha256, the same sha512", other(good256), good512, true},
		{"the same sha256, another sha512", good256, other(good512), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := pipWheelFile{
				PipPackage: PipPackage{Name: "demo", Version: "1.0", Wheel: &PipWheel{
					File: "demo-1.0-py3-none-any.whl", Sha256: tc.sha256, Size: int64(len(data)),
				}},
				CachePath: path,
				SHA512:    tc.sha512,
			}
			r, err := openCachedWheel(w)
			if err != nil {
				t.Fatalf("openCachedWheel: %v", err)
			}
			got, err := io.ReadAll(r)
			_ = r.Close()
			if !tc.changed {
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("read = %q, %v; want the cached bytes", got, err)
				}
				return
			}
			if want := w.Wheel.File + " changed after its download"; err == nil || err.Error() != want {
				t.Fatalf("read error = %v, want %q", err, want)
			}
		})
	}
}

func TestPipExportCancelled(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	e.Settings.DownloadParallelism = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &stepRecorder{}
	emit := func(ev Event) {
		rec.emit(ev)
		if ev.Kind != "progress" {
			return
		}
		// Every file a later step writes, so the cleanup has each one to remove.
		for _, name := range []string{archive.PipArchiveFile, "manifest.json", archive.SignatureFile, "export.cdx-input.json"} {
			if err := os.WriteFile(filepath.Join(e.Dir, name), []byte("x"), 0o664); err != nil {
				t.Error(err)
			}
		}
		cancel()
	}
	if err := e.Run(ctx, emit); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	names := stepNames(rec.steps)
	if names[len(names)-1] != "download:failed" || slices.Contains(names, "archive:running") {
		t.Errorf("steps = %v, want download failed and no archive step", names)
	}
	if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
		t.Errorf("export directory holds %v, want only status.json", names)
	}
	var status exportStatusFile
	if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != store.Cancelled {
		t.Errorf("status state = %s, want cancelled", status.State)
	}
}

// A panic past the downloads reaches the queue, which recovers it; the
// export must by then hold only its status, as a failed run does.
func TestPipExportThatPanicsKeepsOnlyItsStatus(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	e.beforeArchive = func() { panic("a bug between the steps") }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := runJob(context.Background(), log, e, (&stepRecorder{}).emit); err == nil || !strings.Contains(err.Error(), "a bug between the steps") {
		t.Fatalf("runJob = %v, want the panic as the job's error", err)
	}
	if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
		t.Errorf("export directory holds %v, want only status.json", names)
	}
	var status exportStatusFile
	if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != store.Failed {
		t.Errorf("status state = %s, want failed", status.State)
	}
}

func TestPipExportRefusesAnEmptySet(t *testing.T) {
	f := runPipAnalysis(t, piptest.NewIndex(t).URL, "# nothing pinned\n", nil)
	e := f.newPipExport(t)
	rec, err := runPipExport(context.Background(), e)
	if want := "the analysis lists no package"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Run = %v, want an error saying %q", err, want)
	}
	if names := stepNames(rec.steps); !slices.Equal(names, []string{"package-list:running", "package-list:failed"}) {
		t.Errorf("steps = %v, want package-list failed", names)
	}
	if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
		t.Errorf("export directory holds %v, want only status.json", names)
	}
}

// The export directory is group-writable, so the tools account can plant a
// link where the archive goes, aimed at a file only the server may write.
func TestPipExportNeverWritesTheArchiveThroughALink(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	victim := filepath.Join(t.TempDir(), "signing-key.pem")
	const held = "a file the server owns"
	if err := os.WriteFile(victim, []byte(held), 0o600); err != nil {
		t.Fatal(err)
	}
	e.beforeArchive = func() {
		if err := os.Symlink(victim, filepath.Join(e.Dir, archive.PipArchiveFile)); err != nil {
			t.Error(err)
		}
	}
	rec, err := runPipExport(context.Background(), e)
	if err == nil || !strings.Contains(err.Error(), "create the archive") {
		t.Fatalf("Run = %v, want the archive's creation refused", err)
	}
	if got := string(readFile(t, victim)); got != held {
		t.Errorf("the link's target now holds %d bytes, want it untouched", len(got))
	}
	last := rec.steps[len(rec.steps)-1]
	if last.Name != "archive" || last.State != string(store.Failed) {
		t.Errorf("last step = %+v, want archive failed", last)
	}
	if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
		t.Errorf("export directory holds %v, want only status.json", names)
	}
}

// exportTrivy is cannedTrivy with the conversion an export also runs.
type exportTrivy struct {
	*cannedTrivy
	convertErr error
}

// convertedReport is what exportTrivy writes as report.cdx.json.
const convertedReport = `{"bomFormat":"CycloneDX","specVersion":"1.6","from":"exportTrivy"}`

func (x *exportTrivy) ConvertToCycloneDX(_ context.Context, _, outPath string) (string, error) {
	if x.convertErr != nil {
		return "FATAL convert failed", x.convertErr
	}
	return "", os.WriteFile(outPath, []byte(convertedReport), 0o664)
}

// pipExportFiles are the files a done pip export holds, sorted.
var pipExportFiles = []string{
	"findings.csv", "manifest.json", archive.SignatureFile, archive.PipArchiveFile,
	"report.cdx.json", "report.trivy.json", "summary.md",
}

// scannedBy gives e an export scan that reports rows, and returns it.
func scannedBy(e *PipExport, rows ...[5]string) *exportTrivy {
	x := &exportTrivy{cannedTrivy: &cannedTrivy{report: pipTrivyReport(rows...)}}
	e.Trivy = x
	return x
}

func TestPipExportWritesTheFourReports(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	trivy := scannedBy(e, [5]string{"idna", "3.10", "CVE-2024-3651", "MEDIUM", "3.7"})
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if names := dirNames(t, e.Dir); !slices.Equal(names, pipExportFiles) {
		t.Fatalf("export directory holds %v, want %v", names, pipExportFiles)
	}
	var got, want any
	if err := json.Unmarshal(readFile(t, filepath.Join(e.Dir, "report.trivy.json")), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(trivy.report), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("report.trivy.json = %v, want the export scan's report %v", got, want)
	}
	if got := string(readFile(t, filepath.Join(e.Dir, "report.cdx.json"))); got != convertedReport {
		t.Errorf("report.cdx.json = %s, want the conversion of the export scan", got)
	}
	csvText := string(readFile(t, filepath.Join(e.Dir, "findings.csv")))
	if want := strings.Join(report.PipFindingsHeader, ",") + "\nidna,3.10,,CVE-2024-3651,medium,3.7,test finding\n"; csvText != want {
		t.Errorf("findings.csv =\n%s\nwant\n%s", csvText, want)
	}

	var analysis statusFile
	if err := f.st.ReadJSON(filepath.Join(f.ref.Dir, "status.json"), &analysis); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, filepath.Join(e.Dir, archive.PipArchiveFile))
	summary := string(readFile(t, filepath.Join(e.Dir, "summary.md")))
	for _, want := range []string{
		"- Analysis date: " + analysis.CreatedAt.Format(time.RFC3339) + "\n",
		"- Target: Python 3.11.2, linux/x86_64 glibc 2.28, uv 0.13.7\n",
		"## Requirements files\n\n- requirements.txt\n\n",
		"| In the archive | 0 | 0 | 1 | 0 | 0 |\n",
		"## Critical and high CVEs\n\nNone.\n",
		fmt.Sprintf("- Size: %d bytes\n- SHA-256: %s\n- Packages: 3\n", len(data), sha256Hex(data)),
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary.md lacks %q:\n%s", want, summary)
		}
	}
}

// jinjaSet holds a project the index names Jinja2, a hyphenated name
// Trivy may spell with a dot, and a transitive package.
var jinjaSet = resolved("certifi", "2024.8.30", "jinja2", "3.1.2", "markupsafe", "3.0.2", "requests", "2.32.3", "typing-extensions", "4.12.2")

func TestPipExportScansPyPIComponents(t *testing.T) {
	ix := piptest.NewIndex(t)
	for _, p := range jinjaSet {
		ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
	}
	f := runPipAnalysis(t, ix.URL, "Jinja2==3.1.2\nrequests==2.32.3\ntyping_extensions==4.12.2\n", jinjaSet)
	e := f.newPipExport(t)
	trivy := scannedBy(e,
		[5]string{"Jinja2", "3.1.2", "CVE-2024-56326", "HIGH", "3.1.5"},
		[5]string{"MarkupSafe", "3.0.2", "CVE-2099-0001", "LOW", ""},
		[5]string{"typing.extensions", "4.12.2", "CVE-2099-0002", "LOW", ""},
		[5]string{"typing-extensions", "4.12.2", "CVE-2099-0002", "LOW", ""},
	)
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(trivy.sbom, &doc); err != nil {
		t.Fatalf("decode the scanned SBOM: %v", err)
	}
	purls := map[string]bool{}
	for _, c := range doc.Components {
		purls[c.PURL] = true
	}
	var want []string
	for _, p := range jinjaSet {
		want = append(want, "pkg:pypi/"+pip.Normalize(p.Name)+"@"+p.Version)
	}
	if got := slices.Sorted(maps.Keys(purls)); !slices.Equal(got, want) {
		t.Errorf("the scanned SBOM lists %v, want %v", got, want)
	}

	csvText := string(readFile(t, filepath.Join(e.Dir, "findings.csv")))
	for _, row := range []string{
		"\njinja2,3.1.2,requirements.txt,CVE-2024-56326,high,3.1.5,test finding\n",
		"\nmarkupsafe,3.0.2,,CVE-2099-0001,low,,test finding\n",
		"\ntyping-extensions,4.12.2,requirements.txt,CVE-2099-0002,low,,test finding\n",
	} {
		if strings.Count(csvText, row) != 1 {
			t.Errorf("findings.csv holds %q %d times, want once:\n%s", strings.TrimSpace(row), strings.Count(csvText, row), csvText)
		}
	}
	if lines := strings.Count(csvText, "\n"); lines != 4 {
		t.Errorf("findings.csv holds %d lines, want the header and 3 rows:\n%s", lines, csvText)
	}
	summary := string(readFile(t, filepath.Join(e.Dir, "summary.md")))
	for _, want := range []string{
		"- [high] CVE-2024-56326 in jinja2==3.1.2, fixed in 3.1.5: test finding\n",
		"| In the archive | 0 | 1 | 0 | 2 | 0 |\n",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary.md lacks %q:\n%s", want, summary)
		}
	}
}

// trivyIdentifier, trivyPackage and trivyVulnerability are the parts of a
// Trivy JSON report that name a package, as Trivy 0.76 writes them.
type trivyIdentifier struct {
	PURL   string `json:"PURL"`
	BOMRef string `json:"BOMRef"`
}

type trivyPackage struct {
	ID         string          `json:"ID"`
	Name       string          `json:"Name"`
	Identifier trivyIdentifier `json:"Identifier"`
	Version    string          `json:"Version"`
}

type trivyVulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgID            string          `json:"PkgID"`
	PkgName          string          `json:"PkgName"`
	PkgIdentifier    trivyIdentifier `json:"PkgIdentifier"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Severity         string          `json:"Severity"`
	Title            string          `json:"Title"`
}

type trivyResults struct {
	Results []struct {
		Packages        []trivyPackage       `json:"Packages"`
		Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

// listingTrivy scans as Trivy does: its report lists a package for each
// component of the SBOM, with the component's name, purl and bom-ref, and
// a row's vulnerability on each component of the row's name and version.
// Its conversion lists a CycloneDX component for each package of the
// report and a vulnerability for each of the report's, as trivy convert
// does.
type listingTrivy struct {
	rows [][5]string
}

func (l *listingTrivy) ScanSBOM(_ context.Context, sbomPath, outPath string) (string, error) {
	var doc struct {
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	data, err := os.ReadFile(sbomPath)
	if err == nil {
		err = json.Unmarshal(data, &doc)
	}
	if err != nil {
		return "", err
	}
	var pkgs []trivyPackage
	var vulns []trivyVulnerability
	for _, c := range doc.Components {
		p := trivyPackage{ID: c.Name + "@" + c.Version, Name: c.Name, Version: c.Version, Identifier: trivyIdentifier{PURL: c.PURL, BOMRef: c.BOMRef}}
		pkgs = append(pkgs, p)
		for _, r := range l.rows {
			if r[0] == c.Name && r[1] == c.Version {
				vulns = append(vulns, trivyVulnerability{
					VulnerabilityID: r[2], PkgID: p.ID, PkgName: p.Name, PkgIdentifier: p.Identifier,
					InstalledVersion: p.Version, Severity: r[3], FixedVersion: r[4], Title: "test finding",
				})
			}
		}
	}
	report := map[string]any{"SchemaVersion": 2, "Results": []any{map[string]any{
		"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg", "Packages": pkgs, "Vulnerabilities": vulns,
	}}}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return "", os.WriteFile(outPath, out, 0o664)
}

func (l *listingTrivy) ConvertToCycloneDX(_ context.Context, reportPath, outPath string) (string, error) {
	var report trivyResults
	data, err := os.ReadFile(reportPath)
	if err == nil {
		err = json.Unmarshal(data, &report)
	}
	if err != nil {
		return "", err
	}
	type component struct {
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	}
	type affect struct {
		Ref string `json:"ref"`
	}
	type vulnerability struct {
		ID      string   `json:"id"`
		Affects []affect `json:"affects"`
	}
	doc := struct {
		BOMFormat       string          `json:"bomFormat"`
		Components      []component     `json:"components"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}{BOMFormat: "CycloneDX"}
	for _, r := range report.Results {
		for _, p := range r.Packages {
			doc.Components = append(doc.Components, component{BOMRef: p.Identifier.BOMRef, Name: p.Name, Version: p.Version, PURL: p.Identifier.PURL})
		}
		for _, v := range r.Vulnerabilities {
			doc.Vulnerabilities = append(doc.Vulnerabilities, vulnerability{ID: v.VulnerabilityID, Affects: []affect{{Ref: v.PkgIdentifier.BOMRef}}})
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return "", os.WriteFile(outPath, out, 0o664)
}

func (l *listingTrivy) UpdateDB(context.Context) (string, error) { return "", nil }

func TestPipExportReportsListEachWheelOnce(t *testing.T) {
	ix := piptest.NewIndex(t)
	for _, p := range jinjaSet {
		ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
	}
	f := runPipAnalysis(t, ix.URL, "Jinja2==3.1.2\nrequests==2.32.3\ntyping_extensions==4.12.2\n", jinjaSet)
	e := f.newPipExport(t)
	e.Trivy = &listingTrivy{rows: [][5]string{
		{"jinja2", "3.1.2", "CVE-2024-56326", "HIGH", "3.1.5"},
		// Published under the dotted spelling only, as plone.namedfile's are.
		{"typing.extensions", "4.12.2", "CVE-2099-0005", "LOW", ""},
		{"typing.extensions", "4.12.2", "CVE-2099-0006", "LOW", ""},
		{"typing-extensions", "4.12.2", "CVE-2099-0006", "LOW", ""},
	}}
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var wheels []string
	for _, p := range jinjaSet {
		wheels = append(wheels, pip.Normalize(p.Name)+"@"+p.Version)
	}
	slices.Sort(wheels)

	var cdx struct {
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(e.Dir, "report.cdx.json")), &cdx); err != nil {
		t.Fatal(err)
	}
	var components []string
	refs := map[string]string{}
	for _, c := range cdx.Components {
		components = append(components, c.Name+"@"+c.Version)
		refs[c.BOMRef] = c.Name
	}
	slices.Sort(components)
	if !slices.Equal(components, wheels) {
		t.Errorf("report.cdx.json lists %v, want the %d wheels %v", components, len(wheels), wheels)
	}
	var affected []string
	for _, v := range cdx.Vulnerabilities {
		for _, a := range v.Affects {
			affected = append(affected, v.ID+" on "+refs[a.Ref])
		}
	}
	slices.Sort(affected)
	if want := []string{"CVE-2024-56326 on jinja2", "CVE-2099-0005 on typing-extensions", "CVE-2099-0006 on typing-extensions"}; !slices.Equal(affected, want) {
		t.Errorf("report.cdx.json's vulnerabilities affect %v, want %v", affected, want)
	}

	var trivy trivyResults
	if err := json.Unmarshal(readFile(t, filepath.Join(e.Dir, "report.trivy.json")), &trivy); err != nil {
		t.Fatal(err)
	}
	var packages, vulns []string
	for _, r := range trivy.Results {
		for _, p := range r.Packages {
			packages = append(packages, p.Name+"@"+p.Version)
		}
		for _, v := range r.Vulnerabilities {
			vulns = append(vulns, v.VulnerabilityID+" on "+v.PkgName+" "+v.PkgID+" "+v.PkgIdentifier.BOMRef)
		}
	}
	slices.Sort(packages)
	if !slices.Equal(packages, wheels) {
		t.Errorf("report.trivy.json lists %v, want the %d wheels %v", packages, len(wheels), wheels)
	}
	slices.Sort(vulns)
	if want := []string{
		"CVE-2024-56326 on jinja2 jinja2@3.1.2 pkg:pypi/jinja2@3.1.2",
		"CVE-2099-0005 on typing-extensions typing-extensions@4.12.2 pkg:pypi/typing-extensions@4.12.2",
		"CVE-2099-0006 on typing-extensions typing-extensions@4.12.2 pkg:pypi/typing-extensions@4.12.2",
	}; !slices.Equal(vulns, want) {
		t.Errorf("report.trivy.json's vulnerabilities = %v, want %v", vulns, want)
	}
	csvText := string(readFile(t, filepath.Join(e.Dir, "findings.csv")))
	if want := "\ntyping-extensions,4.12.2,requirements.txt,CVE-2099-0005,low,,test finding\n"; !strings.Contains(csvText, want) {
		t.Errorf("findings.csv lacks the finding published under the dotted spelling:\n%s", csvText)
	}
}

func TestPipExportFindingsComeFromTheExportScan(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	for _, p := range f.ref.Result.Packages {
		if len(p.CVEs) != 0 {
			t.Fatalf("the analysis found %v on %s, want none so the export's scan stands alone", p.CVEs, p.Name)
		}
	}
	e := f.newPipExport(t)
	scannedBy(e, [5]string{"requests", "2.32.3", "CVE-2099-0003", "CRITICAL", "2.32.4"})
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}
	csvText := string(readFile(t, filepath.Join(e.Dir, "findings.csv")))
	if want := "\nrequests,2.32.3,requirements.txt,CVE-2099-0003,critical,2.32.4,test finding\n"; !strings.Contains(csvText, want) {
		t.Errorf("findings.csv lacks the export scan's finding:\n%s", csvText)
	}
	summary := string(readFile(t, filepath.Join(e.Dir, "summary.md")))
	for _, want := range []string{
		"| In the archive | 1 | 0 | 0 | 0 | 0 |\n",
		"- [critical] CVE-2099-0003 in requests==2.32.3, fixed in 2.32.4: test finding\n",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary.md lacks %q:\n%s", want, summary)
		}
	}
}

func TestPipExportSummaryCarriesTheAnalysisWarnings(t *testing.T) {
	ix := piptest.NewIndex(t)
	for _, p := range pipExportSet {
		ix.Add(piptest.Dist{Name: p.Name, Version: p.Version, Tag: "py3-none-any", Uploaded: released})
	}
	outside := pipTrivyReport([5]string{"urllib3", "1.26.0", "CVE-2099-0004", "LOW", ""})
	f := runScannedPipAnalysis(t, ix.URL, "requests==2.32.3\n", pipExportSet, outside)
	const warning = "1 Trivy finding matched no package of the resolved set: urllib3@1.26.0"
	if !slices.Contains(f.ref.Result.Warnings, warning) {
		t.Fatalf("the analysis warned %q, want %q among them", f.ref.Result.Warnings, warning)
	}
	e := f.newPipExport(t)
	scannedBy(e)
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}
	summary := string(readFile(t, filepath.Join(e.Dir, "summary.md")))
	want := "## Warnings from the analysis\n\n- " + strings.Join(f.ref.Result.Warnings, "\n- ") + "\n\n"
	if !strings.Contains(summary, want) {
		t.Errorf("summary.md lacks the analysis's warnings %q:\n%s", want, summary)
	}
}

// fifoTrivy leaves a FIFO where its scan should write the report, as a
// compromised Trivy could.
type fifoTrivy struct{ *exportTrivy }

func (x fifoTrivy) ScanSBOM(_ context.Context, _, outPath string) (string, error) {
	return "", syscall.Mkfifo(outPath, 0o660)
}

func TestPipExportReadsNoFIFOTheToolsAccountLeft(t *testing.T) {
	t.Run("at the export scan's report", func(t *testing.T) {
		f := donePipAnalysis(t, piptest.NewIndex(t))
		e := f.newPipExport(t)
		e.Trivy = fifoTrivy{&exportTrivy{cannedTrivy: &cannedTrivy{}}}
		var err error
		returnsPromptly(t, filepath.Join(e.Dir, "report.trivy.json"), func() { _, err = runPipExport(context.Background(), e) })
		if err == nil || !strings.Contains(err.Error(), "report.trivy.json is not a regular file") {
			t.Fatalf("Run = %v, want the report refused", err)
		}
		if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
			t.Errorf("export directory holds %v, want only status.json", names)
		}
	})
	t.Run("at the analysis's status.json", func(t *testing.T) {
		f := donePipAnalysis(t, piptest.NewIndex(t))
		e := f.newPipExport(t)
		scannedBy(e)
		status := filepath.Join(f.ref.Dir, "status.json")
		if err := os.Remove(status); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(status, 0o660); err != nil {
			t.Fatal(err)
		}
		var err error
		returnsPromptly(t, status, func() { _, err = runPipExport(context.Background(), e) })
		if err != nil {
			t.Fatalf("Run: %v, want the export done without the analysis's dates", err)
		}
		if names := dirNames(t, e.Dir); !slices.Equal(names, pipExportFiles) {
			t.Errorf("export directory holds %v, want %v", names, pipExportFiles)
		}
	})
}

func TestPipExportFailsWhenTheScanFails(t *testing.T) {
	cases := []struct {
		name   string
		trivy  *exportTrivy
		reason string
	}{
		{"the scan fails", &exportTrivy{cannedTrivy: &cannedTrivy{scanErr: errors.New("database locked")}}, "scan the exported set: database locked"},
		{"the conversion fails", &exportTrivy{cannedTrivy: &cannedTrivy{report: pipTrivyReport()}, convertErr: errors.New("bad report")}, "convert the export scan to CycloneDX: bad report"},
		{"the report is not JSON", &exportTrivy{cannedTrivy: &cannedTrivy{report: "FATAL"}}, "read report.trivy.json"},
		// A package with no name or version matches a vulnerability with
		// none, which the fold would then write into.
		{"a vulnerability is not an object", &exportTrivy{cannedTrivy: &cannedTrivy{report: `{"SchemaVersion":2,"Results":[{"Packages":[{"ID":"x"}],"Vulnerabilities":[null]}]}`}}, "read report.trivy.json: Vulnerabilities holds a value that is not an object"},
		{"a package is not an object", &exportTrivy{cannedTrivy: &cannedTrivy{report: `{"SchemaVersion":2,"Results":[{"Packages":[null]}]}`}}, "read report.trivy.json: Packages holds a value that is not an object"},
		{"a result is not an object", &exportTrivy{cannedTrivy: &cannedTrivy{report: `{"SchemaVersion":2,"Results":[null]}`}}, "read report.trivy.json: Results holds a value that is not an object"},
		{"the packages are not a list", &exportTrivy{cannedTrivy: &cannedTrivy{report: `{"SchemaVersion":2,"Results":[{"Packages":{}}]}`}}, "read report.trivy.json: Packages is not a list"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := donePipAnalysis(t, piptest.NewIndex(t))
			e := f.newPipExport(t)
			e.Trivy = c.trivy
			rec, err := runPipExport(context.Background(), e)
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("Run = %v, want an error saying %q", err, c.reason)
			}
			last := rec.steps[len(rec.steps)-1]
			if last.Name != "reports" || last.State != string(store.Failed) || !strings.Contains(last.Error, c.reason) {
				t.Errorf("last step = %+v, want reports failed saying %q", last, c.reason)
			}
			if names := dirNames(t, e.Dir); !slices.Equal(names, []string{"status.json"}) {
				t.Errorf("export directory holds %v, want only status.json", names)
			}
			var status exportStatusFile
			if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
				t.Fatal(err)
			}
			if status.State != store.Failed {
				t.Errorf("status state = %s, want failed", status.State)
			}
		})
	}
}

// TestCheckPipWheelNameBound pins the wheel name bound at its edge: a name
// that fills out/<file> to the archive's entry name bound passes, one byte
// more is refused.
func TestCheckPipWheelNameBound(t *testing.T) {
	bound := archive.DefaultLimits.NameBytes - len(pipArchiveDir)
	name := func(n int) string {
		head, tail := "idna-3.10-py3-none-", ".whl"
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	for _, c := range []struct {
		size    int
		refused bool
	}{{bound, false}, {bound + 1, true}} {
		p := PipPackage{Name: "idna", Version: "3.10", Wheel: &PipWheel{File: name(c.size), Sha256: strings.Repeat("ab", 32), Size: 1}}
		err := checkPipWheel(p)
		if refused := err != nil && strings.Contains(err.Error(), "longer than an archive entry name"); refused != c.refused {
			t.Errorf("a %d-byte wheel name: err = %v, want refused %v", c.size, err, c.refused)
		}
	}
}

func TestPipExportRefusesAManifestTheImportCannotRead(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	w := pipWheelFile{PipPackage: PipPackage{Name: "demo", Version: "1.0", Wheel: &PipWheel{File: strings.Repeat("a", archive.MaxManifestSize)}}}
	err := e.writeManifest([]pipWheelFile{w}, report.ArchiveManifest{}, f.st.SigningKey())
	if err == nil || !strings.Contains(err.Error(), "larger than the 16777216 bytes the import reads") {
		t.Fatalf("writeManifest = %v, want the manifest refused for its size", err)
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "manifest.json")); !os.IsNotExist(err) {
		t.Errorf("manifest.json was written: %v", err)
	}
}

func TestPipExportFailsBeforeAnyDownloadWithAKeyThatDoesNotRead(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	keyFile := filepath.Join(f.st.Root(), "private", "signing-key.pem")
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec, err := runPipExport(context.Background(), e)
	if err == nil || !strings.Contains(err.Error(), keyFile) {
		t.Fatalf("Run = %v, want an error naming %s", err, keyFile)
	}
	if steps := stepNames(rec.steps); slices.Contains(steps, "download:running") {
		t.Errorf("steps = %v, want no download with a key that does not read", steps)
	}
	// Without a failed step the screen would show the failure with no cause.
	var status exportStatusFile
	if err := json.Unmarshal(readFile(t, filepath.Join(e.Dir, "status.json")), &status); err != nil {
		t.Fatal(err)
	}
	const cause = "store: signing key private/signing-key.pem is not"
	if len(status.Steps) == 0 || status.Steps[0].Name != "prepare" || status.Steps[0].State != string(store.Failed) || !strings.HasPrefix(status.Steps[0].Error, cause) {
		t.Errorf("status.json steps = %+v, want a failed prepare step starting %q", status.Steps, cause)
	}
	if len(rec.steps) == 0 || !strings.HasPrefix(rec.steps[0].Error, cause) {
		t.Errorf("step events = %+v, want a prepare cause starting %q", rec.steps, cause)
	}
}

// A regenerate while the export runs must not split the manifest and the
// signature across two keys.
func TestPipExportSignsWithTheKeyItStartedWith(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	before := f.st.SigningKey()
	e.beforeArchive = func() {
		if _, _, err := store.ReplaceSigningKey(f.st.Root(), os.Getuid()); err != nil {
			t.Error(err)
		}
	}
	if _, err := runPipExport(context.Background(), e); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.st.SigningKey().PublicKeySHA256 == before.PublicKeySHA256 {
		t.Fatal("the key was not regenerated during the export, the test proves nothing")
	}
	manifest := readFile(t, filepath.Join(e.Dir, "manifest.json"))
	sig := readFile(t, filepath.Join(e.Dir, archive.SignatureFile))
	if err := archive.CheckSignature(manifest, sig, publicKey(t, before)); err != nil {
		t.Errorf("the signature does not verify with the key the export began with: %v", err)
	}
}

// A step past prepare fails with an error naming a path under the data
// root; its cause, in the step event and in status.json, names none.
func TestPipExportDownloadCauseNamesNoDataDirectory(t *testing.T) {
	f := donePipAnalysis(t, piptest.NewIndex(t))
	e := f.newPipExport(t)
	root := f.st.Root()
	if err := os.RemoveAll(filepath.Join(root, "cache", "wheels")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "cache"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cache", "wheels"), nil, 0o660); err != nil {
		t.Fatal(err)
	}

	rec, err := runPipExport(context.Background(), e)
	if err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("Run = %v, want an error naming %s", err, root)
	}
	last := rec.steps[len(rec.steps)-1]
	if last.State != string(store.Failed) || last.Error == "" || strings.Contains(last.Error, root) {
		t.Errorf("last step = %+v, want a cause without %s", last, root)
	}
	var status exportStatusFile
	if err := f.st.ReadJSON(filepath.Join(e.Dir, "status.json"), &status); err != nil {
		t.Fatal(err)
	}
	for _, s := range status.Steps {
		if strings.Contains(s.Error, root) {
			t.Errorf("status.json step %+v names %s", s, root)
		}
	}
}
