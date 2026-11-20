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
	svc, st := newTestService(t)
	svc.trivy = &cannedTrivy{report: pipTrivyReport()}
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
		Trivy:    &cannedTrivy{report: pipTrivyReport()},
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
	if want := []string{"manifest.json", archive.SignatureFile, archive.PipArchiveFile}; !slices.Equal(dirNames(t, e.Dir), want) {
		t.Errorf("export directory holds %v, want %v", dirNames(t, e.Dir), want)
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

func TestPipExportFailsWhenAWheelChangesBeforeTheArchive(t *testing.T) {
	tests := []struct {
		name   string
		change func(data []byte) []byte
	}{
		{"other bytes of the same length", func(data []byte) []byte { return bytes.Repeat([]byte("x"), len(data)) }},
		{"one byte shorter", func(data []byte) []byte { return data[:len(data)-1] }},
		{"one byte longer", func(data []byte) []byte { return append(slices.Clone(data), 'x') }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := donePipAnalysis(t, piptest.NewIndex(t))
			e := f.newPipExport(t)
			w := *f.ref.Result.Packages[1].Wheel
			e.beforeArchive = func() {
				path := filepath.Join(f.st.Root(), "cache", "wheels", w.Sha256+".whl")
				if err := os.WriteFile(path, tc.change(readFile(t, path)), 0o664); err != nil {
					t.Error(err)
				}
			}
			rec, err := runPipExport(context.Background(), e)
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
