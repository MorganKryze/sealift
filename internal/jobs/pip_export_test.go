package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// pipExportSet is the resolved set of the analysis most pip export tests
// start from, sorted as the analysis sorts it.
var pipExportSet = resolved("certifi", "2024.8.30", "idna", "3.10", "requests", "2.32.3")

// pipFixture is a done pip analysis and the store that holds it.
type pipFixture struct {
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
	return pipFixture{st: st, project: project, ref: PipAnalysisRef{
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
		{"too many bytes", 3, pip.MaxWheelBytes, fmt.Sprintf("%d bytes", archive.DefaultLimits.Unpacked)},
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
