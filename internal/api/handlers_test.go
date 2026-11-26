package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
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

	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/pip"
)

// newTestServer builds a full router against a fresh store and returns an
// httptest.Server, so every case below exercises the real mux, the real
// strict dispatch and Problem Details encoding, not the handler in
// isolation.
func newTestServer(t *testing.T) (*httptest.Server, *Handlers) {
	t.Helper()
	q := jobs.NewQueue(nil)
	h := newTestHandlers(t, q)
	// Registered after the store's temporary directory, so it runs first:
	// a job still writing into that directory would otherwise make its
	// removal fail.
	t.Cleanup(q.Close)
	srv := httptest.NewServer(Routes(h, testStatic()))
	t.Cleanup(srv.Close)
	return srv, h
}

// createProject posts a multipart package.json to /api/projects and
// decodes the response into a Project.
func createProject(t *testing.T, srv *httptest.Server, manifest string) (Project, *http.Response) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("manifest", "package.json")
	if err != nil {
		t.Fatalf("create manifest part: %v", err)
	}
	if _, err := part.Write([]byte(manifest)); err != nil {
		t.Fatalf("write manifest part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	resp, err := http.Post(srv.URL+"/api/projects", w.FormDataContentType(), &body)
	if err != nil {
		t.Fatalf("POST /api/projects: %v", err)
	}
	defer resp.Body.Close()

	var project Project
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(data, &project); err != nil {
			t.Fatalf("decode project: %v (body %s)", err, data)
		}
	}
	return project, &http.Response{StatusCode: resp.StatusCode, Body: io.NopCloser(bytes.NewReader(data))}
}

func TestCreateProjectQueuesAnAnalysisAndListsIt(t *testing.T) {
	srv, _ := newTestServer(t)

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201, body: %s", resp.StatusCode, body)
	}
	if project.Id == "" || project.Name != "left-pad" {
		t.Fatalf("project = %+v, want a named project with an id", project)
	}
	if project.Analyses == nil || len(*project.Analyses) != 1 {
		t.Fatalf("project.Analyses = %v, want exactly the queued analysis", project.Analyses)
	}
	if state := (*project.Analyses)[0].State; state != Queued && state != Running && state != Done && state != Failed {
		t.Errorf("queued analysis state = %q, want a recognized state", state)
	}

	listResp, err := http.Get(srv.URL + "/api/projects")
	if err != nil {
		t.Fatalf("GET /api/projects: %v", err)
	}
	defer listResp.Body.Close()
	var list []ProjectSummary
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode project list: %v", err)
	}
	if len(list) != 1 || list[0].Id != project.Id {
		t.Fatalf("ListProjects = %+v, want one entry for %q", list, project.Id)
	}
}

func TestCreateProjectInvalidManifestListsEveryEntry(t *testing.T) {
	srv, _ := newTestServer(t)

	manifest := `{"name":"bad","dependencies":{"left-pad":"^1.3.0"},"devDependencies":{"esbuild":"latest"},"overrides":{"x":"1.0.0"}}`
	_, resp := createProject(t, srv, manifest)
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400, body: %s", resp.StatusCode, body)
	}
	var problem Problem
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Errors == nil || len(*problem.Errors) != 3 {
		t.Fatalf("problem.Errors = %v, want the 3 offending entries (2 dependencies, 1 unsupported field)", problem.Errors)
	}
}

func TestCreateProjectMissingManifestFieldReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	resp, err := http.Post(srv.URL+"/api/projects", w.FormDataContentType(), &body)
	if err != nil {
		t.Fatalf("POST /api/projects: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGetProjectUnknownIDReturns404WithProblemDetails(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/projects/does-not-exist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem Problem
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Status != http.StatusNotFound {
		t.Errorf("problem.Status = %d, want 404", problem.Status)
	}
}

func TestGetAnalysisAndExportUnknownIDReturn404(t *testing.T) {
	srv, _ := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	for _, path := range []string{
		fmt.Sprintf("/api/projects/%s/analyses/does-not-exist", project.Id),
		fmt.Sprintf("/api/projects/%s/exports/does-not-exist", project.Id),
	} {
		got, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		got.Body.Close()
		if got.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, got.StatusCode)
		}
	}
}

// TestGetAnalysisAfterNullSurvivesThroughTheAPI proves a nil After in
// ranking.json, the case once step 9 (check-combined) never measured it,
// reaches a caller of GetAnalysis as null rather than a decode failure
// dropping the whole result or a zero vector claiming a measurement that
// never happened.
func TestGetAnalysisAfterNullSurvivesThroughTheAPI(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":null,` +
		`"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	resp2, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET analysis: %v", err)
	}
	defer resp2.Body.Close()
	data, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body: %s", resp2.StatusCode, data)
	}
	if !bytes.Contains(data, []byte(`"after":null`)) {
		t.Errorf("response body has no explicit null after field, want one, body: %s", data)
	}

	var got Analysis
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode: %v, body: %s", err, data)
	}
	if got.Result == nil {
		t.Fatalf("Result decoded as nil, want ranking.json's fields carried through, body: %s", data)
	}
	if got.Result.After != nil {
		t.Errorf("Result.After = %v, want nil", got.Result.After)
	}
}

func TestQueueExportInvalidSelectionReturns400WithEveryEntry(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],` +
		`"dependencies":[{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"candidates":[{"version":"1.3.1","vector":[0,0,0,0,0],"signals":[],"key":true,"resolved":true}]}],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	body, _ := json.Marshal(ExportRequest{Selection: map[string][]string{"left-pad": {"9.9.9"}}})
	resp2, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 400, body: %s", resp2.StatusCode, data)
	}
	var problem Problem
	if err := json.NewDecoder(resp2.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Errors == nil || len(*problem.Errors) != 1 {
		t.Fatalf("problem.Errors = %v, want exactly the one offending entry", problem.Errors)
	}
	if got := *(*problem.Errors)[0].Name; got != "left-pad@9.9.9" {
		t.Fatalf("problem.Errors[0].Name = %q, want %q", got, "left-pad@9.9.9")
	}

	// Nothing was reserved for the rejected request: no export directory,
	// committed or pending, exists for this project.
	exports, err := h.Store.Exports(project.Id)
	if err != nil {
		t.Fatalf("Exports: %v", err)
	}
	if len(exports) != 0 {
		t.Fatalf("Exports() = %v, want none", exports)
	}
}

// TestQueueExportInvalidSelectionListsOnlyTheBadVersionWhenOneIsGood proves
// the per-entry validation error list is not all-or-nothing at the
// dependency level: left-pad selects one version the analysis resolved
// and one it did not, and only the second is reported.
func TestQueueExportInvalidSelectionListsOnlyTheBadVersionWhenOneIsGood(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],` +
		`"dependencies":[{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"candidates":[{"version":"1.3.1","vector":[0,0,0,0,0],"signals":[],"key":true,"resolved":true}]}],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	// "1.3.1" is a real candidate; "9.9.9" is not.
	body, _ := json.Marshal(ExportRequest{Selection: map[string][]string{"left-pad": {"1.3.1", "9.9.9"}}})
	resp2, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 400, body: %s", resp2.StatusCode, data)
	}
	var problem Problem
	if err := json.NewDecoder(resp2.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Errors == nil || len(*problem.Errors) != 1 {
		t.Fatalf("problem.Errors = %v, want exactly the one bad entry, not the good one too", problem.Errors)
	}
	if got := *(*problem.Errors)[0].Name; got != "left-pad@9.9.9" {
		t.Fatalf("problem.Errors[0].Name = %q, want %q", got, "left-pad@9.9.9")
	}
}

// TestQueueExportAnalysisNotDoneAnswers409 proves the fix for G2:
// jobs.ErrAnalysisNotDone names an analysis in the wrong state for what
// the caller asked, a conflict with the request, not a server failure.
func TestQueueExportAnalysisNotDoneAnswers409(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"failed"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}

	body, _ := json.Marshal(ExportRequest{Selection: map[string][]string{}})
	resp2, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 409, body: %s", resp2.StatusCode, data)
	}
}

// pinnedTrivyRelease points h at a GitHub stand-in that serves release
// 1.2.3 of Trivy for amd64, makes 1.2.3 the pin, and returns the paths the
// stand-in was asked for.
func pinnedTrivyRelease(t *testing.T, h *Handlers) func() []string {
	t.Helper()
	const version = "1.2.3"
	var tarball bytes.Buffer
	gz := gzip.NewWriter(&tarball)
	tw := tar.NewWriter(gz)
	body := "#!/bin/sh\necho fake trivy\n"
	if err := tw.WriteHeader(&tar.Header{Name: "trivy", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tarball.Bytes())
	asset := "trivy_" + version + "_Linux-64bit.tar.gz"

	var mu sync.Mutex
	var paths []string
	var gh *httptest.Server
	gh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/repos/aquasecurity/trivy/releases/tags/v" + version:
			_, _ = fmt.Fprintf(w, `{"tag_name":"v%s","assets":[{"name":%q,"browser_download_url":%q}]}`, version, asset, gh.URL+"/"+asset)
		case "/" + asset:
			_, _ = w.Write(tarball.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(gh.Close)
	h.Tools.GitHubAPI = gh.URL
	h.Tools.Arch = "amd64"
	h.Tools.Trivy = tools.TrivyPin{Version: version, SHA256: map[string]string{"amd64": hex.EncodeToString(sum[:])}}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(paths)
	}
}

// exportTrivyFake is a runner.Trivy whose ScanSBOM and ConvertToCycloneDX
// write a minimal valid report and CycloneDX document, so an export job
// that reaches the reports step can finish without a real Trivy binary.
type exportTrivyFake struct{}

func (exportTrivyFake) ScanSBOM(_ context.Context, _, outPath string) (string, error) {
	return "", os.WriteFile(outPath, []byte(`{"SchemaVersion":2,"Results":[]}`), 0o664)
}

func (exportTrivyFake) ConvertToCycloneDX(_ context.Context, _, outPath string) (string, error) {
	return "", os.WriteFile(outPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`), 0o664)
}

func (exportTrivyFake) UpdateDB(context.Context) (string, error) { return "", nil }

// newTestHandlersWithTrivy is newTestHandlers with exportTrivyFake, for a
// test whose export job must reach the reports step instead of stopping
// at whatever the shared fakeTrivy leaves unwritten.
func newTestHandlersWithTrivy(t *testing.T, q *jobs.Queue) *Handlers {
	t.Helper()
	trivy := exportTrivyFake{}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	seedToolsReady(t, st)
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	tm.GitHubAPI = unroutable
	tm.NPMRegistry = unroutable
	svc := jobs.NewService(st, q, tm, fakePnpm{}, trivy, &npm.Client{})
	return NewHandlers(st, svc, tm)
}

// waitForExportState waits for the export's end, then reads it through
// GetExport and fails the test unless its state is one of wantStates.
func waitForExportState(t *testing.T, h *Handlers, srv *httptest.Server, projectID, exportID string, wantStates ...State) Export {
	t.Helper()
	waitForTerminalState(t, h, projectID, "export", exportID)
	var e Export
	getEnded(t, fmt.Sprintf("%s/api/projects/%s/exports/%s", srv.URL, projectID, exportID), &e)
	if !slices.Contains(wantStates, e.State) {
		t.Fatalf("export %s ended %s, want one of %v", exportID, e.State, wantStates)
	}
	return e
}

// getEnded decodes the 200 answer of a GET on a job that has ended.
func getEnded(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s = %d, body: %s", url, resp.StatusCode, data)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// TestQueueExportMultiVersionSelectionReachesTheJobWithBoth selects two
// versions of the same dependency and lets the export job actually run,
// with a stub pnpm-lock.yaml under each selected version's candidate
// directory: packageList (internal/jobs/export.go) reads every version
// in a dependency's list, so the job only reaches state done if it read
// both, not just the first.
func TestQueueExportMultiVersionSelectionReachesTheJobWithBoth(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlersWithTrivy(t, q)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],` +
		`"dependencies":[{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"candidates":[{"version":"1.3.1","vector":[0,0,0,0,0],"signals":[],"key":true,"resolved":true}]}],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	for _, version := range []string{"1.3.0", "1.3.1"} {
		dir := filepath.Join(analysisDir, "candidates", "left-pad@"+version)
		if err := os.MkdirAll(dir, 0o770); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages: {}\n"), 0o664); err != nil {
			t.Fatalf("write pnpm-lock.yaml for %s: %v", version, err)
		}
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "candidates.trivy.json"), []byte(`{"SchemaVersion":2,"Results":[]}`), 0o664); err != nil {
		t.Fatalf("write candidates.trivy.json: %v", err)
	}

	body, _ := json.Marshal(ExportRequest{Selection: map[string][]string{"left-pad": {"1.3.0", "1.3.1"}}})
	resp2, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 202, body: %s", resp2.StatusCode, data)
	}
	var queued Export
	if err := json.NewDecoder(resp2.Body).Decode(&queued); err != nil {
		t.Fatalf("decode queued export: %v", err)
	}

	final := waitForExportState(t, h, srv, project.Id, queued.Id, Done, Failed)
	if final.State != Done {
		t.Fatalf("export state = %q, want %q: both selected versions of left-pad should resolve with their stub lockfiles", final.State, Done)
	}
}

// TestQueueExportFailureIsVisibleAfterItEnds proves the fix for finding 2:
// a failing export used to remove its own directory, so it vanished from
// GET /projects/{id} within one poll and its cause was never readable
// once the live event stream was gone. The registry here points at an
// unroutable address, so the download step fails deterministically
// without touching the network.
func TestQueueExportFailureIsVisibleAfterItEnds(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	seedToolsReady(t, st)
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	tm.GitHubAPI = unroutable
	tm.NPMRegistry = unroutable
	reg := &npm.Client{Registry: unroutable, Attempts: 1, Backoff: func(int) time.Duration { return 0 }}
	svc := jobs.NewService(st, q, tm, fakePnpm{}, exportTrivyFake{}, reg)
	h := NewHandlers(st, svc, tm)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],` +
		`"dependencies":[{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"candidates":[{"version":"1.3.1","vector":[0,0,0,0,0],"signals":[],"key":true,"resolved":true}]}],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	candidateDir := filepath.Join(analysisDir, "candidates", "left-pad@1.3.1")
	if err := os.MkdirAll(candidateDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	lockfile := "lockfileVersion: '9.0'\npackages:\n  \"left-pad@1.3.1\":\n    resolution: {integrity: sha512-abc123}\n"
	if err := os.WriteFile(filepath.Join(candidateDir, "pnpm-lock.yaml"), []byte(lockfile), 0o664); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "candidates.trivy.json"), []byte(`{"SchemaVersion":2,"Results":[]}`), 0o664); err != nil {
		t.Fatalf("write candidates.trivy.json: %v", err)
	}

	body, _ := json.Marshal(ExportRequest{Selection: map[string][]string{"left-pad": {"1.3.1"}}})
	resp2, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 202, body: %s", resp2.StatusCode, data)
	}
	var queued Export
	if err := json.NewDecoder(resp2.Body).Decode(&queued); err != nil {
		t.Fatalf("decode queued export: %v", err)
	}

	final := waitForExportState(t, h, srv, project.Id, queued.Id, Done, Failed)
	if final.State != Failed {
		t.Fatalf("export state = %q, want %q: the registry is unroutable", final.State, Failed)
	}

	getResp, err := http.Get(fmt.Sprintf("%s/api/projects/%s", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET project: %v", err)
	}
	defer getResp.Body.Close()
	var got Project
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	if got.Exports == nil || len(*got.Exports) == 0 {
		t.Fatalf("GetProject exports = %v, want the failed export still listed", got.Exports)
	}
	listed := (*got.Exports)[0]
	if listed.State != Failed {
		t.Fatalf("listed export state = %q, want %q: it must still be listed after it ended, not vanished", listed.State, Failed)
	}
	if listed.AnalysisId != "20260917T101502Z" {
		t.Errorf("listed export analysisId = %q, want %q", listed.AnalysisId, "20260917T101502Z")
	}
	if listed.Failure == nil || listed.Failure.Message == "" {
		t.Fatalf("listed export failure = %v, want a non-empty cause", listed.Failure)
	}
}

// testBlockingJob is a jobs.Job a test controls through run, used to hold
// the queue busy so a job queued behind it stays deterministically
// queued instead of racing the fake tools to a terminal state.
type testBlockingJob struct {
	run func(context.Context, func(jobs.Event)) error
}

func (j *testBlockingJob) Kind() string { return "blocking" }

func (j *testBlockingJob) Run(ctx context.Context, emit func(jobs.Event)) error {
	return j.run(ctx, emit)
}

// TestGetProjectAndListProjectsShowALiveAnalysisBeforeItCommits pins a
// blocking job in front of the queue first, so the analysis CreateProject
// queues is deterministically still queued, with no committed directory
// at all, when GetProject and ListProjects are asked about it.
func TestGetProjectAndListProjectsShowALiveAnalysisBeforeItCommits(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlers(t, q)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()

	var project Project
	var analysisID string
	release := make(chan struct{})
	blocking := &testBlockingJob{run: func(_ context.Context, _ func(jobs.Event)) error {
		<-release
		return nil
	}}
	if _, err := q.Submit(blocking); err != nil {
		t.Fatalf("Submit(blocking): %v", err)
	}
	// Released and waited out before this test returns, not left to a
	// deferred close: Service's finalizer goroutine keeps writing to the
	// analysis directory after the queued job runs, and t.TempDir's own
	// cleanup racing that goroutine is exactly the kind of flake this
	// test must not leave behind.
	defer func() {
		close(release)
		if analysisID != "" {
			waitForTerminalState(t, h, project.Id, "analysis", analysisID)
		}
	}()

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	analysisID = (*project.Analyses)[0].Id
	if state, _, ok := h.Service.LiveState(project.Id, "analysis", analysisID); !ok || state != store.Queued {
		t.Fatalf("LiveState(%s) = (%v, %v), want it queued behind the blocking job", analysisID, state, ok)
	}

	getResp, err := http.Get(srv.URL + "/api/projects/" + project.Id)
	if err != nil {
		t.Fatalf("GET project: %v", err)
	}
	defer getResp.Body.Close()
	var got Project
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	if got.Analyses == nil || len(*got.Analyses) == 0 || (*got.Analyses)[0].Id != analysisID {
		t.Fatalf("GetProject analyses = %v, want the live analysis %q first", got.Analyses, analysisID)
	}
	if (*got.Analyses)[0].State != Queued {
		t.Fatalf("GetProject analysis state = %q, want %q", (*got.Analyses)[0].State, Queued)
	}

	listResp, err := http.Get(srv.URL + "/api/projects")
	if err != nil {
		t.Fatalf("GET projects: %v", err)
	}
	defer listResp.Body.Close()
	var list []ProjectSummary
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode project list: %v", err)
	}
	if len(list) != 1 || list[0].LastAnalysis == nil || list[0].LastAnalysis.Id != analysisID {
		t.Fatalf("ListProjects = %+v, want LastAnalysis = %q", list, analysisID)
	}
}

// TestGetProjectLiveExportCarriesItsAnalysisID proves the fix for finding
// 1: a queued or running export has no committed directory to read
// analysisId from, so it must come from Service's own tracking instead of
// going out empty. An empty analysisId is what let the web UI's
// exports.filter(e => e.analysisId === analysis.id) drop the live export
// entirely.
func TestGetProjectLiveExportCarriesItsAnalysisID(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlers(t, q)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()

	project, err := h.Store.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	const analysisID = "20260917T101502Z"
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.ID, "analyses", analysisID)
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	// A blocking job holds the queue busy for the whole test, so the export
	// queued behind it stays live (Service still tracking it) deterministically.
	release := make(chan struct{})
	blocking := &testBlockingJob{run: func(_ context.Context, _ func(jobs.Event)) error {
		<-release
		return nil
	}}
	if _, err := q.Submit(blocking); err != nil {
		t.Fatalf("Submit(blocking): %v", err)
	}
	var exportID string
	defer func() {
		close(release)
		if exportID != "" {
			waitForTerminalState(t, h, project.ID, "export", exportID)
		}
	}()

	exportInfo, err := h.Service.QueueExport(project.ID, analysisID, jobs.ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	exportID = exportInfo.ID

	getResp, err := http.Get(srv.URL + "/api/projects/" + project.ID)
	if err != nil {
		t.Fatalf("GET project: %v", err)
	}
	defer getResp.Body.Close()
	var got Project
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	if got.Exports == nil || len(*got.Exports) == 0 {
		t.Fatalf("GetProject exports = %v, want the live export first", got.Exports)
	}
	live := (*got.Exports)[0]
	if live.Id != exportID {
		t.Fatalf("live export id = %q, want %q", live.Id, exportID)
	}
	if live.AnalysisId != analysisID {
		t.Fatalf("live export analysisId = %q, want %q (an empty analysisId is what dropped the live export from the web UI's relatedExport filter)", live.AnalysisId, analysisID)
	}
}

func TestSettingsHaveNoSignatureKey(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/settings")
	if err != nil {
		t.Fatalf("GET /api/settings: %v", err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if _, ok := got["signatureKey"]; ok {
		t.Fatalf("GET /api/settings = %v, want no signatureKey", got)
	}
}

// assertServesNothingOutsideProjects plants, one row at a time, a link that
// leaves projects/ at each component of rel, the path a route reads there,
// or a loop of links at its last one, and expects the route at url to
// answer 404 without the signing key's bytes. The tools account can write
// every directory under projects/.
func assertServesNothingOutsideProjects(t *testing.T, url string, rel []string) {
	t.Helper()
	for depth := range rel {
		for _, relative := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, relative %v", filepath.Join(rel[:depth+1]...), relative), func(t *testing.T) {
				srv, h := newTestServer(t)
				root := h.Store.Root()
				key, err := os.ReadFile(filepath.Join(root, "private", "signing-key.pem"))
				if err != nil {
					t.Fatal(err)
				}
				at := filepath.Join(append([]string{root, "projects"}, rel[:depth+1]...)...)
				rest := rel[depth+1:]
				// The link points at the key for the last component, at
				// private/ when only the key's name follows, and otherwise at
				// a directory under cache/ holding the key's bytes at the rest
				// of rel.
				target := filepath.Join(root, "private", "signing-key.pem")
				switch {
				case len(rest) == 1 && rest[0] == "signing-key.pem":
					target = filepath.Join(root, "private")
				case len(rest) > 0:
					target = filepath.Join(root, "cache", "planted")
					copied := filepath.Join(append([]string{target}, rest...)...)
					if err := os.MkdirAll(filepath.Dir(copied), 0o770); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(copied, key, 0o664); err != nil {
						t.Fatal(err)
					}
				}
				if relative {
					if target, err = filepath.Rel(filepath.Dir(at), target); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.MkdirAll(filepath.Dir(at), 0o770); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, at); err != nil {
					t.Fatal(err)
				}
				assertNotFoundWithoutKey(t, srv.URL+url, key)
			})
		}
	}
	// Two links to each other stay inside projects/, so only the loop
	// itself refuses them.
	t.Run("a loop of links", func(t *testing.T) {
		srv, h := newTestServer(t)
		root := h.Store.Root()
		key, err := os.ReadFile(filepath.Join(root, "private", "signing-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		at := filepath.Join(append([]string{root, "projects"}, rel...)...)
		if err := os.MkdirAll(filepath.Dir(at), 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(at)+".loop", at); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(at), at+".loop"); err != nil {
			t.Fatal(err)
		}
		assertNotFoundWithoutKey(t, srv.URL+url, key)
	})
}

func assertNotFoundWithoutKey(t *testing.T, url string, key []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, key) {
		t.Fatalf("GET %s served the signing key (status %d)", url, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET %s status = %d, want 404", url, resp.StatusCode)
	}
}

func TestDownloadExportFileServesNothingOutsideProjects(t *testing.T) {
	assertServesNothingOutsideProjects(t, "/api/projects/x/exports/20260917T101502Z/files/signing-key.pem",
		[]string{"x", "exports", "20260917T101502Z", "signing-key.pem"})
}

func TestGetAnalysisLogServesNothingOutsideProjects(t *testing.T) {
	assertServesNothingOutsideProjects(t, "/api/projects/x/analyses/20260917T101502Z/log",
		[]string{"x", "analyses", "20260917T101502Z", "log.txt"})
}

func TestGetProjectManifestServesNothingOutsideProjects(t *testing.T) {
	assertServesNothingOutsideProjects(t, "/api/projects/x/manifest", []string{"x", "package.json"})
}

func TestDownloadExportFileRefusesAnEscapingName(t *testing.T) {
	srv, h := newTestServer(t)

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	exportDir := filepath.Join(h.Store.Root(), "projects", project.Id, "exports", "20260917T101502Z")
	if err := os.MkdirAll(exportDir, 0o770); err != nil {
		t.Fatalf("mkdir export dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(exportDir, "summary.md"), []byte("# hi"), 0o664); err != nil {
		t.Fatalf("write summary.md: %v", err)
	}

	ok, err := http.Get(fmt.Sprintf("%s/api/projects/%s/exports/20260917T101502Z/files/summary.md", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET summary.md: %v", err)
	}
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("GET summary.md status = %d, want 200", ok.StatusCode)
	}
	data, _ := io.ReadAll(ok.Body)
	if string(data) != "# hi" {
		t.Fatalf("summary.md content = %q, want %q", data, "# hi")
	}

	escaped, err := http.Get(fmt.Sprintf("%s/api/projects/%s/exports/20260917T101502Z/files/..%%2F..%%2Fprivate%%2Fsettings.json", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET escaping name: %v", err)
	}
	defer escaped.Body.Close()
	if escaped.StatusCode != http.StatusNotFound {
		t.Fatalf("GET escaping name status = %d, want 404", escaped.StatusCode)
	}
}

func TestDeleteProjectAnalysisExport(t *testing.T) {
	srv, h := newTestServer(t)

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	// The analysis the create call queued is not the one this test deletes.
	// Cancel it: with real pnpm and Trivy it can outlast any short wait.
	queued := (*project.Analyses)[0].Id
	if _, err := h.Service.Cancel(project.Id, "analysis", queued); err != nil && !errors.Is(err, jobs.ErrNotFound) {
		t.Fatalf("Cancel: %v", err)
	}
	waitForTerminalState(t, h, project.Id, "analysis", queued)

	// Give the analysis a committed directory of its own to delete,
	// independent of whether the fake pnpm/trivy tools let the real job
	// reach state done.
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260916T090000Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir analysis dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}

	del, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/projects/%s/analyses/20260916T090000Z", srv.URL, project.Id), nil)
	if err != nil {
		t.Fatalf("build DELETE: %v", err)
	}
	delResp, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatalf("DELETE analysis: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE analysis status = %d, want 204", delResp.StatusCode)
	}
	if _, err := h.Store.AnalysisInfo(project.Id, "20260916T090000Z"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("AnalysisInfo after delete: err = %v, want ErrNotFound", err)
	}

	deleteProject := func() int {
		t.Helper()
		req, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/projects/"+project.Id, nil)
		if err != nil {
			t.Fatalf("build DELETE project: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("DELETE project: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	pending, err := h.Store.NewDir("analyses", project.Id)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	if status := deleteProject(); status != http.StatusConflict {
		t.Fatalf("DELETE project during a job: status = %d, want 409", status)
	}
	if err := pending.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if status := deleteProject(); status != http.StatusNoContent {
		t.Fatalf("DELETE project status = %d, want 204", status)
	}
}

func TestSetProjectTarget(t *testing.T) {
	srv, _ := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	target := project.Target
	target.Node = "20.0.0"
	body, _ := json.Marshal(target)
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/projects/%s/target", srv.URL, project.Id), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build PUT target: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT target: %v", err)
	}
	defer putResp.Body.Close()
	var updated Project
	if err := json.NewDecoder(putResp.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated project: %v", err)
	}
	if updated.Target.Node != "20.0.0" {
		t.Fatalf("Target.Node = %q, want %q", updated.Target.Node, "20.0.0")
	}
}

func TestCancelAnalysisUnknownIDFallsBackToStore(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260916T090000Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"failed"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/projects/%s/analyses/20260916T090000Z/cancel", srv.URL, project.Id), nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST cancel: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 200 (the store's own failed state), body: %s", resp2.StatusCode, body)
	}
	var a Analysis
	if err := json.NewDecoder(resp2.Body).Decode(&a); err != nil {
		t.Fatalf("decode analysis: %v", err)
	}
	if a.State != Failed {
		t.Fatalf("State = %q, want %q (Service was not tracking this id, so the store's state wins)", a.State, Failed)
	}
}

// TestCancelAnalysisRouteRejectsALiveExportsID proves the matching hole
// G1 closes at the API layer: naming a live export's id through the
// analyses cancel route must answer 404, not reach the export and echo
// back a synthesized Analysis body for it.
func TestCancelAnalysisRouteRejectsALiveExportsID(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlers(t, q)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()

	// Created directly through the store, not through POST /projects: that
	// endpoint also queues an analysis, which could by chance reserve the
	// same directory id as the export queued below (same project, same
	// second) and defeat this test's own premise.
	project, err := h.Store.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	// A blocking job holds the queue busy for the whole test, so the
	// export queued behind it stays live (Service still tracking it)
	// deterministically: nothing races the fakes to a terminal state.
	release := make(chan struct{})
	blocking := &testBlockingJob{run: func(_ context.Context, _ func(jobs.Event)) error {
		<-release
		return nil
	}}
	if _, err := q.Submit(blocking); err != nil {
		t.Fatalf("Submit(blocking): %v", err)
	}
	var exportID string
	// Released and waited out before this test returns, not left to a
	// deferred close: Service's finalizer goroutine keeps writing to the
	// export directory after the queued job runs, and t.TempDir's own
	// cleanup racing that goroutine is exactly the kind of flake this
	// avoids.
	defer func() {
		close(release)
		if exportID != "" {
			waitForTerminalState(t, h, project.ID, "export", exportID)
		}
	}()

	exportInfo, err := h.Service.QueueExport(project.ID, "20260917T101502Z", jobs.ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	exportID = exportInfo.ID

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/projects/%s/analyses/%s/cancel", srv.URL, project.ID, exportInfo.ID), nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST cancel: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 404 (the export's id is not an analysis, and Cancel must reject the kind mismatch), body: %s", resp2.StatusCode, body)
	}

	// The mismatch above must not have touched the export itself: it
	// stays live and cancellable through its own route.
	if state, _, ok := h.Service.LiveState(project.ID, "export", exportInfo.ID); !ok || (state != store.Queued && state != store.Running) {
		t.Fatalf("LiveState(export route) = (%q, %v), want a live queued or running state", state, ok)
	}
}

// TestCancelExportLiveExportSucceeds proves the export cancel route reaches
// jobs.Service the same way the analysis one does: a live export answers
// 200 with state cancelled.
func TestCancelExportLiveExportSucceeds(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlers(t, q)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()

	project, err := h.Store.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.ID, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	// A blocking job holds the queue busy for the whole test, so the export
	// queued behind it stays live (Service still tracking it) deterministically.
	release := make(chan struct{})
	blocking := &testBlockingJob{run: func(_ context.Context, _ func(jobs.Event)) error {
		<-release
		return nil
	}}
	if _, err := q.Submit(blocking); err != nil {
		t.Fatalf("Submit(blocking): %v", err)
	}
	var exportID string
	defer func() {
		close(release)
		if exportID != "" {
			waitForTerminalState(t, h, project.ID, "export", exportID)
		}
	}()

	exportInfo, err := h.Service.QueueExport(project.ID, "20260917T101502Z", jobs.ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	exportID = exportInfo.ID

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/projects/%s/exports/%s/cancel", srv.URL, project.ID, exportID), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST cancel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body: %s", resp.StatusCode, body)
	}
	var e Export
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if e.State != Cancelled {
		t.Fatalf("State = %q, want %q", e.State, Cancelled)
	}
}

// TestCancelExportUnknownIDReturns404 proves an id neither Service nor the
// store knows about answers 404, not a synthesized 200.
func TestCancelExportUnknownIDReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/projects/%s/exports/20260101T000000Z/cancel", srv.URL, project.Id), nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST cancel: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 404, body: %s", resp2.StatusCode, body)
	}
}

// TestGetAnalysisIncludesToolVersions proves the Trivy version, its
// database date and the pnpm version status.json recorded reach the API
// response, on the same fields internal/jobs.statusFile writes them under.
func TestGetAnalysisIncludesToolVersions(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260918T090000Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	status := `{"state":"done","trivyVersion":"0.72.0","trivyDbDate":"2026-09-09T00:00:00Z","pnpmVersion":"10.34.5"}`
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(status), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}

	resp2, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/20260918T090000Z", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET analysis: %v", err)
	}
	defer resp2.Body.Close()
	var a Analysis
	if err := json.NewDecoder(resp2.Body).Decode(&a); err != nil {
		t.Fatalf("decode analysis: %v", err)
	}
	if a.TrivyVersion == nil || *a.TrivyVersion != "0.72.0" {
		t.Errorf("TrivyVersion = %v, want 0.72.0", a.TrivyVersion)
	}
	if a.PnpmVersion == nil || *a.PnpmVersion != "10.34.5" {
		t.Errorf("PnpmVersion = %v, want 10.34.5", a.PnpmVersion)
	}
	want := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	if a.TrivyDbDate == nil || !a.TrivyDbDate.Equal(want) {
		t.Errorf("TrivyDbDate = %v, want %v", a.TrivyDbDate, want)
	}
}

// TestGetAnalysisReportsFailure proves the cause of a failed step reaches
// the API instead of staying readable only in log.txt.
func TestGetAnalysisReportsFailure(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260918T090000Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	status := `{"state":"failed","steps":[{"name":"scan-project","state":"failed","error":"trivy: exit status 1"}]}`
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(status), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}

	resp2, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/20260918T090000Z", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET analysis: %v", err)
	}
	defer resp2.Body.Close()
	var a Analysis
	if err := json.NewDecoder(resp2.Body).Decode(&a); err != nil {
		t.Fatalf("decode analysis: %v", err)
	}
	if a.Failure == nil || a.Failure.Step != "scan-project" || a.Failure.Message != "trivy: exit status 1" {
		t.Errorf("Failure = %+v, want step scan-project with the recorded message", a.Failure)
	}
}

// TestGetAnalysisLog proves an analysis' log.txt is reachable through the
// API as plain text, and that a missing analysis answers 404 rather than
// an empty body.
func TestGetAnalysisLog(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260918T090000Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "log.txt"), []byte("line one\nline two\n"), 0o664); err != nil {
		t.Fatalf("write log.txt: %v", err)
	}

	resp2, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/20260918T090000Z/log", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET log: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
	body, _ := io.ReadAll(resp2.Body)
	if string(body) != "line one\nline two\n" {
		t.Errorf("body = %q, want the exact log content", body)
	}

	resp3, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/does-not-exist/log", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET log: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an analysis that does not exist", resp3.StatusCode)
	}
}

// jobHangLimit bounds a wait on a job's end. A wall-clock deadline close
// to a job's usual run time fails on a loaded runner while the job still
// ends well, so this one only catches a job that never ends.
const jobHangLimit = 30 * time.Second

// waitForTerminalState waits until Service no longer tracks id under
// projectID and kind: its finalizer has committed the job's directory and
// stopped touching it, which a test racing a queued job against its own
// t.TempDir cleanup needs. Each event wakes a recheck, the job's "end"
// event among them; a slow tick covers an event dropped for a full
// subscriber channel.
func waitForTerminalState(t *testing.T, h *Handlers, projectID, kind, id string) {
	t.Helper()
	events, unsubscribe := h.Service.Subscribe()
	defer unsubscribe()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	hang := time.After(jobHangLimit)
	for {
		state, _, tracked := h.Service.LiveState(projectID, kind, id)
		if !tracked {
			return
		}
		select {
		case _, ok := <-events:
			if !ok {
				events = nil
			}
		case <-tick.C:
		case <-hang:
			t.Fatalf("%s %s still %s after %s", kind, id, state, jobHangLimit)
		}
	}
}

// waitForState waits for the analysis's end, then reads it through
// GetAnalysis and fails the test unless its state is one of wantStates.
func waitForState(t *testing.T, h *Handlers, srv *httptest.Server, projectID, analysisID string, wantStates ...State) Analysis {
	t.Helper()
	waitForTerminalState(t, h, projectID, "analysis", analysisID)
	var a Analysis
	getEnded(t, fmt.Sprintf("%s/api/projects/%s/analyses/%s", srv.URL, projectID, analysisID), &a)
	if !slices.Contains(wantStates, a.State) {
		t.Fatalf("analysis %s ended %s, want one of %v", analysisID, a.State, wantStates)
	}
	return a
}

func TestQueueAndGetAnalysisReachesATerminalState(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	analysisID := (*project.Analyses)[0].Id

	// The fake pnpm and Trivy runners never produce a real lockfile or
	// report, so this analysis cannot reach done; it still must reach a
	// terminal state instead of hanging, and Service's finalizer must not
	// leave a stray .tmp directory behind once it does.
	final := waitForState(t, h, srv, project.Id, analysisID, Failed, Done)
	if final.Id != analysisID {
		t.Fatalf("final analysis id = %q, want %q", final.Id, analysisID)
	}
}

// TestListProjectsFiltersByManifestSha256 proves the query param finds
// the projects created from one manifest's exact bytes and no others,
// newest first, and that Project itself carries the hash.
func TestListProjectsFiltersByManifestSha256(t *testing.T) {
	srv, _ := newTestServer(t)
	manifest := `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`

	first, resp := createProject(t, srv, manifest)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject first status = %d", resp.StatusCode)
	}
	if first.ManifestSha256 == nil || *first.ManifestSha256 == "" {
		t.Fatalf("first.ManifestSha256 = %v, want a hash", first.ManifestSha256)
	}
	hash := *first.ManifestSha256

	second, resp2 := createProject(t, srv, manifest)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject second status = %d", resp2.StatusCode)
	}
	_, resp3 := createProject(t, srv, `{"name":"other","dependencies":{"left-pad":"1.3.0"}}`)
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject other status = %d", resp3.StatusCode)
	}

	listResp, err := http.Get(srv.URL + "/api/projects?manifestSha256=" + hash)
	if err != nil {
		t.Fatalf("GET /api/projects?manifestSha256=...: %v", err)
	}
	defer listResp.Body.Close()
	var list []ProjectSummary
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode project list: %v", err)
	}
	if len(list) != 2 || list[0].Id != second.Id || list[1].Id != first.Id {
		t.Fatalf("filtered list = %+v, want [%q, %q] newest first", list, second.Id, first.Id)
	}
}

// TestCreateProjectRefusesWhenToolsNotReady proves an analysis never gets
// queued, and no project directory gets created, while trivy and its
// database are not both on the data volume: a fresh store, not the
// shared fixture that seeds readiness for every other test.
func TestCreateProjectRefusesWhenToolsNotReady(t *testing.T) {
	q := jobs.NewQueue(nil)
	t.Cleanup(q.Close)
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	tm.GitHubAPI = unroutable
	tm.NPMRegistry = unroutable
	svc := jobs.NewService(st, q, tm, fakePnpm{}, fakeTrivy{}, &npm.Client{})
	h := NewHandlers(st, svc, tm)
	srv := httptest.NewServer(Routes(h, testStatic()))
	t.Cleanup(srv.Close)

	_, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 409, body: %s", resp.StatusCode, data)
	}
	var problem Problem
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Missing == nil {
		t.Fatalf("problem.Missing is nil, want [trivy trivy-db]")
	}
	missing := *problem.Missing
	if len(missing) != 2 || missing[0] != "trivy" || missing[1] != "trivy-db" {
		t.Fatalf("problem.Missing = %v, want [trivy trivy-db]", missing)
	}

	projects, err := st.Projects()
	if err != nil {
		t.Fatalf("Projects: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("Projects = %v, want none: a refused request must create nothing", projects)
	}
}

func TestQueueExportWithNothingToPackAnswers400(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	body, _ := json.Marshal(ExportRequest{Selection: map[string][]string{}})
	resp2, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 400, body: %s", resp2.StatusCode, data)
	}
}

func TestGetProjectManifestReturnsTheUploadedBytes(t *testing.T) {
	srv, _ := newTestServer(t)
	manifest := `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`
	project, resp := createProject(t, srv, manifest)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	got, err := http.Get(fmt.Sprintf("%s/api/projects/%s/manifest", srv.URL, project.Id))
	if err != nil {
		t.Fatalf("GET manifest: %v", err)
	}
	defer got.Body.Close()
	body, _ := io.ReadAll(got.Body)
	if got.StatusCode != http.StatusOK || string(body) != manifest {
		t.Fatalf("status %d, body %q, want 200 and the uploaded bytes", got.StatusCode, body)
	}

	missing, err := http.Get(srv.URL + "/api/projects/no-such-project/manifest")
	if err != nil {
		t.Fatalf("GET missing manifest: %v", err)
	}
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing project status = %d, want 404", missing.StatusCode)
	}
}

// formPart is one part of a multipart request. A part with a filename is a
// file upload.
type formPart struct{ field, filename, data string }

// postParts posts parts to /api/projects and returns the status and body.
func postParts(t *testing.T, srv *httptest.Server, parts []formPart) (int, []byte) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for _, p := range parts {
		var part io.Writer
		var err error
		if p.filename != "" {
			part, err = w.CreateFormFile(p.field, p.filename)
		} else {
			part, err = w.CreateFormField(p.field)
		}
		if err != nil {
			t.Fatalf("create part %q: %v", p.field, err)
		}
		if _, err := part.Write([]byte(p.data)); err != nil {
			t.Fatalf("write part %q: %v", p.field, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	resp, err := http.Post(srv.URL+"/api/projects", w.FormDataContentType(), &body)
	if err != nil {
		t.Fatalf("POST /api/projects: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func pipParts(name string, files ...formPart) []formPart {
	parts := []formPart{{field: "ecosystem", data: "pip"}}
	if name != "" {
		parts = append(parts, formPart{field: "name", data: name})
	}
	return append(parts, files...)
}

func requirementsPart(filename, data string) formPart {
	return formPart{field: "requirements", filename: filename, data: data}
}

func decodeBadRequest(t *testing.T, status int, data []byte) Problem {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", status, data)
	}
	var p Problem
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("decode problem: %v (body %s)", err, data)
	}
	return p
}

func TestCreatePipProject(t *testing.T) {
	custom := store.PipTarget{Python: "3.12.4", OS: "linux", CPU: "x86_64", Glibc: "2.31", UvVer: "0.13.7"}
	customJSON, _ := json.Marshal(custom)
	cases := []struct {
		name  string
		extra []formPart
		want  store.PipTarget
	}{
		{"default target", nil, store.DefaultPipTarget},
		{"target from the part", []formPart{{field: "pipTarget", data: string(customJSON)}}, custom},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, h := newTestServer(t)
			allowPipAnalyses(t, h)
			parts := pipParts("Data tools", requirementsPart("requirements.txt", "requests==2.32.3\n"))
			status, data := postParts(t, srv, append(parts, c.extra...))
			if status != http.StatusCreated {
				t.Fatalf("status = %d, want 201, body: %s", status, data)
			}
			var project Project
			if err := json.Unmarshal(data, &project); err != nil {
				t.Fatalf("decode project: %v", err)
			}
			if project.Ecosystem != Pip || project.Name != "Data tools" {
				t.Errorf("project = %+v, want a pip project named Data tools", project)
			}
			if project.Target != nil {
				t.Errorf("target = %+v, want none", project.Target)
			}
			want := PipTarget{Python: c.want.Python, Os: c.want.OS, Cpu: c.want.CPU, Glibc: c.want.Glibc, UvVer: c.want.UvVer}
			if project.PipTarget == nil || *project.PipTarget != want {
				t.Errorf("pipTarget = %+v, want %+v", project.PipTarget, want)
			}
			if project.Analyses == nil || len(*project.Analyses) != 1 || (*project.Analyses)[0].State != Queued {
				t.Errorf("analyses = %+v, want one queued", project.Analyses)
			}
			files, err := h.Store.ProjectRequirements(project.Id)
			if err != nil || len(files) != 1 || string(files[0].Data) != "requests==2.32.3\n" {
				t.Errorf("stored files = %+v, %v", files, err)
			}
		})
	}
}

// A pip project whose request names no target gets the one the policy sets,
// whatever the built-in default.
func TestPipProjectTakesThePolicyTarget(t *testing.T) {
	srv, h := newTestServer(t)
	allowPipAnalyses(t, h)
	h.Policy.Pip = store.PipTarget{Python: "3.12.4", OS: "linux", CPU: "x86_64", Glibc: "2.31", UvVer: store.DefaultPipTarget.UvVer}
	status, data := postParts(t, srv, pipParts("Data tools", requirementsPart("requirements.txt", "requests==2.32.3\n")))
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", status, data)
	}
	var project Project
	if err := json.Unmarshal(data, &project); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	if want := pipTargetToAPI(h.Policy.Pip); project.PipTarget == nil || *project.PipTarget != want {
		t.Errorf("pipTarget = %+v, want the policy's %+v", project.PipTarget, want)
	}
}

// fakeUv is a runner.Uv that resolves every requirement to itself.
type fakeUv struct{}

func (fakeUv) Compile(_ context.Context, in runner.CompileInput) (runner.CompileResult, error) {
	var set []runner.Resolved
	for _, line := range strings.Fields(string(in.Requirements)) {
		name, version, _ := strings.Cut(line, "==")
		set = append(set, runner.Resolved{Name: name, Version: version})
	}
	return runner.CompileResult{Lock: in.Requirements, Set: set}, nil
}

// allowPipAnalyses lets h queue pip analyses with no network: uv counts as
// installed and the index is unroutable.
func allowPipAnalyses(t *testing.T, h *Handlers) {
	t.Helper()
	bin := filepath.Join(h.Store.Root(), "tools", "uv", store.DefaultPipTarget.UvVer, "uv")
	if err := os.MkdirAll(filepath.Dir(bin), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.Tools.PipIndex = unroutable
	h.Service.SetPip(fakeUv{}, &pip.Client{Index: unroutable})
}

func TestCreatePipProjectRefusesBadLines(t *testing.T) {
	srv, h := newTestServer(t)
	file := "requests==2.32.3\n# a comment\nflask>=3.0\n--index-url https://example.com/simple\n"
	status, data := postParts(t, srv, pipParts("proj", requirementsPart("requirements-dev.txt", file)))
	p := decodeBadRequest(t, status, data)
	if p.Errors == nil || len(*p.Errors) != 2 {
		t.Fatalf("errors = %+v, want 2 entries", p.Errors)
	}
	first := (*p.Errors)[0]
	if first.Field != "requirements-dev.txt" || first.Line == nil || *first.Line != 3 {
		t.Errorf("first error = %+v, want requirements-dev.txt line 3", first)
	}
	if first.Value == nil || *first.Value != "flask>=3.0" || first.Reason == "" {
		t.Errorf("first error = %+v, want the line text and a reason", first)
	}
	second := (*p.Errors)[1]
	if second.Line == nil || *second.Line != 4 || second.Reason == "" {
		t.Errorf("second error = %+v, want line 4 with a reason", second)
	}
	if projects, _ := h.Store.Projects(); len(projects) != 0 {
		t.Errorf("a refused request created %d projects", len(projects))
	}
}

func TestCreatePipProjectRefusesConflictingPins(t *testing.T) {
	srv, _ := newTestServer(t)
	status, data := postParts(t, srv, pipParts("proj",
		requirementsPart("a.txt", "requests==2.32.3\n"),
		requirementsPart("b.txt", "Requests==2.31.0\n")))
	p := decodeBadRequest(t, status, data)
	if p.Errors == nil || len(*p.Errors) == 0 {
		t.Fatalf("errors = %+v, want the conflict", p.Errors)
	}
	for _, e := range *p.Errors {
		if e.Field == "" || e.Reason == "" {
			t.Errorf("error = %+v, want a file and a reason", e)
		}
	}
}

func TestCreatePipProjectRefusesOversizeFile(t *testing.T) {
	srv, h := newTestServer(t)
	big := strings.Repeat("#", 1<<20+1) // 1 MiB plus 1 byte
	status, data := postParts(t, srv, pipParts("proj", requirementsPart("requirements.txt", big)))
	p := decodeBadRequest(t, status, data)
	if !strings.Contains(p.Title+deref(p.Detail), "1 MiB") {
		t.Errorf("problem = %+v, want the 1 MiB bound named", p)
	}
	if projects, _ := h.Store.Projects(); len(projects) != 0 {
		t.Errorf("an oversize file created %d projects, want none", len(projects))
	}
}

func TestCreatePipProjectRefusesUnusableFileNames(t *testing.T) {
	names := map[string]string{
		"long":       strings.Repeat("a", 4<<10) + ".txt",
		"format":     "a\u202eb.txt",
		"hidden":     ".hidden",
		"with space": "my file.txt",
	}
	// Refused lines make the answer repeat the file name once per line, unless the name is refused first.
	refusedLines := strings.Repeat("--index-url https://example.com/simple\n", 200)
	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			srv, h := newTestServer(t)
			status, data := postParts(t, srv, pipParts("proj", requirementsPart(name, refusedLines)))
			p := decodeBadRequest(t, status, data)
			if !strings.Contains(deref(p.Detail), "128") {
				t.Errorf("detail = %q, want the 128 character bound named", deref(p.Detail))
			}
			if len(data) > 2<<10 {
				t.Errorf("answer is %d bytes, want it independent of the name's length", len(data))
			}
			if strings.ContainsRune(string(data), '\u202e') {
				t.Errorf("answer carries a raw U+202E: %s", data)
			}
			if projects, _ := h.Store.Projects(); len(projects) != 0 {
				t.Errorf("a refused name created %d projects", len(projects))
			}
		})
	}
}

func TestCreatePipProjectCapsTheRefusalList(t *testing.T) {
	srv, _ := newTestServer(t)
	file := strings.Repeat("--index-url https://example.com/simple\n", 1000)
	status, data := postParts(t, srv, pipParts("proj", requirementsPart("requirements.txt", file)))
	p := decodeBadRequest(t, status, data)
	if p.Errors == nil || len(*p.Errors) != maxRequirementsProblems {
		t.Fatalf("errors = %d entries, want %d", len(deref2(p.Errors)), maxRequirementsProblems)
	}
	if !strings.Contains(deref(p.Detail), "1000") {
		t.Errorf("detail = %q, want the total of 1000 refusals", deref(p.Detail))
	}
}

func deref2(e *[]ProblemDetail) []ProblemDetail {
	if e == nil {
		return nil
	}
	return *e
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestCreateProjectRefusesTooManyParts(t *testing.T) {
	srv, _ := newTestServer(t)
	var parts []formPart
	for i := 0; i < 41; i++ {
		parts = append(parts, formPart{field: "extra", data: "x"})
	}
	status, data := postParts(t, srv, parts)
	p := decodeBadRequest(t, status, data)
	if !strings.Contains(deref(p.Detail), "40 parts") {
		t.Errorf("detail = %q, want the 40 parts bound named", deref(p.Detail))
	}
}

func TestCreatePipProjectRefusesTooManyFiles(t *testing.T) {
	srv, _ := newTestServer(t)
	var files []formPart
	for i := 0; i < 33; i++ {
		files = append(files, requirementsPart(fmt.Sprintf("r%d.txt", i), "requests==2.32.3\n"))
	}
	status, data := postParts(t, srv, pipParts("proj", files...))
	p := decodeBadRequest(t, status, data)
	if !strings.Contains(deref(p.Detail), "32 files") {
		t.Errorf("detail = %q, want the 32 files bound named", deref(p.Detail))
	}
}

func TestCreatePipProjectNeedsAName(t *testing.T) {
	srv, _ := newTestServer(t)
	status, data := postParts(t, srv, pipParts("", requirementsPart("r.txt", "requests==2.32.3\n")))
	p := decodeBadRequest(t, status, data)
	if !strings.Contains(deref(p.Detail), "name") {
		t.Errorf("detail = %q, want it to name the name field", deref(p.Detail))
	}
}

func TestCreatePipProjectNeedsAFile(t *testing.T) {
	srv, _ := newTestServer(t)
	status, data := postParts(t, srv, pipParts("proj"))
	p := decodeBadRequest(t, status, data)
	if !strings.Contains(deref(p.Detail), "requirements") {
		t.Errorf("detail = %q, want it to name the requirements field", deref(p.Detail))
	}
}

func TestCreatePipProjectRefusesBadTarget(t *testing.T) {
	cases := []struct {
		name, target, want string
	}{
		{"unknown field", `{"python":"3.11.2","os":"linux","cpu":"x86_64","glibc":"2.28","uvVer":"0.13.7","extra":"x"}`, "extra"},
		{"glibc above the range", `{"python":"3.11.2","os":"linux","cpu":"x86_64","glibc":"2.41","uvVer":"0.13.7"}`, "glibc"},
		{"not json", `not json`, "pipTarget"},
		{"too large", `{"python":"` + strings.Repeat("3", 4096) + `"}`, "4 KiB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, h := newTestServer(t)
			status, data := postParts(t, srv, append(pipParts("proj", requirementsPart("r.txt", "requests==2.32.3\n")), formPart{field: "pipTarget", data: c.target}))
			p := decodeBadRequest(t, status, data)
			if !strings.Contains(deref(p.Detail), c.want) {
				t.Errorf("detail = %q, want it to contain %q", deref(p.Detail), c.want)
			}
			if projects, _ := h.Store.Projects(); len(projects) != 0 {
				t.Errorf("a refused target created %d projects", len(projects))
			}
		})
	}
}

func TestCreateProjectRefusesUnknownEcosystem(t *testing.T) {
	srv, _ := newTestServer(t)
	status, data := postParts(t, srv, []formPart{{field: "ecosystem", data: "cargo"}, {field: "manifest", filename: "package.json", data: `{"name":"x"}`}})
	p := decodeBadRequest(t, status, data)
	if !strings.Contains(deref(p.Detail), "ecosystem") {
		t.Errorf("detail = %q, want it to name the ecosystem field", deref(p.Detail))
	}
}

func TestListProjectsMixesEcosystems(t *testing.T) {
	srv, h := newTestServer(t)

	// A project as 0.6.2 wrote it.
	dir := filepath.Join(h.Store.Root(), "projects", "left-pad-abc123")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	record := `{"id":"left-pad-abc123","name":"left-pad","target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"createdAt":"2026-11-01T10:00:00Z","manifestSha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}`
	if err := os.WriteFile(filepath.Join(dir, "project.json"), []byte(record), 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.CreatePipProject("Data tools", []store.RequirementsFile{{Name: "requirements.txt", Data: []byte("requests==2.32.3\n")}}, store.DefaultPipTarget); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/api/projects")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw []map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	byName := map[string]map[string]json.RawMessage{}
	for _, r := range raw {
		var name string
		_ = json.Unmarshal(r["name"], &name)
		byName[name] = r
	}
	npmRow, pipRow := byName["left-pad"], byName["Data tools"]
	if npmRow == nil || pipRow == nil {
		t.Fatalf("list = %v, want both projects", raw)
	}
	if string(npmRow["ecosystem"]) != `"npm"` || npmRow["target"] == nil || npmRow["pipTarget"] != nil {
		t.Errorf("npm row = %v, want ecosystem npm, a target and no pipTarget", npmRow)
	}
	if string(pipRow["ecosystem"]) != `"pip"` || pipRow["pipTarget"] == nil || pipRow["target"] != nil {
		t.Errorf("pip row = %v, want ecosystem pip, a pipTarget and no target", pipRow)
	}
}

// uvIndexServer serves a piptest index holding uv 0.13.7, a month old, and
// uv 0.13.8, a day old, through a front that counts every request.
func uvIndexServer(t *testing.T) (index string, requests func() int) {
	t.Helper()
	ix := piptest.NewIndex(t)
	for v, age := range map[string]time.Duration{"0.13.7": 30 * 24 * time.Hour, "0.13.8": 24 * time.Hour} {
		ix.Add(piptest.Dist{
			Name: "uv", Version: v, Tag: "py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64",
			Uploaded: time.Now().Add(-age),
			Payload:  map[string][]byte{"uv-" + v + ".data/scripts/uv": []byte("#!/bin/sh\necho uv\n")},
		})
	}
	var mu sync.Mutex
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		ix.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/simple/", func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

// writeAnalysisFiles commits an analysis directory holding files, as a job
// would leave it.
func writeAnalysisFiles(t *testing.T, st *store.Store, projectID, id string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(st.Root(), "projects", projectID, "analyses", id)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o664); err != nil {
			t.Fatal(err)
		}
	}
}

// getAnalysisRaw answers GET analysis as its top-level JSON keys.
func getAnalysisRaw(t *testing.T, srv *httptest.Server, projectID, id string) map[string]json.RawMessage {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/%s", srv.URL, projectID, id))
	if err != nil {
		t.Fatalf("GET analysis: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET analysis status = %d, body: %s", resp.StatusCode, body)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode analysis: %v", err)
	}
	return raw
}

func sameJSON(t *testing.T, got []byte, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("decode %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("decode %s: %v", want, err)
	}
	return reflect.DeepEqual(g, w)
}

func TestAnalysisStoredBeforePipReadsUnchanged(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	// An analysis as 0.6.2 wrote it.
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,1,0,0,0],"after":null,` +
		`"dependencies":[{"name":"left-pad","current":"1.3.0","vector":[0,1,0,0,0],"cves":[{"id":"CVE-2024-0001","severity":"HIGH"}],"candidates":[]}],"warnings":[]}`
	writeAnalysisFiles(t, h.Store, project.Id, "20261101T100000Z", map[string]string{
		"status.json":  `{"state":"done","createdAt":"2026-11-01T10:00:00Z","steps":[],"pnpmVersion":"10.34.5","trivyVersion":"0.72.0","trivyDbDate":"2026-10-31T00:00:00Z","target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"}}`,
		"ranking.json": ranking,
	})

	raw := getAnalysisRaw(t, srv, project.Id, "20261101T100000Z")
	if !sameJSON(t, raw["result"], ranking) {
		t.Errorf("result = %s, want ranking.json unchanged", raw["result"])
	}
	for _, key := range []string{"pipResult", "uvVersion"} {
		if v, ok := raw[key]; ok {
			t.Errorf("%s = %s, want it absent", key, v)
		}
	}
	if string(raw["pnpmVersion"]) != `"10.34.5"` {
		t.Errorf("pnpmVersion = %s, want 10.34.5", raw["pnpmVersion"])
	}
}

func TestGetPipAnalysis(t *testing.T) {
	srv, h := newTestServer(t)
	project, err := h.Store.CreatePipProject("Data tools", []store.RequirementsFile{{Name: "requirements.txt", Data: []byte("jinja2==3.1.2\n")}}, store.DefaultPipTarget)
	if err != nil {
		t.Fatal(err)
	}
	target := `{"python":"3.11.2","os":"linux","cpu":"x86_64","glibc":"2.28","uvVer":"0.13.7"}`
	cases := []struct {
		name, stored, want string
	}{
		{
			"every list present",
			`{"target":` + target + `,"files":["requirements.txt"],"packages":[{"name":"jinja2","version":"3.1.2","files":["requirements.txt"],` +
				`"wheel":{"file":"jinja2-3.1.2-py3-none-any.whl","url":"https://files.example/jinja2-3.1.2-py3-none-any.whl","sha256":"` + strings.Repeat("a", 64) + `","size":133101},` +
				`"cves":[{"id":"CVE-2024-22195","severity":"MEDIUM","fixedVersions":["3.1.3"],"title":"jinja2: HTML attribute injection"}]}],` +
				`"blocking":[{"name":"docopt","version":"0.6.2","kind":"source-only","detail":"source distribution only"}],"warnings":["redis==5.0.8 is yanked on the index: no reason given"]}`,
			"",
		},
		{
			"every list absent",
			`{"target":` + target + `,"packages":[{"name":"markupsafe","version":"3.0.2","cves":[{"id":"CVE-2024-0002","severity":"LOW"}]}]}`,
			`{"target":` + target + `,"files":[],"packages":[{"name":"markupsafe","version":"3.0.2","files":[],"cves":[{"id":"CVE-2024-0002","severity":"LOW","fixedVersions":[]}]}],"blocking":[],"warnings":[]}`,
		},
		{
			"every list null",
			`{"target":` + target + `,"files":null,"packages":[{"name":"certifi","version":"2024.8.30","files":null,"cves":null}],"blocking":null,"warnings":null}`,
			`{"target":` + target + `,"files":[],"packages":[{"name":"certifi","version":"2024.8.30","files":[],"cves":[]}],"blocking":[],"warnings":[]}`,
		},
		{
			"no packages",
			`{"target":` + target + `}`,
			`{"target":` + target + `,"files":[],"packages":[],"blocking":[],"warnings":[]}`,
		},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := fmt.Sprintf("20261120T10000%dZ", i)
			writeAnalysisFiles(t, h.Store, project.ID, id, map[string]string{
				"status.json":     `{"state":"done","steps":[],"pnpmVersion":"","uvVersion":"0.13.7","trivyVersion":"0.72.0","trivyDbDate":"2026-11-19T00:00:00Z","pipTarget":` + target + `}`,
				"pip-result.json": c.stored,
			})
			raw := getAnalysisRaw(t, srv, project.ID, id)
			want := c.want
			if want == "" {
				want = c.stored
			}
			if !sameJSON(t, raw["pipResult"], want) {
				t.Errorf("pipResult = %s, want %s", raw["pipResult"], want)
			}
			if string(raw["uvVersion"]) != `"0.13.7"` {
				t.Errorf("uvVersion = %s, want 0.13.7", raw["uvVersion"])
			}
			for _, key := range []string{"result", "pnpmVersion"} {
				if v, ok := raw[key]; ok {
					t.Errorf("%s = %s, want it absent on a pip analysis", key, v)
				}
			}
		})
	}
}

func TestGetPipAnalysisDropsAnUnreadableResult(t *testing.T) {
	srv, h := newTestServer(t)
	project, err := h.Store.CreatePipProject("Data tools", []store.RequirementsFile{{Name: "requirements.txt", Data: []byte("jinja2==3.1.2\n")}}, store.DefaultPipTarget)
	if err != nil {
		t.Fatal(err)
	}
	writeAnalysisFiles(t, h.Store, project.ID, "20261120T100000Z", map[string]string{
		"status.json":     `{"state":"done","uvVersion":"0.13.7"}`,
		"pip-result.json": `{"packages":"jinja2"}`,
	})
	raw := getAnalysisRaw(t, srv, project.ID, "20261120T100000Z")
	if v, ok := raw["pipResult"]; ok {
		t.Errorf("pipResult = %s, want it dropped", v)
	}
	if string(raw["state"]) != `"done"` {
		t.Errorf("state = %s, want the analysis still answered", raw["state"])
	}
}

// postExport posts body to the analysis's exports route and returns the
// status and the response bytes.
func postExport(t *testing.T, srv *httptest.Server, projectID, analysisID, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(fmt.Sprintf("%s/api/projects/%s/analyses/%s/exports", srv.URL, projectID, analysisID), "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func TestQueueExportForAPipProject(t *testing.T) {
	q := jobs.NewQueue(nil)
	h := newTestHandlersWithTrivy(t, q)
	t.Cleanup(q.Close)
	srv := httptest.NewServer(Routes(h, testStatic()))
	t.Cleanup(srv.Close)

	ix := piptest.NewIndex(t)
	released := time.Date(2024, time.September, 1, 0, 0, 0, 0, time.UTC)
	ix.Add(piptest.Dist{Name: "certifi", Version: "2024.8.30", Tag: "py3-none-any", Uploaded: released})
	ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any", Uploaded: released})
	allowPipAnalyses(t, h)
	h.Tools.PipIndex = ix.URL
	h.Tools.Arch = "amd64"
	h.Service.SetPip(fakeUv{}, &pip.Client{Index: ix.URL})
	project, err := h.Store.CreatePipProject("Data tools", []store.RequirementsFile{{Name: "requirements.txt", Data: []byte("certifi==2024.8.30\nrequests==2.32.3\n")}}, store.DefaultPipTarget)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := h.Service.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	waitForTerminalState(t, h, project.ID, "analysis", analysis.ID)
	if info, err := h.Store.AnalysisInfo(project.ID, analysis.ID); err != nil || info.State != store.Done {
		t.Fatalf("analysis = %+v, %v; want done", info, err)
	}

	status, body := postExport(t, srv, project.ID, analysis.ID, `{"selection":{"requests":["2.32.3"]}}`)
	if p := decodeProblem(t, body); status != http.StatusBadRequest || !strings.Contains(deref(p.Detail), "takes no selection") {
		t.Errorf("a selection answered %d %s, want 400 saying a pip export takes no selection", status, body)
	}

	status, body = postExport(t, srv, project.ID, analysis.ID, `{"selection":{}}`)
	if status != http.StatusAccepted {
		t.Fatalf("an empty selection answered %d %s, want 202", status, body)
	}
	var queued Export
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatal(err)
	}
	done := waitForExportState(t, h, srv, project.ID, queued.Id, Done, Failed, Cancelled)
	if done.State != Done || done.Files == nil || !slices.Contains(*done.Files, "packages_pip.tar.gz") {
		t.Fatalf("export = %+v, want done with packages_pip.tar.gz", done)
	}
	resp, err := http.Get(fmt.Sprintf("%s/api/projects/%s/exports/%s/files/packages_pip.tar.gz", srv.URL, project.ID, queued.Id))
	if err != nil {
		t.Fatal(err)
	}
	served, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(project.Dir, "exports", queued.Id, "packages_pip.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(served, onDisk) {
		t.Errorf("the file route answered %d with %d bytes, want 200 with the %d bytes on disk", resp.StatusCode, len(served), len(onDisk))
	}

	// The result loses a wheel, as one written by another build could.
	path := filepath.Join(project.Dir, "analyses", analysis.ID, "pip-result.json")
	var result map[string]any
	if err := json.Unmarshal(readTestFile(t, path), &result); err != nil {
		t.Fatal(err)
	}
	delete(result["packages"].([]any)[0].(map[string]any), "wheel")
	if err := h.Store.WriteJSON(path, result); err != nil {
		t.Fatal(err)
	}
	status, body = postExport(t, srv, project.ID, analysis.ID, `{"selection":{}}`)
	if p := decodeProblem(t, body); status != http.StatusConflict || !strings.Contains(deref(p.Detail), "1 of 2 packages has no wheel") {
		t.Errorf("an analysis without every wheel answered %d %s, want 409 naming the count", status, body)
	}
}

func decodeProblem(t *testing.T, data []byte) Problem {
	t.Helper()
	var p Problem
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("decode problem %s: %v", data, err)
	}
	return p
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// reasonsAnalysis writes a done analysis where left-pad can leave major 1
// and is-even keeps a CVE that no version fixes, with a stub lockfile for
// each version an export may select.
func reasonsAnalysis(t *testing.T, h *Handlers, projectID string) {
	t.Helper()
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,1,0,0,0],"after":[0,1,0,0,0],` +
		`"dependencies":[` +
		`{"name":"is-even","current":"1.0.0","vector":[0,1,0,0,0],"cves":[{"id":"CVE-2025-0001","severity":"HIGH","package":"is-even@1.0.0","fixedIn":""}],"candidates":[]},` +
		`{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"cves":[],"jump":"2.0.0","candidates":[{"version":"2.0.0","vector":[0,0,0,0,0],"cves":[],"signals":[],"key":true,"resolved":true}]}` +
		`],"warnings":[],"families":[]}`
	analysisDir := filepath.Join(h.Store.Root(), "projects", projectID, "analyses", "20260917T101502Z")
	for _, dep := range []string{"is-even@1.0.0", "left-pad@1.3.0", "left-pad@2.0.0"} {
		dir := filepath.Join(analysisDir, "candidates", dep)
		if err := os.MkdirAll(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages: {}\n"), 0o664); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"status.json":           `{"state":"done"}`,
		"ranking.json":          ranking,
		"candidates.trivy.json": `{"SchemaVersion":2,"Results":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(analysisDir, name), []byte(content), 0o664); err != nil {
			t.Fatal(err)
		}
	}
}

func queueExportWith(t *testing.T, srv *httptest.Server, projectID string, req ExportRequest) *http.Response {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(
		fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, projectID),
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST queueExport: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func reasonsProblem(t *testing.T, resp *http.Response) Problem {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400, body: %s", resp.StatusCode, data)
	}
	var problem Problem
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Detail == nil {
		t.Fatal("the problem has no detail")
	}
	return problem
}

func TestQueueExportNamesEachMissingReason(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)

	problem := reasonsProblem(t, queueExportWith(t, srv, project.Id, ExportRequest{Selection: map[string][]string{"left-pad": {"2.0.0"}, "is-even": {"1.0.0"}}}))
	want := "is-even 1.0.0 keeps CVE-2025-0001, which no version fixes, and needs a reason; " +
		"left-pad 1.3.0 to 2.0.0 leaves major 1 and needs a reason"
	if *problem.Detail != want {
		t.Errorf("detail = %q, want %q", *problem.Detail, want)
	}
	exports, err := h.Store.Exports(project.Id)
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 0 {
		t.Errorf("Exports() = %v, want none reserved for a refused request", exports)
	}
}

func TestQueueExportRepeatsNoReasonText(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)

	secret := "internal ticket SEC-4411   <img src=x>"
	reasons := []Reason{
		{Kind: MajorJump, Dependencies: []string{"left-pad"}, Text: secret},
		{Kind: CveWithoutFix, Dependencies: []string{"left-pad"}, Text: "left-pad SEC-4411 is fine"},
	}
	resp2 := queueExportWith(t, srv, project.Id, ExportRequest{Selection: map[string][]string{"left-pad": {"2.0.0"}}, Reasons: &reasons})
	data, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", resp2.StatusCode, data)
	}
	for _, leak := range []string{"SEC-4411", "img", "ticket", "fine"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("the refusal repeats %q from a reason: %s", leak, data)
		}
	}
	var problem Problem
	if err := json.Unmarshal(data, &problem); err != nil {
		t.Fatal(err)
	}
	// is-even, left out of the selection, keeps its CVE without fix.
	want := "is-even 1.0.0 keeps CVE-2025-0001, which no version fixes, and needs a reason; " +
		"reason 1 (major-jump): the reason holds a control, line-separating, bidirectional or format character; " +
		"reason 2 (cve-without-fix) covers nothing the selection takes"
	if problem.Detail == nil {
		t.Fatal("the problem has no detail")
	}
	if *problem.Detail != want {
		t.Errorf("detail = %q, want %q", *problem.Detail, want)
	}
}

// The project tree ships its lockfile, which holds each current version:
// is-even 1.0.0 keeps a CVE that no version fixes and crosses beside any
// version selected.
func TestQueueExportCountsTheCurrentVersionsTheProjectTreeShips(t *testing.T) {
	srv, h := newTestServer(t)
	h.Service.Review = policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,1,0,0,0],"after":[0,1,0,0,0],` +
		`"dependencies":[` +
		`{"name":"is-even","current":"1.0.0","vector":[0,1,0,0,0],"cves":[{"id":"CVE-2025-0001","severity":"HIGH","package":"is-even@1.0.0","fixedIn":""}],` +
		`"candidates":[{"version":"1.0.1","vector":[1,0,0,0,0],"cves":[{"id":"CVE-2025-0002","severity":"CRITICAL","package":"is-even@1.0.1","fixedIn":"1.0.2"}],"signals":[],"key":true,"resolved":true}]},` +
		`{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"cves":[],"candidates":[]}` +
		`],"warnings":[],"families":[]}`
	if err := os.WriteFile(filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z", "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z", "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}

	withTree := true
	want := "review.cveWithoutFix is refuse: is-even 1.0.0 keeps CVE-2025-0001, which no version fixes, and cannot cross"
	for name, sel := range map[string]map[string][]string{
		"nothing selected":         {},
		"a worse version selected": {"is-even": {"1.0.1"}},
	} {
		problem := reasonsProblem(t, queueExportWith(t, srv, project.Id, ExportRequest{Selection: sel, IncludeProject: &withTree}))
		if *problem.Detail != want {
			t.Errorf("%s: detail = %q, want %q", name, *problem.Detail, want)
		}
	}
}

// volumeTools records every entry under the volume's tools folder: a
// file's sha256, a link's target, a folder's name.
func volumeTools(t *testing.T, root string) map[string]string {
	t.Helper()
	entries := map[string]string{}
	err := filepath.WalkDir(filepath.Join(root, "tools"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		switch {
		case d.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			entries[rel] = "link " + target
			return err
		case d.IsDir():
			entries[rel] = "dir"
		default:
			data, err := os.ReadFile(path)
			sum := sha256.Sum256(data)
			entries[rel] = "file " + hex.EncodeToString(sum[:])
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read the tools folder: %v", err)
	}
	return entries
}

// TestToolAndSettingsRoutesAreGone proves no request installs a tool or
// writes the settings: the deployment prepares the one and sets the other.
func TestToolAndSettingsRoutesAreGone(t *testing.T) {
	srv, h := newTestServer(t)
	githubRequests := pinnedTrivyRelease(t, h)
	index, indexRequests := uvIndexServer(t)
	h.Tools.PipIndex = index
	settings, _ := json.Marshal(settingsToAPI(h.Store.Settings()))
	beforeSettings := h.Store.Settings()
	before := volumeTools(t, h.Store.Root())

	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/tools", ""},
		{http.MethodPost, "/api/tools/trivy/update", `{"force":true}`},
		{http.MethodPost, "/api/tools/trivy/activate", `{"version":"1.2.3"}`},
		{http.MethodPost, "/api/tools/trivy/db/update", `{}`},
		{http.MethodPost, "/api/tools/uv/install", `{"version":"0.13.8","force":true}`},
		{http.MethodPut, "/api/settings", string(settings)},
	}
	for _, route := range routes {
		req, err := http.NewRequest(route.method, srv.URL+route.path, strings.NewReader(route.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", route.method, route.path, err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusGone {
			t.Errorf("%s %s = %d, want 410: %s", route.method, route.path, resp.StatusCode, data)
		}
	}

	if after := volumeTools(t, h.Store.Root()); !reflect.DeepEqual(after, before) {
		t.Errorf("the tools folder changed:\nbefore %v\nafter  %v", before, after)
	}
	if got := githubRequests(); len(got) != 0 {
		t.Errorf("the routes asked GitHub for %v, want nothing", got)
	}
	if n := indexRequests(); n != 0 {
		t.Errorf("the routes made %d requests to the package index, want 0", n)
	}
	if got := h.Store.Settings(); got != beforeSettings {
		t.Errorf("Settings() = %+v, want %+v", got, beforeSettings)
	}
	if _, err := os.Lstat(filepath.Join(h.Store.Root(), "private", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("a settings file appeared on the volume (stat: %v)", err)
	}
}

// TestJobRoutesWaitForThePreparation proves the routes that start work
// read the start's preparation, not the tools manager alone: with Trivy and
// its database in place but pnpm still preparing, creating a project of
// either ecosystem, queueing an analysis and queueing an export each answer
// 409 naming pnpm.
func TestJobRoutesWaitForThePreparation(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject while ready: status = %d", resp.StatusCode)
	}
	if ready, _ := h.Tools.Ready(); !ready {
		t.Fatal("the tools manager must report ready for this test to mean anything")
	}
	h.Ready = fixedReadiness{Items: []tools.Item{
		{Name: "trivy", State: tools.ItemReady},
		{Name: "trivy-db", State: tools.ItemReady},
		{Name: "pnpm", Version: "10.34.5", State: tools.ItemPreparing},
	}}

	check := func(what string, status int, data []byte) {
		t.Helper()
		if status != http.StatusConflict {
			t.Errorf("%s: status = %d, want 409, body: %s", what, status, data)
			return
		}
		var p Problem
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("%s: decode problem: %v", what, err)
		}
		if p.Missing == nil || !slices.Equal(*p.Missing, []string{"pnpm"}) {
			t.Errorf("%s: missing = %v, want [pnpm]", what, p.Missing)
		}
	}
	post := func(path string, body any) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		r, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer r.Body.Close()
		data, _ := io.ReadAll(r.Body)
		return r.StatusCode, data
	}

	_, resp = createProject(t, srv, `{"name":"is-odd","dependencies":{"is-odd":"3.0.1"}}`)
	data, _ := io.ReadAll(resp.Body)
	check("create an npm project", resp.StatusCode, data)
	status, data := postParts(t, srv, pipParts("Data tools", requirementsPart("requirements.txt", "requests==2.32.3\n")))
	check("create a pip project", status, data)
	status, data = post("/api/projects/"+project.Id+"/analyses", struct{}{})
	check("queue an analysis", status, data)
	status, data = post("/api/projects/"+project.Id+"/analyses/20260917T101502Z/exports", ExportRequest{Selection: map[string][]string{}})
	check("queue an export", status, data)
}

// occupyComingSeconds creates a committed directory under dir for every
// id the next minute could produce, so the store has to add its suffix to
// the next id it allocates there.
func occupyComingSeconds(t *testing.T, dir string) {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Second)
	for i := range 60 {
		id := start.Add(time.Duration(i) * time.Second).Format("20060102T150405Z")
		if err := os.MkdirAll(filepath.Join(dir, id), 0o770); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
}

// A clean version selected beside the current one the project tree ships
// does not hide the current one's CVE without fix.
func TestQueueExportRefusesTheCurrentVersionBesideACleanOne(t *testing.T) {
	srv, h := newTestServer(t)
	h.Service.Review = policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,1,0,0,0],"after":[0,0,0,0,0],` +
		`"dependencies":[` +
		`{"name":"is-even","current":"1.0.0","vector":[0,1,0,0,0],"cves":[{"id":"CVE-2025-0001","severity":"HIGH","package":"is-even@1.0.0","fixedIn":""}],` +
		`"candidates":[{"version":"1.0.1","vector":[0,0,0,0,0],"cves":[],"signals":[],"key":true,"resolved":true}]},` +
		`{"name":"left-pad","current":"1.3.0","vector":[0,0,0,0,0],"cves":[],"candidates":[]}` +
		`],"warnings":[],"families":[]}`
	if err := os.WriteFile(filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z", "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z", "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}
	withTree := true
	problem := reasonsProblem(t, queueExportWith(t, srv, project.Id, ExportRequest{Selection: map[string][]string{"is-even": {"1.0.1"}}, IncludeProject: &withTree}))
	want := "review.cveWithoutFix is refuse: is-even 1.0.0 keeps CVE-2025-0001, which no version fixes, and cannot cross"
	if *problem.Detail != want {
		t.Errorf("detail = %q, want %q", *problem.Detail, want)
	}
}

// The refuse policy covers what the archive holds: a dependency left out
// stays at its current version in the project and asks a reason only.
func TestQueueExportAcceptsAReasonForADependencyLeftOutUnderRefuse(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlersWithTrivy(t, q)
	h.Service.Review = policy.Review{MajorJump: policy.Refuse, CVEWithoutFix: policy.Refuse}
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)

	sel := map[string][]string{"left-pad": {"1.3.0"}}
	problem := reasonsProblem(t, queueExportWith(t, srv, project.Id, ExportRequest{Selection: sel}))
	want := "is-even 1.0.0 keeps CVE-2025-0001, which no version fixes, and needs a reason"
	if *problem.Detail != want {
		t.Errorf("detail = %q, want %q", *problem.Detail, want)
	}

	reasons := []Reason{{Kind: CveWithoutFix, Dependencies: []string{"is-even"}, Text: "We call is-even on our own numbers only."}}
	resp2 := queueExportWith(t, srv, project.Id, ExportRequest{Selection: sel, Reasons: &reasons})
	if resp2.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 202, body: %s", resp2.StatusCode, data)
	}
}

func TestQueueExportAcceptsTheReasonsItNeeds(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlersWithTrivy(t, q)
	srv := httptest.NewServer(Routes(h, testStatic()))
	defer srv.Close()
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)

	reasons := []Reason{
		{Kind: MajorJump, Dependencies: []string{"left-pad"}, Text: "Version 2 keeps the same API for us."},
		{Kind: CveWithoutFix, Dependencies: []string{"is-even"}, Text: "We call is-even on our own numbers only."},
	}
	resp2 := queueExportWith(t, srv, project.Id, ExportRequest{Selection: map[string][]string{"left-pad": {"2.0.0"}, "is-even": {"1.0.0"}}, Reasons: &reasons})
	if resp2.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, want 202, body: %s", resp2.StatusCode, data)
	}
	var queued Export
	if err := json.NewDecoder(resp2.Body).Decode(&queued); err != nil {
		t.Fatal(err)
	}
	if final := waitForExportState(t, h, srv, project.Id, queued.Id, Done, Failed); final.State != Done {
		t.Fatalf("export state = %q, want %q", final.State, Done)
	}

	f, err := h.Store.ExportFile(project.Id, queued.Id, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var manifest struct {
		Review struct {
			Jumps []struct {
				Reason string `json:"reason"`
			} `json:"jumps"`
			Left []struct {
				Dependency string `json:"dependency"`
				Reason     string `json:"reason"`
			} `json:"left"`
		} `json:"review"`
	}
	if err := json.NewDecoder(f).Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Review.Jumps) != 1 || manifest.Review.Jumps[0].Reason != reasons[0].Text {
		t.Errorf("review.jumps = %+v, want left-pad's jump with its reason", manifest.Review.Jumps)
	}
	if len(manifest.Review.Left) != 1 || manifest.Review.Left[0].Reason != reasons[1].Text {
		t.Errorf("review.left = %+v, want is-even's CVE with its reason", manifest.Review.Left)
	}
}

// suffixedIDTime checks that id carries the store's suffix and returns the
// time its timestamp part names.
func suffixedIDTime(t *testing.T, id string) time.Time {
	t.Helper()
	stamp, suffix, ok := strings.Cut(id, "-")
	if !ok || len(suffix) != 6 {
		t.Fatalf("id = %q, want a timestamp with a six-digit suffix", id)
	}
	want, err := time.Parse("20060102T150405Z", stamp)
	if err != nil {
		t.Fatalf("parse %q: %v", stamp, err)
	}
	return want
}

// TestLiveJobWithASuffixedIDShowsItsCreationTime covers every response
// built from a live job's id rather than its committed status.json.
func TestLiveJobWithASuffixedIDShowsItsCreationTime(t *testing.T) {
	ctx := context.Background()
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := newTestHandlers(t, q)
	release := make(chan struct{})
	defer close(release)
	if _, err := q.Submit(&testBlockingJob{run: func(context.Context, func(jobs.Event)) error {
		<-release
		return nil
	}}); err != nil {
		t.Fatalf("Submit(blocking): %v", err)
	}

	project, err := h.Store.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	analysisDir := filepath.Join(project.Dir, "analyses", "20260917T101502Z")
	if err := os.MkdirAll(analysisDir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), []byte(`{"state":"done"}`), 0o664); err != nil {
		t.Fatalf("write status.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "ranking.json"), []byte(ranking), 0o664); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(emptyProjectScan), 0o664); err != nil {
		t.Fatalf("write project.trivy.json: %v", err)
	}
	occupyComingSeconds(t, filepath.Join(project.Dir, "analyses"))
	occupyComingSeconds(t, filepath.Join(project.Dir, "exports"))

	analysis, err := h.Service.QueueAnalysis(project.ID)
	if err != nil {
		t.Fatalf("QueueAnalysis: %v", err)
	}
	want := suffixedIDTime(t, analysis.ID)
	got, err := h.GetAnalysis(ctx, GetAnalysisRequestObject{ProjectId: project.ID, AnalysisId: analysis.ID})
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if a, ok := got.(GetAnalysis200JSONResponse); !ok || !a.CreatedAt.Equal(want) {
		t.Errorf("GetAnalysis = %+v, want createdAt %v", got, want)
	}
	if live, _ := h.liveAnalysisOrExport(project.ID); live == nil || !live.CreatedAt.Equal(want) {
		t.Errorf("project's live analysis = %+v, want createdAt %v", live, want)
	}
	cancelled, err := h.CancelAnalysis(ctx, CancelAnalysisRequestObject{ProjectId: project.ID, AnalysisId: analysis.ID})
	if err != nil {
		t.Fatalf("CancelAnalysis: %v", err)
	}
	if a, ok := cancelled.(CancelAnalysis200JSONResponse); !ok || !a.CreatedAt.Equal(want) {
		t.Errorf("CancelAnalysis = %+v, want createdAt %v", cancelled, want)
	}
	waitForTerminalState(t, h, project.ID, "analysis", analysis.ID)

	export, err := h.Service.QueueExport(project.ID, "20260917T101502Z", jobs.ExportRequest{Selection: map[string][]string{}, IncludeProject: true})
	if err != nil {
		t.Fatalf("QueueExport: %v", err)
	}
	want = suffixedIDTime(t, export.ID)
	gotExport, err := h.GetExport(ctx, GetExportRequestObject{ProjectId: project.ID, ExportId: export.ID})
	if err != nil {
		t.Fatalf("GetExport: %v", err)
	}
	if e, ok := gotExport.(GetExport200JSONResponse); !ok || !e.CreatedAt.Equal(want) {
		t.Errorf("GetExport = %+v, want createdAt %v", gotExport, want)
	}
	if _, live := h.liveAnalysisOrExport(project.ID); live == nil || !live.CreatedAt.Equal(want) {
		t.Errorf("project's live export = %+v, want createdAt %v", live, want)
	}
	cancelledExport, err := h.CancelExport(ctx, CancelExportRequestObject{ProjectId: project.ID, ExportId: export.ID})
	if err != nil {
		t.Fatalf("CancelExport: %v", err)
	}
	if e, ok := cancelledExport.(CancelExport200JSONResponse); !ok || !e.CreatedAt.Equal(want) {
		t.Errorf("CancelExport = %+v, want createdAt %v", cancelledExport, want)
	}
	waitForTerminalState(t, h, project.ID, "export", export.ID)
}

func TestQueueExportBoundsTheRequest(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)

	manyReasons := make([]Reason, maxRequestEntries+1)
	for i := range manyReasons {
		manyReasons[i] = Reason{Kind: MajorJump, Dependencies: []string{"left-pad"}, Text: "x"}
	}
	manyNames := make([]string, maxRequestEntries+1)
	for i := range manyNames {
		manyNames[i] = "left-pad"
	}
	bigSelection := map[string][]string{}
	for i := range maxRequestEntries + 1 {
		bigSelection[fmt.Sprintf("p%d", i)] = nil
	}
	long := strings.Repeat("a", maxNameBytes+1)
	tests := []struct {
		name, detail string
		req          ExportRequest
	}{
		{"10,001 reasons", "the export request holds more than 10000 reasons",
			ExportRequest{Selection: map[string][]string{}, Reasons: &manyReasons}},
		{"10,001 dependencies in the selection", "the export selection holds more than 10000 dependencies",
			ExportRequest{Selection: bigSelection}},
		{"10,001 dependencies in a reason", "reason 1 holds more than 10000 dependencies",
			ExportRequest{Selection: map[string][]string{}, Reasons: &[]Reason{{Kind: MajorJump, Dependencies: manyNames, Text: "x"}}}},
		{"a selected name of 215 bytes", "a dependency name in the export selection is longer than 214 bytes",
			ExportRequest{Selection: map[string][]string{long: {"1.0.0"}}}},
		{"a reason's name of 215 bytes", "reason 1 names a dependency longer than 214 bytes",
			ExportRequest{Selection: map[string][]string{}, Reasons: &[]Reason{{Kind: MajorJump, Dependencies: []string{long}, Text: "x"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := queueExportWith(t, srv, project.Id, tt.req)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			var p Problem
			if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
			if p.Detail == nil || *p.Detail != tt.detail {
				t.Errorf("detail = %v, want %q", p.Detail, tt.detail)
			}
		})
	}
}

func TestQueueExportAcceptsTheRequestAtItsBounds(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0","is-even":"1.0.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	reasons := make([]Reason, maxRequestEntries)
	for i := range reasons {
		reasons[i] = Reason{Kind: MajorJump, Dependencies: []string{strings.Repeat("a", maxNameBytes)}, Text: "x"}
	}
	selection := map[string][]string{strings.Repeat("b", maxNameBytes): {"1.0.0"}}
	for i := range maxRequestEntries - 1 {
		selection[fmt.Sprintf("p%d", i)] = nil
	}
	resp2 := queueExportWith(t, srv, project.Id, ExportRequest{Selection: selection, Reasons: &reasons})
	data, _ := io.ReadAll(resp2.Body)
	if strings.Contains(string(data), "more than") || strings.Contains(string(data), "longer than 214") {
		t.Errorf("a request at its bounds was refused by a bound: %s", data)
	}
}

func TestAJSONBodyOver16MiBIsRefused(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	body := `{"selection":{},"pad":"` + strings.Repeat("a", maxJSONBodyBytes) + `"}`
	resp2, err := http.Post(fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id), "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp2.StatusCode)
	}
	var p Problem
	if err := json.NewDecoder(resp2.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Detail == nil || *p.Detail != "the request body is larger than 16 MiB" {
		t.Errorf("detail = %v", p.Detail)
	}
}

func TestABodyThatIsNotJSONIsRefusedWhateverItsSize(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	url := fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id)
	big := `{"selection":{},"pad":"` + strings.Repeat("a", 17<<20) + `"}`
	for _, tt := range []struct{ name, contentType, body string }{
		{"17 MiB as text/plain", "text/plain", big},
		{"17 MiB with no type", "", big},
		{"a small body as text/plain", "text/plain", `{"selection":{}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}
			var p Problem
			if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAMultipartBodyOverItsBoundIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	body := "--b\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n" + strings.Repeat("a", maxMultipartBodyBytes) + "\r\n--b--\r\n"
	resp, err := http.Post(srv.URL+"/api/projects", "multipart/form-data; boundary=b", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertTooLarge(t, resp, "the request body is larger than 41 MiB")
}

// A valid manifest followed by a part the handler skips would create the
// project without the cap: only the cap refuses it.
func TestAValidManifestPaddedPastTheMultipartBoundIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	status, data := postParts(t, srv, []formPart{
		{field: "name", data: "pads"},
		{field: "manifest", filename: "package.json", data: `{"name":"pads","dependencies":{"left-pad":"1.3.0"}}`},
		{field: "pad", data: strings.Repeat("a", maxMultipartBodyBytes)},
	})
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %.200s", status, data)
	}
	var p Problem
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if deref(p.Detail) != "the request body is larger than 41 MiB" {
		t.Errorf("detail = %q", deref(p.Detail))
	}
}

// A chunked body declares no length, so only the reader's cap stops it.
func TestAChunkedJSONBodyOver16MiBIsRefused(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	body := io.MultiReader(strings.NewReader(`{"selection":{},"pad":"`), strings.NewReader(strings.Repeat("a", maxJSONBodyBytes)), strings.NewReader(`"}`))
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if req.ContentLength != 0 {
		t.Fatalf("ContentLength = %d, want an unknown length", req.ContentLength)
	}
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	assertTooLarge(t, resp2, "the request body is larger than 16 MiB")
}

// The body bounds belong to /api: the web shell outside it answers as it
// always did, and no 415 reaches it.
func TestBodyBoundsStayUnderTheAPIPrefix(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/", "/apix", "/projects"} {
		resp, err := http.Post(srv.URL+path, "text/plain", strings.NewReader("hello"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnsupportedMediaType {
			t.Errorf("POST %s = 415, want the bounds left to /api/", path)
		}
	}
	resp, err := http.Post(srv.URL+"/api/projects", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("POST /api/projects as text/plain = %d, want 415", resp.StatusCode)
	}
}

func assertTooLarge(t *testing.T, resp *http.Response, detail string) {
	t.Helper()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 413: %.200s", resp.StatusCode, data)
	}
	var p Problem
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if deref(p.Detail) != detail {
		t.Errorf("detail = %q, want %q", deref(p.Detail), detail)
	}
}

// Only the project upload takes a multipart body: a JSON route sent one
// keeps the JSON cap.
func TestAMultipartBodyOnAJSONRouteKeepsTheJSONCap(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"pads","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	reasonsAnalysis(t, h, project.Id)
	body := `{"selection":{},"pad":"` + strings.Repeat("a", maxJSONBodyBytes) + `"}`
	resp2, err := http.Post(fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id), "multipart/form-data; boundary=b", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	assertTooLarge(t, resp2, "the request body is larger than 16 MiB")
}

// emptyProjectScan is a lockfile scan that finds nothing.
const emptyProjectScan = `{"SchemaVersion": 2, "Results": []}`

// An export of the project tree conflicts with the analysis's own files
// when its lockfile scan is missing or its lockfile is too large to walk:
// both answer 409, neither a server failure.
func TestQueueExportProjectTreeRefusalsAnswer409(t *testing.T) {
	var lock, scan strings.Builder
	lock.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n")
	for i := range 1100 {
		fmt.Fprintf(&lock, "      d%d:\n        specifier: 1.0.0\n        version: 1.0.0\n", i)
	}
	lock.WriteString("snapshots:\n")
	for i := range 1100 {
		fmt.Fprintf(&lock, "  d%d@1.0.0:\n    dependencies:\n      hub: 1.0.0\n", i)
	}
	lock.WriteString("  hub@1.0.0:\n    dependencies:\n")
	for i := range 1000 {
		fmt.Fprintf(&lock, "      l%d: 1.0.0\n", i)
	}
	scan.WriteString(`{"SchemaVersion": 2, "Results": [{"Vulnerabilities": [`)
	for i := range 1000 {
		fmt.Fprintf(&lock, "  l%d@1.0.0: {}\n", i)
		if i > 0 {
			scan.WriteString(",")
		}
		fmt.Fprintf(&scan, `{"VulnerabilityID": "CVE-2025-%04d", "PkgName": "l%d", "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1", "Severity": "LOW", "Title": "t"}`, i, i)
	}
	scan.WriteString("]}]}")
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`

	for _, tc := range []struct {
		name  string
		files map[string]string
		cause string
	}{
		{"no project scan", map[string]string{}, "project.trivy.json"},
		{"lockfile too large", map[string]string{"project.trivy.json": scan.String(), "project/pnpm-lock.yaml": lock.String()}, "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, h := newTestServer(t)
			project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("CreateProject status = %d", resp.StatusCode)
			}
			analysisDir := filepath.Join(h.Store.Root(), "projects", project.Id, "analyses", "20260917T101502Z")
			if err := os.MkdirAll(filepath.Join(analysisDir, "project"), 0o770); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{"status.json": `{"state":"done"}`, "ranking.json": ranking}
			for name, data := range tc.files {
				files[name] = data
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(analysisDir, name), []byte(data), 0o664); err != nil {
					t.Fatal(err)
				}
			}
			resp2, err := http.Post(
				fmt.Sprintf("%s/api/projects/%s/analyses/20260917T101502Z/exports", srv.URL, project.Id),
				"application/json", strings.NewReader(`{"selection":{},"includeProject":true}`),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer resp2.Body.Close()
			data, _ := io.ReadAll(resp2.Body)
			if resp2.StatusCode != http.StatusConflict || !strings.Contains(string(data), tc.cause) {
				t.Errorf("status = %d, body: %s, want 409 naming %q", resp2.StatusCode, data, tc.cause)
			}
		})
	}
}
