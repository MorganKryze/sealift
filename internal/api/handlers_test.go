package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
	"github.com/MorganKryze/sealift/npm"
)

// newTestServer builds a full router against a fresh store and returns an
// httptest.Server, so every case below exercises the real mux, the real
// strict dispatch and Problem Details encoding, not the handler in
// isolation.
func newTestServer(t *testing.T) (*httptest.Server, *Handlers) {
	t.Helper()
	q := jobs.NewQueue(nil)
	t.Cleanup(q.Close)
	h := newTestHandlers(t, q)
	srv := httptest.NewServer(Routes(h))
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

func TestQueueExportInvalidSelectionReturns400WithEveryEntry(t *testing.T) {
	srv, h := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	settings := h.Store.Settings()
	settings.SignatureKey = "top-secret"
	if err := h.Store.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
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

	settings := h.Store.Settings()
	settings.SignatureKey = "top-secret"
	if err := h.Store.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
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

// newTestHandlersWithTrivy is newTestHandlers with the Trivy fake the
// caller chooses, for a test whose export job must reach the reports
// step instead of stopping at whatever the shared fakeTrivy leaves
// unwritten.
func newTestHandlersWithTrivy(t *testing.T, q *jobs.Queue, trivy runner.Trivy) *Handlers {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	tm.GitHubAPI = unroutable
	tm.NPMRegistry = unroutable
	svc := jobs.NewService(st, q, tm, fakePnpm{}, trivy, &npm.Client{})
	return NewHandlers(st, q, svc, tm, trivy)
}

// waitForExportState polls GetExport until it reports one of wantStates
// or the deadline passes.
func waitForExportState(t *testing.T, srv *httptest.Server, projectID, exportID string, wantStates ...State) Export {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("%s/api/projects/%s/exports/%s", srv.URL, projectID, exportID))
		if err == nil {
			var e Export
			if json.NewDecoder(resp.Body).Decode(&e) == nil {
				resp.Body.Close()
				for _, want := range wantStates {
					if e.State == want {
						return e
					}
				}
			} else {
				resp.Body.Close()
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("export %s never reached %v in time", exportID, wantStates)
	return Export{}
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
	h := newTestHandlersWithTrivy(t, q, exportTrivyFake{})
	srv := httptest.NewServer(Routes(h))
	defer srv.Close()

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}

	settings := h.Store.Settings()
	settings.SignatureKey = "top-secret"
	if err := h.Store.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
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

	final := waitForExportState(t, srv, project.Id, queued.Id, Done, Failed)
	if final.State != Done {
		t.Fatalf("export state = %q, want %q: both selected versions of left-pad should resolve with their stub lockfiles", final.State, Done)
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
	srv := httptest.NewServer(Routes(h))
	defer srv.Close()

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
			waitForTerminalState(t, h, analysisID)
		}
	}()

	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	analysisID = (*project.Analyses)[0].Id
	if state, ok := h.Service.LiveState(analysisID); !ok || state != store.Queued {
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

func TestSettingsRoundTripMasksSignatureKey(t *testing.T) {
	srv, _ := newTestServer(t)

	getResp, err := http.Get(srv.URL + "/api/settings")
	if err != nil {
		t.Fatalf("GET /api/settings: %v", err)
	}
	var settings Settings
	if err := json.NewDecoder(getResp.Body).Decode(&settings); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	getResp.Body.Close()
	if settings.SignatureKey != "" {
		t.Fatalf("SignatureKey = %q, want empty before any key is set", settings.SignatureKey)
	}

	settings.SignatureKey = "top-secret"
	settings.MinReleaseAgeDays = 14
	body, _ := json.Marshal(settings)
	putReq, err := http.NewRequest(http.MethodPut, srv.URL+"/api/settings", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build PUT: %v", err)
	}
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT /api/settings: %v", err)
	}
	var updated Settings
	if err := json.NewDecoder(putResp.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated settings: %v", err)
	}
	putResp.Body.Close()
	if updated.SignatureKey != maskedSignatureKey {
		t.Fatalf("SignatureKey after update = %q, want the mask %q", updated.SignatureKey, maskedSignatureKey)
	}

	// Sending the mask back keeps the real key, proving a client that only
	// changes another field never has to know the real key.
	updated.MinReleaseAgeDays = 21
	body, _ = json.Marshal(updated)
	putReq2, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/settings", bytes.NewReader(body))
	putReq2.Header.Set("Content-Type", "application/json")
	putResp2, err := http.DefaultClient.Do(putReq2)
	if err != nil {
		t.Fatalf("second PUT: %v", err)
	}
	putResp2.Body.Close()

	getResp2, err := http.Get(srv.URL + "/api/settings")
	if err != nil {
		t.Fatalf("GET after second PUT: %v", err)
	}
	var final Settings
	if err := json.NewDecoder(getResp2.Body).Decode(&final); err != nil {
		t.Fatalf("decode final settings: %v", err)
	}
	getResp2.Body.Close()
	if final.MinReleaseAgeDays != 21 {
		t.Errorf("MinReleaseAgeDays = %d, want 21 (the second update applied)", final.MinReleaseAgeDays)
	}
	if final.SignatureKey != maskedSignatureKey {
		t.Errorf("SignatureKey = %q, want it to still read as set", final.SignatureKey)
	}
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

	delProject, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/projects/"+project.Id, nil)
	if err != nil {
		t.Fatalf("build DELETE project: %v", err)
	}
	delProjectResp, err := http.DefaultClient.Do(delProject)
	if err != nil {
		t.Fatalf("DELETE project: %v", err)
	}
	delProjectResp.Body.Close()
	if delProjectResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE project status = %d, want 204", delProjectResp.StatusCode)
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

func TestGetToolsSucceedsWithoutNetworkAccess(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/tools")
	if err != nil {
		t.Fatalf("GET /api/tools: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body: %s", resp.StatusCode, body)
	}
	var state ToolsState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode tools state: %v", err)
	}
	if state.PnpmInstalled == nil || state.TrivyInstalled == nil {
		t.Errorf("ToolsState = %+v, want non-nil empty slices, not null", state)
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

// waitForTerminalState polls Service.LiveState until id is no longer
// tracked, meaning Service's finalizer goroutine has already reacted to
// its "end" event and stopped touching its directory. A test that races
// a queued job against its own t.TempDir cleanup needs this: the
// finalizer keeps writing after the job itself returns.
func waitForTerminalState(t *testing.T, h *Handlers, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h.Service.LiveState(id); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s was still tracked after the deadline", id)
}

// waitForState polls GetAnalysis until it reports one of wantStates or the
// deadline passes, so a test can watch a real, fake-tool-backed analysis
// reach a terminal state without hardcoding a sleep.
func waitForState(t *testing.T, srv *httptest.Server, projectID, analysisID string, wantStates ...State) Analysis {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("%s/api/projects/%s/analyses/%s", srv.URL, projectID, analysisID))
		if err == nil {
			var a Analysis
			if json.NewDecoder(resp.Body).Decode(&a) == nil {
				resp.Body.Close()
				for _, want := range wantStates {
					if a.State == want {
						return a
					}
				}
			} else {
				resp.Body.Close()
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("analysis %s never reached %v in time", analysisID, wantStates)
	return Analysis{}
}

func TestQueueAndGetAnalysisReachesATerminalState(t *testing.T) {
	srv, _ := newTestServer(t)
	project, resp := createProject(t, srv, `{"name":"left-pad","dependencies":{"left-pad":"1.3.0"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CreateProject status = %d", resp.StatusCode)
	}
	analysisID := (*project.Analyses)[0].Id

	// The fake pnpm and Trivy runners never produce a real lockfile or
	// report, so this analysis cannot reach done; it still must reach a
	// terminal state instead of hanging, and Service's finalizer must not
	// leave a stray .tmp directory behind once it does.
	final := waitForState(t, srv, project.Id, analysisID, Failed, Done)
	if final.Id != analysisID {
		t.Fatalf("final analysis id = %q, want %q", final.Id, analysisID)
	}
}
