package store

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// writeAnalysisDir creates projects/<projectID>/analyses/<id> with the
// given status.json body (or none, when status is empty), returning its
// path.
func writeAnalysisDir(t *testing.T, s *Store, id, status string) string {
	t.Helper()
	dir := filepath.Join(s.Root(), "projects", "proj-1", "analyses", id)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if status != "" {
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(status), fileMode); err != nil {
			t.Fatalf("write status.json: %v", err)
		}
	}
	return dir
}

func TestAnalysesListsNewestFirstAndSkipsTmp(t *testing.T) {
	s := openTestStore(t)
	writeAnalysisDir(t, s, "20260915T080000Z", `{"state":"done"}`)
	writeAnalysisDir(t, s, "20260917T101502Z", `{"state":"failed"}`)
	if err := os.MkdirAll(filepath.Join(s.Root(), "projects", "proj-1", "analyses", "20260918T000000Z.tmp"), dirMode); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}

	got, err := s.Analyses("proj-1")
	if err != nil {
		t.Fatalf("Analyses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Analyses() = %+v, want 2 entries", got)
	}
	if got[0].ID != "20260917T101502Z" || got[0].State != Failed {
		t.Errorf("got[0] = %+v, want the newest, failed one first", got[0])
	}
	if got[1].ID != "20260915T080000Z" || got[1].State != Done {
		t.Errorf("got[1] = %+v, want the older, done one second", got[1])
	}
}

func TestAnalysesSkipsADamagedStatusJSONInsteadOfFailing(t *testing.T) {
	s := openTestStore(t)
	writeAnalysisDir(t, s, "20260915T080000Z", `{"state":"done"}`)
	writeAnalysisDir(t, s, "20260916T080000Z", `not json`)

	got, err := s.Analyses("proj-1")
	if err != nil {
		t.Fatalf("Analyses: %v", err)
	}
	if len(got) != 1 || got[0].ID != "20260915T080000Z" {
		t.Fatalf("Analyses() = %+v, want only the readable entry", got)
	}
}

func TestAnalysesOnMissingProjectReturnsEmpty(t *testing.T) {
	s := openTestStore(t)
	got, err := s.Analyses("no-such-project")
	if err != nil {
		t.Fatalf("Analyses: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Analyses() = %+v, want none", got)
	}
}

func TestAnalysisInfoReadsRankingJSON(t *testing.T) {
	s := openTestStore(t)
	dir := writeAnalysisDir(t, s, "20260917T101502Z", `{"state":"done"}`)
	ranking := `{"target":{"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},"before":[0,0,0,0,0],"after":[0,0,0,0,0],"dependencies":[],"warnings":[]}`
	if err := os.WriteFile(filepath.Join(dir, "ranking.json"), []byte(ranking), fileMode); err != nil {
		t.Fatalf("write ranking.json: %v", err)
	}

	got, err := s.AnalysisInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if got.State != Done {
		t.Errorf("State = %q, want %q", got.State, Done)
	}
	if got.ProjectID != "proj-1" {
		t.Errorf("ProjectID = %q, want %q", got.ProjectID, "proj-1")
	}
	if len(got.Result) == 0 {
		t.Fatal("Result is empty, want the ranking.json content")
	}
	wantCreated := "2026-09-17T10:15:02Z"
	if got.CreatedAt.Format("2006-01-02T15:04:05Z") != wantCreated {
		t.Errorf("CreatedAt = %v, want %s", got.CreatedAt, wantCreated)
	}
}

func TestAnalysisInfoReportsTheFailure(t *testing.T) {
	s := openTestStore(t)
	const message = "trivy database update failed: start /data/tools/trivy/current/trivy: no such file or directory"
	status := `{"state":"failed","steps":[{"name":"resolve","state":"done"},` +
		`{"name":"scan-project","state":"failed","durationMs":0,"error":"` + message + `"}]}`
	writeAnalysisDir(t, s, "20260917T101502Z", status)

	got, err := s.AnalysisInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	want := &StepFailure{Step: "scan-project", Message: message}
	if got.Failure == nil || *got.Failure != *want {
		t.Errorf("Failure = %+v, want %+v", got.Failure, want)
	}
}

func TestAnalysisInfoDoneReportsNoFailure(t *testing.T) {
	s := openTestStore(t)
	status := `{"state":"done","steps":[{"name":"resolve","state":"done"}]}`
	writeAnalysisDir(t, s, "20260917T101502Z", status)

	got, err := s.AnalysisInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if got.Failure != nil {
		t.Errorf("Failure = %+v, want none", got.Failure)
	}
}

func TestAnalysisInfoUnknownIDReturnsErrNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.AnalysisInfo("proj-1", "20260917T101502Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AnalysisInfo(unknown) = %v, want ErrNotFound", err)
	}
}

func TestDeleteAnalysisRemovesTheDirectory(t *testing.T) {
	s := openTestStore(t)
	writeAnalysisDir(t, s, "20260917T101502Z", `{"state":"done"}`)

	if err := s.DeleteAnalysis("proj-1", "20260917T101502Z"); err != nil {
		t.Fatalf("DeleteAnalysis: %v", err)
	}
	if _, err := s.AnalysisInfo("proj-1", "20260917T101502Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AnalysisInfo after delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteAnalysis("proj-1", "20260917T101502Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second DeleteAnalysis = %v, want ErrNotFound", err)
	}
}

func TestAnalysisMethodsRefuseIDsThatEscapeTheDataVolume(t *testing.T) {
	s := openTestStore(t)
	for _, id := range []string{"../private", "a/b", "", ".."} {
		if _, err := s.AnalysisInfo("proj-1", id); !errors.Is(err, ErrNotFound) {
			t.Errorf("AnalysisInfo(%q): err = %v, want ErrNotFound", id, err)
		}
		if err := s.DeleteAnalysis("proj-1", id); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteAnalysis(%q): err = %v, want ErrNotFound", id, err)
		}
	}
}

// status062 and ranking062 are an analysis directory's files as 0.6.2
// wrote them.
const status062 = `{
  "state": "done",
  "createdAt": "2026-11-01T10:00:00Z",
  "steps": [
    {
      "name": "validate",
      "state": "done",
      "durationMs": 1
    },
    {
      "name": "scan-project",
      "state": "done",
      "durationMs": 812
    }
  ],
  "pnpmVersion": "10.34.5",
  "trivyVersion": "0.72.0",
  "trivyDbDate": "2026-10-31T00:00:00Z",
  "target": {
    "os": "linux",
    "cpu": "x64",
    "libc": "glibc",
    "node": "22.17.1",
    "pnpmVer": "10.34.5"
  }
}
`

const ranking062 = `{
  "target": {
    "os": "linux",
    "cpu": "x64",
    "libc": "glibc",
    "node": "22.17.1",
    "pnpmVer": "10.34.5"
  },
  "before": [0, 1, 0, 0, 0],
  "after": null,
  "dependencies": [],
  "warnings": []
}
`

func TestAnalysisStoredBeforePipReadsUnchanged(t *testing.T) {
	s := openTestStore(t)
	dir := writeAnalysisDir(t, s, "20261101T100000Z", status062)
	if err := os.WriteFile(filepath.Join(dir, "ranking.json"), []byte(ranking062), fileMode); err != nil {
		t.Fatal(err)
	}

	got, err := s.AnalysisInfo("proj-1", "20261101T100000Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if string(got.Result) != ranking062 {
		t.Errorf("Result = %s, want ranking.json byte for byte", got.Result)
	}
	if got.PipResult != nil || got.UvVersion != "" {
		t.Errorf("PipResult = %s, UvVersion = %q, want neither", got.PipResult, got.UvVersion)
	}
	if got.State != Done || got.PnpmVersion != "10.34.5" || got.TrivyVersion != "0.72.0" {
		t.Errorf("AnalysisInfo = %+v, want the stored state and tool versions", got)
	}
}

func TestAnalysisInfoReadsPipResult(t *testing.T) {
	s := openTestStore(t)
	status := `{"state":"done","steps":[{"name":"scan","state":"done"}],"pnpmVersion":"","uvVersion":"0.13.7","trivyVersion":"0.72.0","trivyDbDate":"2026-11-19T00:00:00Z","pipTarget":{"python":"3.11.2","os":"linux","cpu":"x86_64","glibc":"2.28","uvVer":"0.13.7"}}`
	dir := writeAnalysisDir(t, s, "20261120T100000Z", status)
	result := `{"target":{"python":"3.11.2","os":"linux","cpu":"x86_64","glibc":"2.28","uvVer":"0.13.7"},"files":["requirements.txt"],"packages":[],"blocking":[],"warnings":[]}`
	if err := os.WriteFile(filepath.Join(dir, "pip-result.json"), []byte(result), fileMode); err != nil {
		t.Fatal(err)
	}

	got, err := s.AnalysisInfo("proj-1", "20261120T100000Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if string(got.PipResult) != result || got.UvVersion != "0.13.7" {
		t.Errorf("PipResult = %s, UvVersion = %q, want pip-result.json and 0.13.7", got.PipResult, got.UvVersion)
	}
	if got.Result != nil || got.PnpmVersion != "" {
		t.Errorf("Result = %s, PnpmVersion = %q, want neither", got.Result, got.PnpmVersion)
	}
}

func TestAnalysesInTheSameSecondAreListedAndReadable(t *testing.T) {
	s := openTestStore(t)
	fixed := mustParseTime(t, "2026-11-24T09:41:07Z")
	defer stubNow(func() time.Time { return fixed })()

	var ids []string
	for range 2 {
		p, err := s.NewDir("analyses", "proj-1")
		if err != nil {
			t.Fatalf("NewDir: %v", err)
		}
		if err := s.WriteJSON(filepath.Join(p.Path(), "status.json"), map[string]string{"state": "done"}); err != nil {
			t.Fatalf("write status.json: %v", err)
		}
		if err := p.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		ids = append(ids, p.ID())
	}

	got, err := s.Analyses("proj-1")
	if err != nil {
		t.Fatalf("Analyses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Analyses() = %+v, want both analyses of the same second", got)
	}
	for _, id := range ids {
		info, err := s.AnalysisInfo("proj-1", id)
		if err != nil {
			t.Fatalf("AnalysisInfo(%q): %v", id, err)
		}
		if !info.CreatedAt.Equal(fixed) || info.State != Done {
			t.Errorf("AnalysisInfo(%q) = created %v, state %q; want %v, done", id, info.CreatedAt, info.State, fixed)
		}
	}
}

func TestJobCreatedAt(t *testing.T) {
	want := mustParseTime(t, "2026-09-17T10:15:02Z")
	tests := []struct {
		id string
		ok bool
	}{
		{"20260917T101502Z", true},
		{"20260917T101502Z-0a1b2c", true},
		{"20260917T101502Z-0A1B2C", false},
		{"20260917T101502Z-0a1b2", false},
		{"20260917T101502Z-0a1b2c3", false},
		{"20260917T101502Z-0a1b2g", false},
		{"20260917T101502Z0a1b2c", false},
		{"20260917T101502Z_0a1b2c", false},
		{"20260917T101502Z-", false},
		{"20260917T101502Z-0a1b2c-0a1b2c", false},
		{"proj-1", false},
		{"", false},
	}
	for _, tt := range tests {
		got, err := JobCreatedAt(tt.id)
		if tt.ok {
			if err != nil || !got.Equal(want) {
				t.Errorf("JobCreatedAt(%q) = %v, %v; want %v", tt.id, got, err, want)
			}
		} else if err == nil {
			t.Errorf("JobCreatedAt(%q) = %v, want an error", tt.id, got)
		}
	}
}

func TestAnalysesWithRandomSuffixesListBySecond(t *testing.T) {
	s := openTestStore(t)
	writeAnalysisDir(t, s, "20261123T100001Z", `{"state":"done"}`)
	writeAnalysisDir(t, s, "20261123T100000Z-f3a9c1", `{"state":"done"}`)
	writeAnalysisDir(t, s, "20261123T100002Z-0b2e7d", `{"state":"done"}`)

	got, err := s.Analyses("proj-1")
	if err != nil {
		t.Fatalf("Analyses: %v", err)
	}
	var ids []string
	for _, info := range got {
		ids = append(ids, info.ID)
	}
	want := []string{"20261123T100002Z-0b2e7d", "20261123T100001Z", "20261123T100000Z-f3a9c1"}
	if !slices.Equal(ids, want) {
		t.Fatalf("Analyses() ids = %v, want %v", ids, want)
	}
}
