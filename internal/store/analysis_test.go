package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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

func TestAnalysisInfoReportsTheFailedStep(t *testing.T) {
	s := openTestStore(t)
	status := `{"state":"failed","steps":[{"name":"resolve","state":"done"},{"name":"scan","state":"failed"}]}`
	writeAnalysisDir(t, s, "20260917T101502Z", status)

	got, err := s.AnalysisInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if got.FailedStep != "scan" {
		t.Errorf("FailedStep = %q, want %q", got.FailedStep, "scan")
	}
}

func TestAnalysisInfoDoneReportsNoFailedStep(t *testing.T) {
	s := openTestStore(t)
	status := `{"state":"done","steps":[{"name":"resolve","state":"done"}]}`
	writeAnalysisDir(t, s, "20260917T101502Z", status)

	got, err := s.AnalysisInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("AnalysisInfo: %v", err)
	}
	if got.FailedStep != "" {
		t.Errorf("FailedStep = %q, want none", got.FailedStep)
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
