package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeExportDir creates projects/proj-1/exports/<id> with the given files
// (name to content).
func writeExportDir(t *testing.T, s *Store, id string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(s.Root(), "projects", "proj-1", "exports", id)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), fileMode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestExportsListsNewestFirstAndSkipsTmp(t *testing.T) {
	s := openTestStore(t)
	writeExportDir(t, s, "20260915T080000Z", map[string]string{"manifest.json": `{"analysisId":"a1"}`})
	writeExportDir(t, s, "20260917T101502Z", map[string]string{"manifest.json": `{"analysisId":"a2"}`})
	if err := os.MkdirAll(filepath.Join(s.Root(), "projects", "proj-1", "exports", "20260918T000000Z.tmp"), dirMode); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}

	got, err := s.Exports("proj-1")
	if err != nil {
		t.Fatalf("Exports: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Exports() = %+v, want 2 entries", got)
	}
	if got[0].ID != "20260917T101502Z" || got[0].AnalysisID != "a2" {
		t.Errorf("got[0] = %+v, want the newest entry first", got[0])
	}
}

func TestExportInfoListsFilesAndAnalysisID(t *testing.T) {
	s := openTestStore(t)
	writeExportDir(t, s, "20260917T101502Z", map[string]string{
		"manifest.json":       `{"analysisId":"20260916T090000Z","createdAt":"2026-09-17T10:15:03Z"}`,
		"packages_npm.tar.gz": "data",
		"summary.md":          "# summary",
	})

	got, err := s.ExportInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("ExportInfo: %v", err)
	}
	if got.AnalysisID != "20260916T090000Z" {
		t.Errorf("AnalysisID = %q, want %q", got.AnalysisID, "20260916T090000Z")
	}
	if got.CreatedAt.Format("2006-01-02T15:04:05Z") != "2026-09-17T10:15:03Z" {
		t.Errorf("CreatedAt = %v, want the manifest's own time", got.CreatedAt)
	}
	wantFiles := []string{"manifest.json", "packages_npm.tar.gz", "summary.md"}
	if len(got.Files) != len(wantFiles) {
		t.Fatalf("Files = %v, want %v", got.Files, wantFiles)
	}
	for i, name := range wantFiles {
		if got.Files[i] != name {
			t.Errorf("Files[%d] = %q, want %q", i, got.Files[i], name)
		}
	}
}

// TestExportInfoReadsFailedStatus proves the fix for finding 2: a failed
// or cancelled export keeps its directory, and ExportInfo reads its state,
// analysis id and cause from status.json instead of assuming Done the way
// it does when status.json is absent. status.json itself must not leak
// into Files: it is bookkeeping, not one of the export's deliverables.
func TestExportInfoReadsFailedStatus(t *testing.T) {
	s := openTestStore(t)
	writeExportDir(t, s, "20260917T101502Z", map[string]string{
		"status.json": `{"state":"failed","analysisId":"20260916T090000Z","steps":[` +
			`{"name":"package-list","state":"done","durationMs":5},` +
			`{"name":"download","state":"failed","durationMs":120,"error":"jobs: download widgets@1.1.0: possible tampering"}` +
			`]}`,
	})

	got, err := s.ExportInfo("proj-1", "20260917T101502Z")
	if err != nil {
		t.Fatalf("ExportInfo: %v", err)
	}
	if got.State != Failed {
		t.Errorf("State = %q, want %q", got.State, Failed)
	}
	if got.AnalysisID != "20260916T090000Z" {
		t.Errorf("AnalysisID = %q, want %q", got.AnalysisID, "20260916T090000Z")
	}
	if got.Failure == nil {
		t.Fatalf("Failure = nil, want a StepFailure")
	}
	if got.Failure.Step != "download" || got.Failure.Message != "jobs: download widgets@1.1.0: possible tampering" {
		t.Errorf("Failure = %+v, want step download with the download step's own message", got.Failure)
	}
	for _, name := range got.Files {
		if name == "status.json" {
			t.Errorf("Files = %v, want status.json excluded", got.Files)
		}
	}
}

func TestExportInfoUnknownIDReturnsErrNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.ExportInfo("proj-1", "20260917T101502Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ExportInfo(unknown) = %v, want ErrNotFound", err)
	}
}

func TestDeleteExportRemovesTheDirectory(t *testing.T) {
	s := openTestStore(t)
	writeExportDir(t, s, "20260917T101502Z", map[string]string{"manifest.json": `{}`})

	if err := s.DeleteExport("proj-1", "20260917T101502Z"); err != nil {
		t.Fatalf("DeleteExport: %v", err)
	}
	if _, err := s.ExportInfo("proj-1", "20260917T101502Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ExportInfo after delete = %v, want ErrNotFound", err)
	}
}

func TestExportFileServesOneFileAndRefusesEscape(t *testing.T) {
	s := openTestStore(t)
	writeExportDir(t, s, "20260917T101502Z", map[string]string{"summary.md": "# hello"})

	f, err := s.ExportFile("proj-1", "20260917T101502Z", "summary.md")
	if err != nil {
		t.Fatalf("ExportFile: %v", err)
	}
	defer f.Close()
	data := make([]byte, 7)
	if _, err := f.Read(data); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "# hello" {
		t.Fatalf("content = %q, want %q", data, "# hello")
	}

	for _, name := range []string{"../../private/settings.json", "../summary.md", "a/b"} {
		if _, err := s.ExportFile("proj-1", "20260917T101502Z", name); !errors.Is(err, ErrNotFound) {
			t.Errorf("ExportFile(%q): err = %v, want ErrNotFound", name, err)
		}
	}
}

func TestExportFileUnknownNameReturnsErrNotFound(t *testing.T) {
	s := openTestStore(t)
	writeExportDir(t, s, "20260917T101502Z", map[string]string{"summary.md": "# hello"})

	if _, err := s.ExportFile("proj-1", "20260917T101502Z", "missing.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ExportFile(missing): err = %v, want ErrNotFound", err)
	}
}
