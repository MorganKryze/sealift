package jobs

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
)

// jobIDLayout spells a time as the store's analysis and export ids do.
const jobIDLayout = "20060102T150405Z"

// sealedCrossing writes, under the project projectID, a done pip analysis
// whose set is pkgs, and an export of it in state, created at. A done
// export keeps its manifest.json; a failed or cancelled one its status.json
// alone, as the export job leaves them.
func sealedCrossing(t *testing.T, st *store.Store, projectID string, at time.Time, state store.State, pkgs ...PipPackage) (exportID, analysisID string) {
	t.Helper()
	exportID, analysisID = at.UTC().Format(jobIDLayout), at.Add(-time.Hour).UTC().Format(jobIDLayout)
	project := filepath.Join(st.Root(), "projects", projectID)
	analysis := filepath.Join(project, "analyses", analysisID)
	export := filepath.Join(project, "exports", exportID)
	for _, dir := range []string{analysis, export} {
		if err := os.MkdirAll(dir, 0o770); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, v any) {
		t.Helper()
		if err := st.WriteJSON(path, v); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(filepath.Join(analysis, "status.json"), statusFile{State: store.Done, CreatedAt: at.Add(-time.Hour).UTC(), PipTarget: &store.DefaultPipTarget})
	write(filepath.Join(analysis, "pip-result.json"), PipResult{
		Target: store.DefaultPipTarget, Files: []string{"requirements.txt"}, Packages: nonNil(pkgs), Blocking: []PipBlocking{}, Warnings: []string{},
	})
	if state == store.Done {
		write(filepath.Join(export, "manifest.json"), map[string]any{"analysisId": analysisID, "createdAt": at.UTC()})
	} else {
		write(filepath.Join(export, "status.json"), map[string]any{"state": state, "analysisId": analysisID})
	}
	return exportID, analysisID
}

// sealedPkg is a package of a sealed set, with its CVEs as the earlier
// analysis recorded them.
func sealedPkg(name, version string) PipPackage {
	return PipPackage{Name: name, Version: version, Files: []string{}, CVEs: []PipFinding{}}
}

func newPipProject(t *testing.T, st *store.Store, name string) store.Project {
	t.Helper()
	p, err := st.CreatePipProject(name, []store.RequirementsFile{reqFile("requirements.txt", "requests==2.32.3\n")}, store.DefaultPipTarget)
	if err != nil {
		t.Fatalf("CreatePipProject: %v", err)
	}
	return p
}

func TestPreviousCrossingIsTheLatestDoneExportOfTheSameName(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
	set := resolved("requests", "2.32.3")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)

	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	twin := newPipProject(t, st, "  data TOOLS ")
	other := newPipProject(t, st, "Other tools")
	npmProject, err := st.CreateProject("Data tools", []byte(`{"name":"data-tools","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}`))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	sealedCrossing(t, st, a.Project.ID, now.Add(-5*day), store.Done, sealedPkg("requests", "2.30.0"))
	wantExport, wantAnalysis := sealedCrossing(t, st, twin.ID, now.Add(-3*day), store.Done, sealedPkg("requests", "2.31.0"))
	sealedCrossing(t, st, twin.ID, now.Add(-2*day), store.Failed, sealedPkg("requests", "2.0.0"))
	sealedCrossing(t, st, a.Project.ID, now.Add(-day), store.Cancelled, sealedPkg("requests", "2.0.1"))
	sealedCrossing(t, st, other.ID, now.Add(-day), store.Done, sealedPkg("requests", "2.0.2"))
	sealedCrossing(t, st, npmProject.ID, now.Add(-day), store.Done, sealedPkg("requests", "2.0.3"))
	sealedCrossing(t, st, a.Project.ID, now.Add(2*time.Hour), store.Done, sealedPkg("requests", "2.0.4"))

	want := &PipPreviousCrossing{
		ProjectID: twin.ID, ProjectName: "  data TOOLS ", ExportID: wantExport, AnalysisID: wantAnalysis, SealedAt: now.Add(-3 * day),
	}
	got, earlier, err := previousCrossing(st, a.Project, now)
	if err != nil {
		t.Fatalf("previousCrossing: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("previous crossing = %+v, want %+v", got, want)
	}
	if wantSet := []runner.Resolved{{Name: "requests", Version: "2.31.0"}}; !slices.Equal(earlier, wantSet) {
		t.Errorf("earlier set = %+v, want %+v", earlier, wantSet)
	}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	if res.Previous == nil || res.Previous.ExportID != wantExport || res.Previous.ProjectID != twin.ID {
		t.Errorf("recorded previous crossing = %+v, want export %s of %s", res.Previous, wantExport, twin.ID)
	}
	if len(res.Packages) != 1 || res.Packages[0].Previous == nil || res.Packages[0].Previous.Version != "2.31.0" {
		t.Errorf("packages = %+v, want requests coming from 2.31.0", res.Packages)
	}
}

func TestPreviousCrossingScansEachEarlierVersionInTheSameRun(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget,
		reqFile("requirements.txt", "jinja2==3.1.4\nnumpy==2.1.3\nrequests==2.32.3\n"))
	set := resolved("jinja2", "3.1.4", "numpy", "2.1.3", "requests", "2.32.3")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)
	trivy := &cannedTrivy{report: pipTrivyReport(
		[5]string{"Jinja2", "3.1.2", "CVE-2024-22195", "MEDIUM", "3.1.3"},
		[5]string{"requests", "2.32.3", "CVE-2024-47081", "LOW", ""},
	)}
	a.Trivy = trivy
	sealedCrossing(t, st, a.Project.ID, time.Now().Add(-48*time.Hour), store.Done,
		sealedPkg("jinja2", "3.1.2"), sealedPkg("numpy", "1.26.4"), sealedPkg("requests", "2.32.3"))

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	jinjaCVE := PipFinding{ID: "CVE-2024-22195", Severity: "MEDIUM", FixedVersions: []string{"3.1.3"}, Title: "test finding"}
	requestsCVE := PipFinding{ID: "CVE-2024-47081", Severity: "LOW", FixedVersions: []string{}, Title: "test finding"}
	want := map[string]*PipPrevious{
		"jinja2":   {Version: "3.1.2", CVEs: []PipFinding{jinjaCVE}},
		"numpy":    {Version: "1.26.4", CVEs: []PipFinding{}, MajorJump: true},
		"requests": {Version: "2.32.3", CVEs: []PipFinding{requestsCVE}},
	}
	if len(res.Packages) != 3 {
		t.Fatalf("packages = %+v, want jinja2, numpy and requests", res.Packages)
	}
	for _, p := range res.Packages {
		if !reflect.DeepEqual(p.Previous, want[p.Name]) {
			t.Errorf("%s previous = %+v, want %+v", p.Name, p.Previous, want[p.Name])
		}
	}
	if got := res.Packages[0].CVEs; len(got) != 0 {
		t.Errorf("jinja2 3.1.4 CVEs = %+v, want none: the finding is on 3.1.2", got)
	}
	got := scannedPurls(t, trivy)
	slices.Sort(got)
	wantPurls := []string{"pkg:pypi/jinja2@3.1.2", "pkg:pypi/jinja2@3.1.4", "pkg:pypi/numpy@1.26.4", "pkg:pypi/numpy@2.1.3", "pkg:pypi/requests@2.32.3"}
	if !slices.Equal(got, wantPurls) {
		t.Errorf("scanned purls = %v, want %v: each earlier version once, in the same scan", got, wantPurls)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %q, want none: an earlier version is never outside the set", res.Warnings)
	}
	if _, ok := res.Advisories["CVE-2024-22195"]; !ok {
		t.Errorf("advisories = %+v, want the earlier version's CVE described", res.Advisories)
	}
}

func TestPreviousCrossingListsThePackagesThatLeft(t *testing.T) {
	a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "idna==3.10\nrequests==2.32.3\n"))
	set := resolved("idna", "3.10", "requests", "2.32.3")
	a.Uv = &fakeUv{lock: "x==1\n", set: set}
	serveWheels(t, a, set)
	a.Trivy = &cannedTrivy{report: pipTrivyReport([5]string{"six", "1.16.0", "CVE-2099-0001", "HIGH", ""})}
	sealedCrossing(t, st, a.Project.ID, time.Now().Add(-48*time.Hour), store.Done,
		sealedPkg("requests", "2.31.0"), sealedPkg("six", "1.16.0"))

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	want := []PipRemoved{{Name: "six", Version: "1.16.0", CVEs: []PipFinding{
		{ID: "CVE-2099-0001", Severity: "HIGH", FixedVersions: []string{}, Title: "test finding"},
	}}}
	if !reflect.DeepEqual(res.Removed, want) {
		t.Errorf("removed = %+v, want %+v", res.Removed, want)
	}
	if len(res.Packages) != 2 || res.Packages[0].Name != "idna" || res.Packages[0].Previous != nil {
		t.Errorf("packages = %+v, want idna new, with no earlier version", res.Packages)
	}
}

func TestPreviousCrossingThatDoesNotReadWarns(t *testing.T) {
	cases := []struct {
		name   string
		damage func(t *testing.T, analysisDir string)
	}{
		{"an analysis with no pip-result.json", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "pip-result.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a pip-result.json that is no JSON", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "pip-result.json"), []byte("{"), 0o660); err != nil {
				t.Fatal(err)
			}
		}},
		{"an analysis that is gone", func(t *testing.T, dir string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		}},
		{"a package name that is no package name", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "pip-result.json"), []byte(`{"packages":[{"name":"../x","version":"1.0","files":[],"cves":[]}]}`), 0o660); err != nil {
				t.Fatal(err)
			}
		}},
		{"a version that is no exact version", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "pip-result.json"), []byte(`{"packages":[{"name":"six","version":">=1","files":[],"cves":[]}]}`), 0o660); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, st := newPipAnalysis(t, newCountingIndex(t).URL(), store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
			set := resolved("requests", "2.32.3")
			a.Uv = &fakeUv{lock: "x==1\n", set: set}
			serveWheels(t, a, set)
			exportID, analysisID := sealedCrossing(t, st, a.Project.ID, time.Now().Add(-48*time.Hour), store.Done, sealedPkg("requests", "2.31.0"))
			c.damage(t, filepath.Join(st.Root(), "projects", a.Project.ID, "analyses", analysisID))

			if _, _, err := previousCrossing(st, a.Project, time.Now()); err == nil {
				t.Error("previousCrossing succeeded, want an error")
			}
			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, raw := readPipResult(t, st, a)
			if want := []string{"The previous crossing Data tools could not be read, so nothing is compared"}; !slices.Equal(res.Warnings, want) {
				t.Errorf("warnings = %q, want %q", res.Warnings, want)
			}
			for _, key := range []string{`"previous"`, `"removed"`} {
				if strings.Contains(string(raw), key) {
					t.Errorf("pip-result.json = %s, holds %s, want it absent", raw, key)
				}
			}
			if log := pipLog(t, a); !strings.Contains(log, "the previous crossing, export "+exportID+", could not be read: ") {
				t.Errorf("log = %q, want the cause of export %s", log, exportID)
			}
		})
	}
}

func TestPipMajorJump(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"4.2.16", "5.1.4", true},
		{"1.26.4", "2.1.3", true},
		{"2023.11.17", "2024.8.30", false},
		{"0.19", "0.20", false},
		{"3.1.3", "3.1.5", false},
		{"1!1.0", "2.0", true},
		{"1!1.0", "1!1.5", false},
		{"v2.0", "2.1", false},
		{"3.1.4", "3.1.4", false},
		{"999.1", "1000.1", false},
	}
	for _, c := range cases {
		if got := pipMajorJump(c.from, c.to); got != c.want {
			t.Errorf("pipMajorJump(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}
