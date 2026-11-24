package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/report"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
)

// --- test helpers ---

type tarFile struct {
	name, body string
}

func makeTarball(t *testing.T, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg, ModTime: time.Unix(1, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sriOf(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func writeLockfile(t *testing.T, path string, pkgs ...npm.LockPackage) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\npackages:\n")
	for _, p := range pkgs {
		// The key is quoted: pnpm keys starting with "@" (scoped packages)
		// are not valid unquoted YAML plain scalars.
		fmt.Fprintf(&b, "  \"%s@%s\":\n    resolution: {integrity: %s}\n", p.Name, p.Version, p.Integrity)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o664); err != nil {
		t.Fatal(err)
	}
}

// exportFakeTrivy writes canned reports instead of running the real binary.
type exportFakeTrivy struct {
	scanJSON string
}

func (f *exportFakeTrivy) ScanSBOM(_ context.Context, _, outPath string) (string, error) {
	return "", os.WriteFile(outPath, []byte(f.scanJSON), 0o664)
}

func (f *exportFakeTrivy) ConvertToCycloneDX(_ context.Context, _, outPath string) (string, error) {
	return "", os.WriteFile(outPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), 0o664)
}

func (f *exportFakeTrivy) UpdateDB(_ context.Context) (string, error) { return "", nil }

const candidatesTrivyJSON = `{
  "SchemaVersion": 2,
  "Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-WIDGET-OLD", "PkgName": "widgets", "InstalledVersion": "1.0.0", "FixedVersion": "1.1.0", "Severity": "HIGH", "Title": "widgets bug"},
    {"VulnerabilityID": "CVE-GADGET-SHARED", "PkgName": "@scope/gadget", "InstalledVersion": "2.0.0", "Severity": "CRITICAL", "Title": "gadget shared bug"},
    {"VulnerabilityID": "CVE-GADGET-SHARED", "PkgName": "@scope/gadget", "InstalledVersion": "2.1.0", "Severity": "CRITICAL", "Title": "gadget shared bug"},
    {"VulnerabilityID": "CVE-GADGET-NEW", "PkgName": "@scope/gadget", "InstalledVersion": "2.1.0", "Severity": "MEDIUM", "Title": "gadget new bug"},
    {"VulnerabilityID": "CVE-GADGET-OTHER", "PkgName": "@scope/gadget", "InstalledVersion": "2.2.0", "Severity": "MEDIUM", "Title": "gadget other bug"}
  ]}]
}`

const exportScanJSON = `{
  "SchemaVersion": 2,
  "Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-GADGET-SHARED", "PkgName": "@scope/gadget", "InstalledVersion": "2.1.0", "Severity": "CRITICAL", "Title": "gadget shared bug"}
  ]}]
}`

// testHarness builds a project, an analysis directory and a registry
// serving real tarballs for widgets@1.1.0 (no publishConfig), @scope/gadget
// (with publishConfig) at 2.0.0, 2.1.0 and 2.2.0, and helper@3.0.0 (no
// publishConfig, project only). @scope/gadget has two candidates so a test
// can select both at once: a dependency may select any subset of its
// current version and its candidates, not just one.
type testHarness struct {
	t        *testing.T
	store    *store.Store
	registry *httptest.Server
	root     string
	requests atomic.Int32 // every tarball request the registry served, across the harness's lifetime
	onFetch  func()       // called on every tarball request, before it is served
	widgets  []byte
	gadget20 []byte
	gadget21 []byte
	gadget22 []byte
	helper   []byte
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	h := &testHarness{t: t}
	h.widgets = makeTarball(t, tarFile{"package/package.json", `{"name":"widgets","version":"1.1.0"}`})
	h.gadget20 = makeTarball(t, tarFile{"package/package.json", `{"name":"@scope/gadget","version":"2.0.0","publishConfig":{"access":"public"}}`})
	h.gadget21 = makeTarball(t, tarFile{"package/package.json", `{"name":"@scope/gadget","version":"2.1.0","publishConfig":{"access":"public"}}`})
	h.gadget22 = makeTarball(t, tarFile{"package/package.json", `{"name":"@scope/gadget","version":"2.2.0","publishConfig":{"access":"public"}}`})
	h.helper = makeTarball(t, tarFile{"package/package.json", `{"name":"helper","version":"3.0.0"}`})

	h.registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.requests.Add(1)
		if h.onFetch != nil {
			h.onFetch()
		}
		switch r.URL.Path {
		case "/widgets/-/widgets-1.1.0.tgz":
			_, _ = w.Write(h.widgets)
		case "/@scope/gadget/-/gadget-2.1.0.tgz":
			_, _ = w.Write(h.gadget21)
		case "/@scope/gadget/-/gadget-2.2.0.tgz":
			_, _ = w.Write(h.gadget22)
		case "/helper/-/helper-3.0.0.tgz":
			_, _ = w.Write(h.helper)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.registry.Close)

	root := t.TempDir()
	st, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	h.store = st
	h.root = root
	return h
}

// buildAnalysis writes a fake analyses/<id> directory with the lockfiles
// and Trivy report an export reads.
func (h *testHarness) buildAnalysis(analysisDir string) {
	writeLockfile(h.t, filepath.Join(analysisDir, "candidates", "widgets@1.0.0", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "widgets", Version: "1.0.0", Integrity: sriOf([]byte("widgets-1.0.0"))})
	writeLockfile(h.t, filepath.Join(analysisDir, "candidates", "widgets@1.1.0", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "widgets", Version: "1.1.0", Integrity: sriOf(h.widgets)})
	writeLockfile(h.t, filepath.Join(analysisDir, "candidates", "@scope", "gadget@2.0.0", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "@scope/gadget", Version: "2.0.0", Integrity: sriOf(h.gadget20)})
	writeLockfile(h.t, filepath.Join(analysisDir, "candidates", "@scope", "gadget@2.1.0", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "@scope/gadget", Version: "2.1.0", Integrity: sriOf(h.gadget21)})
	writeLockfile(h.t, filepath.Join(analysisDir, "candidates", "@scope", "gadget@2.2.0", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "@scope/gadget", Version: "2.2.0", Integrity: sriOf(h.gadget22)})
	writeLockfile(h.t, filepath.Join(analysisDir, "project", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "helper", Version: "3.0.0", Integrity: sriOf(h.helper)})

	if err := os.WriteFile(filepath.Join(analysisDir, "candidates.trivy.json"), []byte(candidatesTrivyJSON), 0o664); err != nil {
		h.t.Fatal(err)
	}
	status := analysisStatus{CreatedAt: time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC), TrivyVersion: "0.72.0", TrivyDBDate: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
	data, _ := json.Marshal(status)
	if err := os.WriteFile(filepath.Join(analysisDir, "status.json"), data, 0o664); err != nil {
		h.t.Fatal(err)
	}
}

func (h *testHarness) result() Result {
	return Result{
		Before: Vector{1, 1, 0, 0, 0},
		After:  &Vector{1, 0, 1, 0, 0},
		Dependencies: []DependencyResult{
			{
				Name: "widgets", Current: "1.0.0", Best: "1.1.0", Vector: Vector{0, 1, 0, 0, 0},
				Candidates: []Candidate{{Version: "1.1.0", Vector: Vector{0, 0, 0, 0, 0}, Key: true, Resolved: true}},
			},
			{
				Name: "@scope/gadget", Current: "2.0.0", Best: "2.2.0", Vector: Vector{1, 0, 0, 0, 0},
				Candidates: []Candidate{
					{
						Version: "2.1.0", Vector: Vector{1, 0, 1, 0, 0}, Key: true, Resolved: true,
						Signals: []Signal{{Name: "install-script-added", Evidence: "adds a postinstall script", Blocking: false}},
					},
					{
						Version: "2.2.0", Vector: Vector{0, 0, 1, 0, 0}, Key: true, Resolved: true,
						Signals: []Signal{{Name: "publisher-changed", Evidence: "published by someone else", Blocking: false}},
					},
				},
			},
		},
	}
}

func (h *testHarness) newExport(t *testing.T, analysisDir, exportDir string, includeProject bool) *Export {
	t.Helper()
	return &Export{
		Store:    h.store,
		Registry: &npm.Client{Registry: h.registry.URL, Backoff: func(int) time.Duration { return 0 }},
		Trivy:    &exportFakeTrivy{scanJSON: exportScanJSON},
		Project:  store.Project{ID: "demo", Name: "demo", Target: store.Target{OS: "linux", CPU: "x64", Libc: "glibc", Node: "22.17.1", PnpmVer: "10.34.5"}},
		Settings: store.Settings{DownloadParallelism: 4},
		Analysis: AnalysisRef{ID: "20260910T080000Z", Dir: analysisDir, Result: h.result()},
		// @scope/gadget selects two versions at once, so a version that
		// breaks the build is not the only one already sitting in Nexus.
		Request: ExportRequest{Selection: map[string][]string{"widgets": {"1.1.0"}, "@scope/gadget": {"2.1.0", "2.2.0"}}, IncludeProject: includeProject},
		Dir:     exportDir,
		ID:      "20260917T101502Z",
	}
}

func noopEmit(Event) {}

// The summary's After row and remaining list describe the scan of the set
// exported, not the analysis' own picks, whatever the analysis measured.
func TestExportSummaryPrintsTheExportedScan(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, true)
	exp.Analysis.Result.After = &Vector{7, 7, 7, 7, 7}
	// CVE-TWICE sits on two packages and counts once; CVE-MIXED is high on
	// one package and medium on another, and the high one wins.
	exp.Trivy = &exportFakeTrivy{scanJSON: `{
  "SchemaVersion": 2,
  "Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-TWICE", "PkgName": "widgets", "InstalledVersion": "1.1.0", "Severity": "CRITICAL", "Title": "t"},
    {"VulnerabilityID": "CVE-TWICE", "PkgName": "helper", "InstalledVersion": "3.0.0", "Severity": "CRITICAL", "Title": "t"},
    {"VulnerabilityID": "CVE-MIXED", "PkgName": "widgets", "InstalledVersion": "1.1.0", "Severity": "MEDIUM", "Title": "m"},
    {"VulnerabilityID": "CVE-MIXED", "PkgName": "helper", "InstalledVersion": "3.0.0", "Severity": "HIGH", "Title": "m"},
    {"VulnerabilityID": "CVE-LOW", "PkgName": "helper", "InstalledVersion": "3.0.0", "Severity": "LOW", "Title": "l"}
  ]}]
}`}
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	summary, err := os.ReadFile(filepath.Join(exportDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(summary, []byte("| In the archive | 1 | 1 | 0 | 1 | 0 |")) {
		t.Errorf("summary.md After row is not the exported scan's (1, 1, 0, 1, 0):\n%s", summary)
	}
	if bytes.Contains(summary, []byte("| 7 | 7 | 7 | 7 | 7 |")) {
		t.Errorf("summary.md prints the analysis' own After row:\n%s", summary)
	}
	for _, want := range []string{"CVE-TWICE", "CVE-MIXED"} {
		if !bytes.Contains(summary, []byte(want)) {
			t.Errorf("summary.md missing remaining %s:\n%s", want, summary)
		}
	}
}

// A delta export ships only the closures of the dependencies it changes,
// while Before counts the whole project: the two rows say so, so a zero
// After is not read as the whole project being clean.
func TestExportSummaryLabelsBothRowsByScope(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	summary, err := os.ReadFile(filepath.Join(exportDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| Before (whole project) |", "| In the archive |"} {
		if !bytes.Contains(summary, []byte(want)) {
			t.Errorf("summary.md missing the row %q:\n%s", want, summary)
		}
	}
}

// With the project tree in the archive, the archive's own scan counts the
// old versions too, so the summary also prints the project once the
// selection applies, from the analysis' project scan.
func TestExportSummaryPrintsTheProjectedRow(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	scan := `{"SchemaVersion": 2, "Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-OLD", "PkgName": "widgets", "InstalledVersion": "1.0.0", "Severity": "HIGH", "Title": "o"},
    {"VulnerabilityID": "CVE-OTHER", "PkgName": "helper", "InstalledVersion": "3.0.0", "Severity": "LOW", "Title": "l"}
  ]}]}`
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(scan), 0o600); err != nil {
		t.Fatal(err)
	}
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, true)
	for i, d := range exp.Analysis.Result.Dependencies {
		if d.Name == "widgets" {
			exp.Analysis.Result.Dependencies[i].CVEs = []CVE{{ID: "CVE-OLD", Severity: "HIGH"}}
		}
	}
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	summary, err := os.ReadFile(filepath.Join(exportDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(summary, []byte("| After (project with this selection) | 0 | 0 | 0 | 1 | 0 |")) {
		t.Errorf("summary.md lacks the projected row without CVE-OLD:\n%s", summary)
	}
}

func TestExportRun(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, true)

	var mu sync.Mutex
	var events []Event
	// downloadAll emits "progress" from several goroutines at once, so the
	// collector needs its own lock: exp.Run itself only guarantees emit is
	// called, not that it is safe to call concurrently without one.
	emit := func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	if err := exp.Run(context.Background(), emit); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sawDownloadDone, sawProgress := false, false
	for _, e := range events {
		switch e.Kind {
		case "step":
			if strings.Contains(string(e.Data), `"download"`) && strings.Contains(string(e.Data), `"done"`) {
				sawDownloadDone = true
			}
		case "progress":
			sawProgress = true
		}
	}
	if !sawDownloadDone {
		t.Error("no step event reported the download step done")
	}
	if !sawProgress {
		t.Error("no progress event was emitted for the downloads")
	}

	if _, err := os.Stat(exportDir); err != nil {
		t.Fatalf("export directory missing after success: %v", err)
	}

	archivePath := filepath.Join(exportDir, "packages_npm.tar.gz")
	first, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	entries := readArchive(t, first)
	for _, want := range []string{
		"out/widgets-1.1.0.tgz", "out/scope-gadget-2.1.0.tgz", "out/scope-gadget-2.2.0.tgz",
		"out/helper-3.0.0.tgz",
	} {
		if _, ok := entries[want]; !ok {
			t.Errorf("archive missing entry %q; have %v", want, exportArchiveKeys(entries))
		}
	}
	for name := range entries {
		if name != "out/" && !strings.HasSuffix(name, ".tgz") {
			t.Errorf("archive holds %q, want package tarballs and nothing else", name)
		}
	}
	for _, file := range []string{"out/scope-gadget-2.1.0.tgz", "out/scope-gadget-2.2.0.tgz"} {
		gadgetManifest := readGadgetManifest(t, entries[file])
		if _, ok := gadgetManifest["publishConfig"]; ok {
			t.Errorf("%s still has publishConfig", file)
		}
	}

	// Step 2: reproducibility. Running a second, independent export with the
	// same inputs must give the same archive bytes, and every package here
	// has sha512 integrity, so the tarball cache populated by the first
	// export must serve all of them without another HTTP request.
	requestsBeforeSecondRun := h.requests.Load()
	exportDir2 := filepath.Join(t.TempDir(), "exports", "20260917T101503Z.tmp")
	exp2 := h.newExport(t, analysisDir, exportDir2, true)
	keyOfFirst := h.store.SigningKey()
	if _, err := h.store.RegenerateSigningKey(); err != nil {
		t.Fatal(err)
	}
	if err := exp2.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := h.requests.Load(); got != requestsBeforeSecondRun {
		t.Errorf("second export made %d more registry requests, want 0 (cache miss)", got-requestsBeforeSecondRun)
	}
	second, err := os.ReadFile(filepath.Join(exportDir2, "packages_npm.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two exports of the same selection gave different archive bytes after a key regenerate")
	}
	assertSigned(t, exportDir, keyOfFirst)
	assertSigned(t, exportDir2, h.store.SigningKey())

	// Reports.
	var manifest map[string]any
	readJSON(t, filepath.Join(exportDir, "manifest.json"), &manifest)
	if manifest["formatVersion"] != float64(2) {
		t.Errorf("manifest formatVersion = %v, want 2", manifest["formatVersion"])
	}
	if manifest["analysisId"] != "20260910T080000Z" {
		t.Errorf("manifest analysisId = %v", manifest["analysisId"])
	}
	pkgs, _ := manifest["packages"].([]any)
	if len(pkgs) != 4 {
		t.Fatalf("manifest packages = %d, want 4 (widgets, gadget 2.1.0, gadget 2.2.0, helper): %v", len(pkgs), pkgs)
	}
	gadgetVersions := map[string]bool{}
	for _, p := range pkgs {
		entry := p.(map[string]any)
		if entry["name"] == "@scope/gadget" {
			gadgetVersions[entry["version"].(string)] = true
			if entry["publishConfigStripped"] != true {
				t.Errorf("gadget %v manifest entry = %v, want publishConfigStripped true", entry["version"], entry)
			}
		}
	}
	if !gadgetVersions["2.1.0"] || !gadgetVersions["2.2.0"] {
		t.Errorf("manifest gadget versions = %v, want both 2.1.0 and 2.2.0", gadgetVersions)
	}

	for _, name := range []string{"report.trivy.json", "report.cdx.json", "findings.csv", "summary.md"} {
		if _, err := os.Stat(filepath.Join(exportDir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	findings, err := os.ReadFile(filepath.Join(exportDir, "findings.csv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CVE-WIDGET-OLD", "fixed", "introduced",
		// @scope/gadget,2.0.0,2.1.0,... and @scope/gadget,2.0.0,2.2.0,...:
		// one selected version per row, both present for the same
		// dependency, proving a two-version selection gets a CSV row per
		// version rather than collapsing to one.
		"@scope/gadget,2.0.0,2.1.0,", "CVE-GADGET-NEW",
		"@scope/gadget,2.0.0,2.2.0,", "CVE-GADGET-OTHER",
	} {
		if !bytes.Contains(findings, []byte(want)) {
			t.Errorf("findings.csv missing %q:\n%s", want, findings)
		}
	}
	summary, err := os.ReadFile(filepath.Join(exportDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CVE-GADGET-SHARED", "widgets",
		// Both selected versions of @scope/gadget get their own row in the
		// updated-dependencies table, and their own non-blocking signal.
		"| @scope/gadget | 2.0.0 | 2.1.0 |", "install-script-added",
		"| @scope/gadget | 2.0.0 | 2.2.0 |", "publisher-changed",
	} {
		if !bytes.Contains(summary, []byte(want)) {
			t.Errorf("summary.md missing %q:\n%s", want, summary)
		}
	}

	// The committed export holds exactly the seven files a client ever
	// downloads, nothing left over from downloading, stripping or
	// scanning: @scope/gadget's publishConfig guarantees stripped/ would
	// otherwise exist here.
	entriesOnDisk, err := os.ReadDir(exportDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", exportDir, err)
	}
	var names []string
	for _, entry := range entriesOnDisk {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	want := []string{
		"findings.csv", "manifest.json", "manifest.json.sig", "packages_npm.tar.gz",
		"report.cdx.json", "report.trivy.json", "summary.md",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("export directory holds %v, want exactly %v", names, want)
	}
}

// createdAtLine is the one line of manifest.json that changes from run to
// run.
var createdAtLine = regexp.MustCompile(`(?m)^  "createdAt": "[^"]*",$`)

// TestNPMExportBytesMatchTheLastRelease exports a fixed selection and
// compares manifest.json with the one the last release wrote for it, so
// the npm archive and manifest keep their bytes. SEALIFT_UPDATE_GOLDEN=1
// writes the golden file instead.
func TestNPMExportBytesMatchTheLastRelease(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	if err := h.newExport(t, analysisDir, exportDir, true).Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("Run: %v", err)
	}

	manifest, err := os.ReadFile(filepath.Join(exportDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !createdAtLine.Match(manifest) {
		t.Fatalf("manifest.json has no createdAt line:\n%s", manifest)
	}
	manifest = createdAtLine.ReplaceAll(manifest, []byte(`  "createdAt": "2026-09-17T10:15:02Z",`))
	// The review is new and the last release wrote none: every other byte
	// must stay as it was.
	var written report.Manifest
	if err := json.Unmarshal(manifest, &written); err != nil {
		t.Fatal(err)
	}
	if written.Review == nil {
		t.Fatal("manifest.json carries no review")
	}
	written.Review = nil
	if manifest, err = json.MarshalIndent(written, "", "  "); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "npm-export-0.6.2", "manifest.json")
	if os.Getenv("SEALIFT_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, manifest, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, want) {
		t.Errorf("manifest.json differs from %s:\n%s", golden, manifest)
	}

	var doc struct {
		Archive struct {
			SHA256 string `json:"sha256"`
		} `json:"archive"`
	}
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(exportDir, "packages_npm.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != doc.Archive.SHA256 {
		t.Errorf("packages_npm.tar.gz sha256 = %x, want %s from %s", sum, doc.Archive.SHA256, golden)
	}
}

func TestExportRunIntegrityMismatch(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	// Corrupt the recorded integrity of the selected widgets version so it
	// no longer matches the bytes the registry actually serves.
	writeLockfile(t, filepath.Join(analysisDir, "candidates", "widgets@1.1.0", "pnpm-lock.yaml"),
		npm.LockPackage{Name: "widgets", Version: "1.1.0", Integrity: sriOf([]byte("not the real tarball"))})

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)

	err := exp.Run(context.Background(), noopEmit)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("Run: err = %v, want ErrTampered", err)
	}
	assertExportFailedStatus(t, exportDir, "download", "possible tampering")
}

func TestExportRunUnknownSelectionKeepsPendingDirWithStatus(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)
	// Both entries are bad, on purpose: the API needs every offending entry
	// in one 400 response, not just the first.
	exp.Request.Selection["widgets"] = []string{"9.9.9"}
	exp.Request.Selection["@scope/gadget"] = []string{"9.9.9"}

	err := exp.Run(context.Background(), noopEmit)
	if !errors.Is(err, ErrUnknownSelection) {
		t.Fatalf("Run: err = %v, want ErrUnknownSelection", err)
	}
	for _, want := range []string{"widgets@9.9.9", "@scope/gadget@9.9.9"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Run: err = %q, want it to list %q", err, want)
		}
	}
	assertExportFailedStatus(t, exportDir, "package-list", "did not resolve")
}

// The tools account can write an export directory, so a link can wait at
// any name the export writes, aimed at a file the server owns.
func TestExportNeverWritesThroughALink(t *testing.T) {
	for _, tc := range []struct{ name, step string }{
		{filepath.Join("stripped", "scope-gadget-2.1.0.tgz"), "strip"},
		{"packages_npm.tar.gz", "archive"},
		{"export.cdx-input.json", "reports"},
		{"findings.csv", "reports"},
		{"summary.md", "reports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
			h.buildAnalysis(analysisDir)
			exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
			exp := h.newExport(t, analysisDir, exportDir, false)

			victim := filepath.Join(t.TempDir(), "signing-key.pem")
			const held = "a file the server owns"
			if err := os.WriteFile(victim, []byte(held), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(exportDir, tc.name)
			if err := os.MkdirAll(filepath.Dir(link), 0o770); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, link); err != nil {
				t.Fatal(err)
			}

			if err := exp.Run(context.Background(), noopEmit); err == nil {
				t.Error("Run = <nil>, want the planted link refused")
			}
			if got, err := os.ReadFile(victim); err != nil || string(got) != held {
				t.Errorf("the link's target now holds %d bytes (%v), want it untouched", len(got), err)
			}
			assertExportFailedStatus(t, exportDir, tc.step, "file exists")
		})
	}
}

// assertExportFailedStatus proves the fix for finding 2: a failed export
// keeps its directory instead of removing it, with a status.json a reader
// can find the cause in even after the live event stream is gone. wantStep
// and wantMessageSubstr are checked against the first step status.json
// records as failed.
func assertExportFailedStatus(t *testing.T, exportDir, wantStep, wantMessageSubstr string) {
	t.Helper()
	if _, statErr := os.Stat(exportDir); statErr != nil {
		t.Fatalf("pending export directory did not survive a failed export: %v", statErr)
	}
	for _, name := range []string{
		"downloads", "stripped", "export.cdx-input.json", "packages_npm.tar.gz", "manifest.json", "manifest.json.sig",
		"report.trivy.json", "report.cdx.json", "findings.csv", "summary.md",
	} {
		if _, statErr := os.Stat(filepath.Join(exportDir, name)); !os.IsNotExist(statErr) {
			t.Errorf("%s survived a failed export, want it removed", name)
		}
	}
	var status exportStatusFile
	data, err := os.ReadFile(filepath.Join(exportDir, "status.json"))
	if err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("unmarshal status.json: %v", err)
	}
	if status.State != store.Failed {
		t.Errorf("status.json state = %q, want %q", status.State, store.Failed)
	}
	if status.AnalysisID != "20260910T080000Z" {
		t.Errorf("status.json analysisId = %q, want %q", status.AnalysisID, "20260910T080000Z")
	}
	var found *stepRecord
	for i, s := range status.Steps {
		if s.State == string(store.Failed) {
			found = &status.Steps[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("status.json steps = %+v, want one failed step", status.Steps)
	}
	if found.Name != wantStep {
		t.Errorf("failed step = %q, want %q", found.Name, wantStep)
	}
	if !strings.Contains(found.Error, wantMessageSubstr) {
		t.Errorf("failed step error = %q, want it to contain %q", found.Error, wantMessageSubstr)
	}
}

// TestExportRunCancelledDuringDownloadWritesCancelledStatus proves a
// cancelled export is told apart from a failed one in status.json: a
// context already cancelled by the time the download step reads from it
// makes Run return ctx.Err(), and the status Run leaves behind must read
// "cancelled", not "failed".
func TestExportRunCancelledDuringDownloadWritesCancelledStatus(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := exp.Run(ctx, noopEmit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: err = %v, want context.Canceled", err)
	}
	if _, statErr := os.Stat(exportDir); statErr != nil {
		t.Fatalf("pending export directory did not survive a cancelled export: %v", statErr)
	}
	var status exportStatusFile
	data, rerr := os.ReadFile(filepath.Join(exportDir, "status.json"))
	if rerr != nil {
		t.Fatalf("read status.json: %v", rerr)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("unmarshal status.json: %v", err)
	}
	if status.State != store.Cancelled {
		t.Errorf("status.json state = %q, want %q", status.State, store.Cancelled)
	}
}

func TestValidateSelectionListsEveryBadEntry(t *testing.T) {
	h := newTestHarness(t)
	// @scope/gadget selects one known version (2.1.0) and one unknown one
	// (1.2.3): ValidateSelection checks every version of every dependency,
	// not just the first, so only the unknown one is reported.
	bad := ValidateSelection(h.result(), map[string][]string{
		"widgets":       {"9.9.9"},
		"@scope/gadget": {"2.1.0", "1.2.3"},
	})
	want := []string{"@scope/gadget@1.2.3", "widgets@9.9.9"}
	sort.Strings(bad)
	if !slices.Equal(bad, want) {
		t.Errorf("ValidateSelection = %v, want %v", bad, want)
	}

	if got := ValidateSelection(h.result(), map[string][]string{"widgets": {"1.1.0"}}); got != nil {
		t.Errorf("ValidateSelection(known version) = %v, want nil", got)
	}
	if got := ValidateSelection(h.result(), map[string][]string{"widgets": {}}); got != nil {
		t.Errorf("ValidateSelection(empty list) = %v, want nil: an empty list is the same as not selecting the dependency", got)
	}
}

// assertSigned checks that manifest.json.sig verifies over the exact bytes of
// manifest.json with key's public half, and names that key's sha256.
func assertSigned(t *testing.T, dir string, key store.SigningKey) {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(dir, archive.SignatureFile))
	if err != nil {
		t.Fatalf("manifest.json.sig: %v", err)
	}
	if err := archive.CheckSignature(manifest, file, publicKey(t, key)); err != nil {
		t.Errorf("%s does not verify over manifest.json with the key: %v", archive.SignatureFile, err)
	}
	var doc struct {
		PublicKeySha256 string `json:"publicKeySha256"`
	}
	if err := json.Unmarshal(file, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.PublicKeySha256 != key.PublicKeySHA256 {
		t.Errorf("signature names %s, want %s", doc.PublicKeySha256, key.PublicKeySHA256)
	}
}

func publicKey(t *testing.T, key store.SigningKey) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(key.PublicPEM))
	if block == nil {
		t.Fatal("the public PEM does not decode")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub.(ed25519.PublicKey)
}

// TestExportSignsWithTheKeyItStartedWith regenerates the key while the
// downloads run: the export must still sign with the key it began with.
func TestExportSignsWithTheKeyItStartedWith(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)

	before := h.store.SigningKey()
	var once sync.Once
	h.onFetch = func() {
		once.Do(func() {
			if _, err := h.store.RegenerateSigningKey(); err != nil {
				t.Error(err)
			}
		})
	}
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.store.SigningKey().PublicKeySHA256 == before.PublicKeySHA256 {
		t.Fatal("the key was not regenerated during the export, the test proves nothing")
	}
	assertSigned(t, exportDir, before)
}

func TestExportFailsWhenTheManifestCannotBeSigned(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)
	// A directory where the signature belongs makes its write fail.
	if err := os.MkdirAll(filepath.Join(exportDir, archive.SignatureFile, "blocker"), 0o770); err != nil {
		t.Fatal(err)
	}

	var steps []string
	emit := func(e Event) {
		if e.Kind == "step" {
			steps = append(steps, string(e.Data))
		}
	}
	if err := exp.Run(context.Background(), emit); err == nil {
		t.Fatal("Run succeeded with no signature written")
	}
	assertExportFailedStatus(t, exportDir, "reports", "manifest.json.sig")
	entries, err := os.ReadDir(exportDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "status.json" {
		t.Errorf("a failed export keeps %v, want status.json alone", entries)
	}
	if !strings.Contains(strings.Join(steps, "\n"), `"reports"`) {
		t.Errorf("no step event named the reports step: %v", steps)
	}
}

func TestExportFilesNeverHoldThePrivateKey(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, true)
	var events []string
	var mu sync.Mutex
	emit := func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, string(e.Data))
	}
	if err := exp.Run(context.Background(), emit); err != nil {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(h.root, "private", "signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	seed := parsed.(ed25519.PrivateKey).Seed()
	needles := [][]byte{seed, []byte(hex.EncodeToString(seed)), []byte(base64.StdEncoding.EncodeToString(seed)), block.Bytes, []byte("PRIVATE KEY")}

	check := func(where string, content []byte) {
		for _, n := range needles {
			if bytes.Contains(content, n) {
				t.Errorf("%s holds the private key (%d-byte form)", where, len(n))
			}
		}
	}
	files, err := os.ReadDir(exportDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		content, err := os.ReadFile(filepath.Join(exportDir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		check(f.Name(), content)
		if f.Name() == "packages_npm.tar.gz" {
			for name, body := range readArchive(t, content) {
				check("archive entry "+name, []byte(body))
			}
		}
	}
	check("the events", []byte(strings.Join(events, "\n")))
}

// TestExportDownloadSkipsCacheHit proves the cache hit does not merely
// avoid a redundant request: the registry can be gone entirely and a
// second export of the same sha512-addressed package still succeeds,
// because downloadOne never calls it.
func TestExportDownloadSkipsCacheHit(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if got := h.requests.Load(); got == 0 {
		t.Fatal("first export made no registry request; the cache-hit path was not exercised")
	}

	h.registry.Close() // any further download attempt now fails with a connection error

	exportDir2 := filepath.Join(t.TempDir(), "exports", "20260917T101503Z.tmp")
	exp2 := h.newExport(t, analysisDir, exportDir2, false)
	if err := exp2.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("second Run with the registry down: %v", err)
	}
}

// TestExportDownloadReplacesACorruptCacheEntry proves a cache file whose
// bytes no longer match its sha512 name is downloaded again, never shipped.
func TestExportDownloadReplacesACorruptCacheEntry(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	if err := h.newExport(t, analysisDir, filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp"), false).Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	entries, err := filepath.Glob(filepath.Join(h.store.Root(), "cache", "tarballs", "*.tgz"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("cache entries = %v, %v", entries, err)
	}
	for _, entry := range entries {
		if err := os.WriteFile(entry, []byte("not the package"), 0o664); err != nil {
			t.Fatal(err)
		}
	}
	before := h.requests.Load()

	if err := h.newExport(t, analysisDir, filepath.Join(t.TempDir(), "exports", "20260917T101503Z.tmp"), false).Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if h.requests.Load() == before {
		t.Error("second export made no request: the corrupt cache entries were trusted")
	}
	for _, entry := range entries {
		sum, err := fileSHA512(entry)
		if err != nil || sum+".tgz" != filepath.Base(entry) {
			t.Errorf("cache entry %s holds sha512 %s, %v", filepath.Base(entry), sum, err)
		}
	}
}

// TestExportDownloadReportsCacheHits proves the running cache-hit count in
// each progress event reflects downloadOne's own cache-hit accounting: a
// second export of the same selection, once every tarball already sits in
// the cache, reports every package as a hit by the event whose done count
// reaches the total. Concurrent downloaders race the mutex behind emit, so
// that event is not necessarily the last one appended; this looks it up by
// done == total instead of assuming append order.
func TestExportDownloadReportsCacheHits(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	var mu sync.Mutex
	var progress []progressData
	emit := func(e Event) {
		if e.Kind != "progress" {
			return
		}
		var p progressData
		if err := json.Unmarshal(e.Data, &p); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		progress = append(progress, p)
	}

	exportDir2 := filepath.Join(t.TempDir(), "exports", "20260917T101503Z.tmp")
	exp2 := h.newExport(t, analysisDir, exportDir2, false)
	if err := exp2.Run(context.Background(), emit); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	if len(progress) == 0 {
		t.Fatal("no progress events emitted for the second export")
	}
	var final *progressData
	for i := range progress {
		if progress[i].Total > 0 && progress[i].Done == progress[i].Total {
			final = &progress[i]
		}
	}
	if final == nil {
		t.Fatal("no progress event reported every package done")
	}
	if final.CacheHits == nil {
		t.Fatal("final progress event has no cacheHits, want the running count")
	}
	if *final.CacheHits != final.Total {
		t.Fatalf("cacheHits = %d, want every package (%d) to be a hit on the re-export", *final.CacheHits, final.Total)
	}
}

// --- archive reading helpers ---

func readArchive(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzipReader(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(tr); err != nil {
			t.Fatal(err)
		}
		out[h.Name] = buf.String()
	}
	return out
}

func gzipReader(data []byte) (*gzip.Reader, error) {
	return gzip.NewReader(bytes.NewReader(data))
}

func exportArchiveKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func readGadgetManifest(t *testing.T, tarballBody string) map[string]any {
	t.Helper()
	gz, err := gzip.NewReader(strings.NewReader(tarballBody))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatal("package.json not found in gadget tarball")
		}
		if h.Name != "package/package.json" {
			continue
		}
		var manifest map[string]any
		if err := json.NewDecoder(tr).Decode(&manifest); err != nil {
			t.Fatal(err)
		}
		return manifest
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

// The tools account can write the tarball cache and the stripped files, so
// a tarball can change between its download's sha512 check and the reads
// that ship it.
func TestExportFailsWhenATarballChangesAfterItsDownload(t *testing.T) {
	cached := func(h *testHarness, data []byte) string {
		sum := sha512.Sum512(data)
		return filepath.Join(h.root, "cache", "tarballs", hex.EncodeToString(sum[:])+".tgz")
	}
	stripped := func(_ *testHarness, exportDir string) string {
		return filepath.Join(exportDir, "stripped", "scope-gadget-2.1.0.tgz")
	}
	// replaceWithLink puts at path a link to a new file holding data.
	replaceWithLink := func(t *testing.T, path string, data []byte) {
		t.Helper()
		target := filepath.Join(t.TempDir(), "signing-key.pem")
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	replaceWithFIFO := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o660); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, step string
		plant      func(t *testing.T, h *testHarness, exportDir string)
	}{
		{"the cached gadget 2.1.0 holds another tarball", "strip", func(t *testing.T, h *testHarness, _ string) {
			if err := os.WriteFile(cached(h, h.gadget21), h.gadget22, 0o664); err != nil {
				t.Fatal(err)
			}
		}},
		{"the cached gadget 2.1.0 is a link to the same bytes", "strip", func(t *testing.T, h *testHarness, _ string) {
			replaceWithLink(t, cached(h, h.gadget21), h.gadget21)
		}},
		{"the cached gadget 2.1.0 is a FIFO", "strip", func(t *testing.T, h *testHarness, _ string) {
			replaceWithFIFO(t, cached(h, h.gadget21))
		}},
		{"the cached widgets 1.1.0 holds other bytes of its length", "archive", func(t *testing.T, h *testHarness, _ string) {
			if err := os.WriteFile(cached(h, h.widgets), bytes.Repeat([]byte("x"), len(h.widgets)), 0o664); err != nil {
				t.Fatal(err)
			}
		}},
		{"the cached widgets 1.1.0 is a link to a file of its length", "archive", func(t *testing.T, h *testHarness, _ string) {
			replaceWithLink(t, cached(h, h.widgets), bytes.Repeat([]byte("k"), len(h.widgets)))
		}},
		{"the cached widgets 1.1.0 is a FIFO", "archive", func(t *testing.T, h *testHarness, _ string) {
			replaceWithFIFO(t, cached(h, h.widgets))
		}},
		{"the stripped gadget 2.1.0 is a link to a file of its length", "archive", func(t *testing.T, h *testHarness, exportDir string) {
			st, err := os.Stat(stripped(h, exportDir))
			if err != nil {
				t.Fatal(err)
			}
			replaceWithLink(t, stripped(h, exportDir), bytes.Repeat([]byte("k"), int(st.Size())))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
			h.buildAnalysis(analysisDir)
			exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
			exp := h.newExport(t, analysisDir, exportDir, false)
			hook := func() { tc.plant(t, h, exportDir) }
			if tc.step == "strip" {
				exp.beforeStrip = hook
			} else {
				exp.beforeArchive = hook
			}

			// No process writes to a FIFO, so an open that waits for a
			// writer never returns.
			done := make(chan error, 1)
			go func() { done <- exp.Run(context.Background(), noopEmit) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Run = <nil>, want the changed tarball refused")
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the export still runs after 20s")
			}
			assertExportFailedStatus(t, exportDir, tc.step, "changed after its download")
		})
	}
}

// TestReadAnalysisStatusReadsOnlyARegularFile gives the read what the
// tools account can leave at the analysis's status.json. A FIFO would hold
// an open that no cancel interrupts.
func TestReadAnalysisStatusReadsOnlyARegularFile(t *testing.T) {
	const status = `{"createdAt":"2026-11-20T10:00:00Z","trivyVersion":"0.76.2","trivyDbDate":"2026-11-19T00:00:00Z"}`
	for _, c := range []struct {
		name  string
		plant func(path string) error
		want  string // the Trivy version read; empty for a refusal
	}{
		{"a regular file", func(p string) error { return os.WriteFile(p, []byte(status), 0o600) }, "0.76.2"},
		{"a link to a status", func(p string) error {
			target := filepath.Join(filepath.Dir(p), "elsewhere.json")
			if err := os.WriteFile(target, []byte(status), 0o600); err != nil {
				return err
			}
			return os.Symlink(target, p)
		}, ""},
		{"a FIFO", func(p string) error { return syscall.Mkfifo(p, 0o600) }, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "status.json")
			if err := c.plant(path); err != nil {
				t.Fatal(err)
			}
			var got analysisStatus
			returnsPromptly(t, path, func() { got = readAnalysisStatus(dir) })
			if got.TrivyVersion != c.want {
				t.Errorf("Trivy version = %q, want %q", got.TrivyVersion, c.want)
			}
			if c.want == "" && !got.CreatedAt.IsZero() {
				t.Errorf("analysis date = %v, want none read", got.CreatedAt)
			}
		})
	}
}

// replaceWithFIFO puts a FIFO where path was, as the tools account could.
func replaceWithFIFO(t *testing.T, path string) string {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o660); err != nil {
		t.Fatal(err)
	}
	return path
}

// The tools account writes the analysis's lockfiles and reports, the
// export's scan report and the tarball cache. A FIFO it leaves at any of
// them must not hold the export: no cancel interrupts an open, and the
// queue runs one job at a time.
func TestExportReadsNoFIFOTheToolsAccountLeft(t *testing.T) {
	for _, c := range []struct {
		name string
		// plant leaves a FIFO, or has the export's scan leave one, and
		// returns its path.
		plant        func(t *testing.T, h *testHarness, analysisDir string, exp *Export) string
		step, reason string // the failed step and its reason; empty for a done export
	}{
		{"at a candidate's lockfile", func(t *testing.T, _ *testHarness, analysisDir string, _ *Export) string {
			return replaceWithFIFO(t, filepath.Join(analysisDir, "candidates", "widgets@1.1.0", "pnpm-lock.yaml"))
		}, "package-list", "pnpm-lock.yaml is not a regular file"},
		{"at the project's lockfile", func(t *testing.T, _ *testHarness, analysisDir string, _ *Export) string {
			return replaceWithFIFO(t, filepath.Join(analysisDir, "project", "pnpm-lock.yaml"))
		}, "package-list", "pnpm-lock.yaml is not a regular file"},
		{"at a tarball cache entry", func(t *testing.T, h *testHarness, analysisDir string, _ *Export) string {
			if err := h.newExport(t, analysisDir, filepath.Join(t.TempDir(), "exports", "20260917T101501Z.tmp"), true).Run(context.Background(), noopEmit); err != nil {
				t.Fatalf("first Run: %v", err)
			}
			entries, err := filepath.Glob(filepath.Join(h.store.Root(), "cache", "tarballs", "*.tgz"))
			if err != nil || len(entries) == 0 {
				t.Fatalf("cache entries = %v, %v", entries, err)
			}
			return replaceWithFIFO(t, entries[0])
		}, "", ""},
		{"at the analysis's candidate scan", func(t *testing.T, _ *testHarness, analysisDir string, _ *Export) string {
			return replaceWithFIFO(t, filepath.Join(analysisDir, "candidates.trivy.json"))
		}, "reports", "candidates.trivy.json is not a regular file"},
		{"at the analysis's project scan", func(t *testing.T, _ *testHarness, analysisDir string, _ *Export) string {
			path := filepath.Join(analysisDir, "project.trivy.json")
			if err := os.WriteFile(path, []byte(exportScanJSON), 0o664); err != nil {
				t.Fatal(err)
			}
			return replaceWithFIFO(t, path)
		}, "", ""},
		{"at the export scan's report", func(_ *testing.T, _ *testHarness, _ string, exp *Export) string {
			exp.Trivy = fifoTrivy{&exportTrivy{cannedTrivy: &cannedTrivy{}}}
			return filepath.Join(exp.Dir, "report.trivy.json")
		}, "reports", "report.trivy.json is not a regular file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHarness(t)
			analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
			h.buildAnalysis(analysisDir)
			exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
			exp := h.newExport(t, analysisDir, exportDir, true)
			fifo := c.plant(t, h, analysisDir, exp)

			var err error
			returnsPromptly(t, fifo, func() { err = exp.Run(context.Background(), noopEmit) })
			if c.reason == "" {
				if err != nil {
					t.Fatalf("Run: %v, want the export done", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("Run = %v, want an error saying %q", err, c.reason)
			}
			assertExportFailedStatus(t, exportDir, c.step, c.reason)
		})
	}
}

// reviewedExport is the harness' export with a CVE no version fixes on the
// gadget version an install keeps, and the reason it needs.
func reviewedExport(t *testing.T, h *testHarness, analysisDir, exportDir, reason string) *Export {
	t.Helper()
	exp := h.newExport(t, analysisDir, exportDir, false)
	gadget := &exp.Analysis.Result.Dependencies[1]
	gadget.Candidates[1].CVEs = []CVE{{ID: "CVE-GADGET-OTHER", Severity: "MEDIUM", Package: "@scope/gadget@2.2.0"}}
	exp.Request.Reasons = []Reason{{Kind: CVEWithoutFixReason, Dependencies: []string{"@scope/gadget"}, Text: reason}}
	if problems := CheckReasons(exp.Analysis.Result, exp.Request, policy.DefaultReview()); len(problems) > 0 {
		t.Fatalf("the export's reasons should pass: %q", problems)
	}
	return exp
}

func TestExportSignsItsReview(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	if err := os.WriteFile(filepath.Join(analysisDir, "project.trivy.json"), []byte(candidatesTrivyJSON), 0o664); err != nil {
		t.Fatal(err)
	}
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := reviewedExport(t, h, analysisDir, exportDir, "Only our own build calls the gadget.")
	if err := exp.Run(context.Background(), noopEmit); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertSigned(t, exportDir, h.store.SigningKey())

	data, err := os.ReadFile(filepath.Join(exportDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := archive.ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.ReviewProblem != "" || m.Review == nil {
		t.Fatalf("the import keeps the review out: %q", m.ReviewProblem)
	}
	projected := exp.projected()
	if projected == nil {
		t.Fatal("the project scan was not read, the test proves nothing about cves.after")
	}
	want := ReviewOf(exp.Analysis.Result, exp.Request, projected)
	if !reflect.DeepEqual(*m.Review, want) {
		t.Errorf("signed review =\n %+v\nwant\n %+v", *m.Review, want)
	}
	if len(m.Review.Left) != 1 || m.Review.Left[0].Reason != "Only our own build calls the gadget." {
		t.Errorf("review.left = %+v, want the gadget's CVE with its reason", m.Review.Left)
	}
}

func TestSameSelectionSameArchiveWhateverTheReasons(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	var archives [2][]byte
	var reviews [2]*archive.Review
	for i, reason := range []string{"Only our own build calls the gadget.", "The gadget runs in a sandbox, so the CVE cannot reach data."} {
		exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
		if err := reviewedExport(t, h, analysisDir, exportDir, reason).Run(context.Background(), noopEmit); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		data, err := os.ReadFile(filepath.Join(exportDir, "packages_npm.tar.gz"))
		if err != nil {
			t.Fatal(err)
		}
		archives[i] = data
		manifest, err := os.ReadFile(filepath.Join(exportDir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := archive.ParseManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); m.Archive.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("export %d: manifest names sha256 %s, the archive has %x", i, m.Archive.SHA256, sum)
		}
		reviews[i] = m.Review
	}
	if !bytes.Equal(archives[0], archives[1]) {
		t.Error("the archive's bytes changed with the reasons")
	}
	if reviews[0] == nil || reviews[1] == nil || reviews[0].Left[0].Reason == reviews[1].Left[0].Reason {
		t.Error("the two manifests should carry their own reason, the test proves nothing")
	}
}

func TestExportRefusesAManifestTheImportCannotRead(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)
	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	if err := os.MkdirAll(exportDir, 0o775); err != nil {
		t.Fatal(err)
	}
	exp := h.newExport(t, analysisDir, exportDir, false)
	shipped := []shippedPackage{{File: strings.Repeat("a", archive.MaxManifestSize)}}
	err := exp.writeManifest(shipped, report.ArchiveManifest{}, h.store.SigningKey(), nil)
	if err == nil || !strings.Contains(err.Error(), "larger than the 16777216 bytes the import reads") {
		t.Fatalf("writeManifest = %v, want the manifest refused for its size", err)
	}
	if _, err := os.Stat(filepath.Join(exportDir, "manifest.json")); !os.IsNotExist(err) {
		t.Errorf("manifest.json was written: %v", err)
	}
}

func TestExportFailsOnAReviewTheImportWouldKeepOut(t *testing.T) {
	long := strings.Repeat("9", 257)
	for name, set := range map[string]func(*CVE){
		"a cve id over 256 bytes": func(c *CVE) { c.ID = "CVE-" + long },
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness(t)
			analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
			h.buildAnalysis(analysisDir)
			exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
			exp := reviewedExport(t, h, analysisDir, exportDir, "Only our own build calls the gadget.")
			gadget := &exp.Analysis.Result.Dependencies[1]
			gadget.Candidates[1].CVEs = append(gadget.Candidates[1].CVEs, CVE{ID: "CVE-GADGET-FIXED", Severity: "LOW", Package: "@scope/gadget@2.2.0", FixedIn: "2.2.1"})
			set(&gadget.Candidates[1].CVEs[len(gadget.Candidates[1].CVEs)-1])

			err := exp.Run(context.Background(), noopEmit)
			const cause = "the import would keep the review out"
			if err == nil || !strings.Contains(err.Error(), cause) {
				t.Fatalf("Run = %v, want an error saying %q", err, cause)
			}
			if _, err := os.Stat(filepath.Join(exportDir, "manifest.json")); !os.IsNotExist(err) {
				t.Errorf("manifest.json was written: %v", err)
			}
		})
	}
}
