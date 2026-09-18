package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	requests atomic.Int32 // every tarball request the registry served, across the harness's lifetime
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
		Settings: store.Settings{SignatureKey: "top-secret", DownloadParallelism: 4},
		Analysis: AnalysisRef{ID: "20260910T080000Z", Dir: analysisDir, Result: h.result()},
		// @scope/gadget selects two versions at once, so a version that
		// breaks the build is not the only one already sitting in Nexus.
		Request: ExportRequest{Selection: map[string][]string{"widgets": {"1.1.0"}, "@scope/gadget": {"2.1.0", "2.2.0"}}, IncludeProject: includeProject},
		Dir:     exportDir,
		ID:      "20260917T101502Z",
	}
}

func noopEmit(Event) {}

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
		"out/helper-3.0.0.tgz", "out/signature.key",
	} {
		if _, ok := entries[want]; !ok {
			t.Errorf("archive missing entry %q; have %v", want, exportArchiveKeys(entries))
		}
	}
	if got := entries["out/signature.key"]; got != "top-secret" {
		t.Errorf("signature.key = %q, want %q with no trailing newline", got, "top-secret")
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
		t.Error("two exports of the same selection gave different archive bytes")
	}

	// Reports.
	var manifest map[string]any
	readJSON(t, filepath.Join(exportDir, "manifest.json"), &manifest)
	if manifest["formatVersion"] != float64(1) {
		t.Errorf("manifest formatVersion = %v, want 1", manifest["formatVersion"])
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
	if _, statErr := os.Stat(exportDir); !os.IsNotExist(statErr) {
		t.Error("pending export directory survived a failed export")
	}
}

func TestExportRunUnknownSelectionRemovesPendingDir(t *testing.T) {
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
	if _, statErr := os.Stat(exportDir); !os.IsNotExist(statErr) {
		t.Error("pending export directory survived a failed export")
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

func TestExportRunRefusesEmptySignatureKey(t *testing.T) {
	h := newTestHarness(t)
	analysisDir := filepath.Join(t.TempDir(), "analyses", "20260910T080000Z")
	h.buildAnalysis(analysisDir)

	exportDir := filepath.Join(t.TempDir(), "exports", "20260917T101502Z.tmp")
	exp := h.newExport(t, analysisDir, exportDir, false)
	exp.Settings.SignatureKey = ""

	if err := exp.Run(context.Background(), noopEmit); !errors.Is(err, ErrSignatureKeyMissing) {
		t.Fatalf("Run: err = %v, want ErrSignatureKeyMissing", err)
	}
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
