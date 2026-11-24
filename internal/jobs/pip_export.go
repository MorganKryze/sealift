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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/report"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
	"github.com/MorganKryze/sealift/rank"
	"github.com/MorganKryze/sealift/sbom"
)

// ErrPipSelection reports a selection sent for a pip export.
var ErrPipSelection = errors.New("jobs: a pip export carries the analysis's whole set and takes no selection")

// ErrPipNotExportable reports a pip analysis whose result is unreadable,
// lists no package, or lists a package with no wheel.
var ErrPipNotExportable = errors.New("jobs: the pip analysis has no wheel for every package")

// PipAnalysisRef points a pip export at the analysis it exports.
type PipAnalysisRef struct {
	ID     string
	Dir    string // the committed analyses/<id> directory
	Result PipResult
}

// PipExport packs the wheels a pip analysis recorded. It downloads each
// from the URL the analysis recorded, checked against its sha256, and
// never reads an index page: the set is the analysis's.
type PipExport struct {
	Store    *store.Store
	Index    *pip.Client // downloads only
	Trivy    runner.Trivy
	Project  store.Project
	Settings store.Settings
	Analysis PipAnalysisRef
	Dir, ID  string

	beforeArchive func() // a test's hook between the download and archive steps
}

// Kind names the job for the queue.
func (e *PipExport) Kind() string { return "export" }

// StoreID names the job by its store directory id, which the client uses.
func (e *PipExport) StoreID() string { return e.ID }

// Run packs the analysis's wheels: package-list, download, archive and
// reports. A failed or cancelled run keeps only status.json, as Export's
// does; a done run leaves its directory for Service to commit.
func (e *PipExport) Run(ctx context.Context, emit func(Event)) (err error) {
	var steps []stepRecord
	record := func(ev Event) {
		if ev.Kind == "step" {
			var d stepData
			if json.Unmarshal(ev.Data, &d) == nil {
				steps = append(steps, stepRecord{Name: d.Name, State: string(d.State), DurationMs: d.DurationMs, Error: d.Error})
			}
		}
		emit(ev)
	}
	defer func() {
		// A panic fails the run too: runJob recovers it and logs its stack,
		// and the service then commits whatever this directory holds.
		if r := recover(); r != nil {
			e.failed(ctx, steps)
			panic(r)
		}
		if err != nil {
			e.failed(ctx, steps)
		}
	}()

	// One key signs the whole export, whatever a regenerate does meanwhile.
	key := e.Store.SigningKey()

	pkgs, err := e.packageList(record)
	if err != nil {
		return err
	}
	wheels, err := e.downloadAll(ctx, record, pkgs)
	if err != nil {
		return err
	}
	if e.beforeArchive != nil {
		e.beforeArchive()
	}
	arch, err := e.writeArchive(ctx, record, wheels)
	if err != nil {
		return err
	}
	if err := e.writeReports(ctx, record, wheels, arch, key); err != nil {
		return err
	}
	return e.pruneWorkingFiles()
}

// pruneWorkingFiles removes what the export wrote on its way and does not
// keep: the downloads directory and the scan input.
func (e *PipExport) pruneWorkingFiles() error {
	for _, name := range []string{"downloads", "export.cdx-input.json"} {
		if err := os.RemoveAll(filepath.Join(e.Dir, name)); err != nil {
			return fmt.Errorf("jobs: remove %s: %w", name, withoutPath(err))
		}
	}
	return nil
}

// pipWheelFile is one wheel of the set, in the wheel cache.
type pipWheelFile struct {
	PipPackage
	CachePath string
	SHA512    string
}

// pipArchiveDir prefixes every wheel's entry name in the archive.
const pipArchiveDir = "out/"

var wheelSha256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// packageList is the first step: the analysis's set as it recorded it,
// refused when a package has no wheel or when the import would refuse the
// archive. Every name, file and sha256 is checked here, before any path
// joins them.
func (e *PipExport) packageList(emit func(Event)) ([]PipPackage, error) {
	start := time.Now()
	emitStep(emit, "package-list", store.Running, 0)
	pkgs := e.Analysis.Result.Packages
	if err := checkPipSet(pkgs); err != nil {
		emitFailedStep(emit, "package-list", time.Since(start), err)
		return nil, err
	}
	emitStep(emit, "package-list", store.Done, time.Since(start))
	return pkgs, nil
}

// checkPipSet refuses a set the archive cannot carry within the limits
// the import reads it with.
func checkPipSet(pkgs []PipPackage) error {
	if len(pkgs) == 0 {
		return errors.New("jobs: the analysis lists no package, and the import refuses an archive without one")
	}
	limits := archive.DefaultLimits
	// The out/ directory takes one entry.
	if len(pkgs) >= limits.Entries {
		return fmt.Errorf("jobs: the set has %d packages, and an archive holds at most %d entries, its directory included", len(pkgs), limits.Entries)
	}
	seen := make(map[string]bool, len(pkgs))
	var total int64
	for i, p := range pkgs {
		if !pip.ValidName(p.Name) || !pip.IsExactVersion(p.Version) {
			return fmt.Errorf("jobs: package %d of the analysis has no valid name and version", i+1)
		}
		key := pip.Normalize(p.Name)
		if seen[key] {
			return fmt.Errorf("jobs: %s is listed twice", key)
		}
		seen[key] = true
		if p.Wheel == nil {
			return fmt.Errorf("jobs: %s==%s has no wheel", p.Name, p.Version)
		}
		if err := checkPipWheel(p); err != nil {
			return err
		}
		// Each size is at most pip.MaxDownloadBytes, so the sum cannot overflow.
		total += p.Wheel.Size
	}
	if total > limits.Unpacked {
		return fmt.Errorf("jobs: the wheels hold %d bytes, and an archive holds at most %d bytes", total, limits.Unpacked)
	}
	return nil
}

// checkPipWheel ties a package's wheel to its name and version, and checks
// the file name, sha256 and size the analysis recorded. A refusal quotes
// the file only once its name has passed.
func checkPipWheel(p PipPackage) error {
	w := p.Wheel
	parsed, err := pip.ParseWheelName(w.File)
	if err != nil {
		return fmt.Errorf("jobs: %s==%s: %w", p.Name, p.Version, err)
	}
	if bound := archive.DefaultLimits.NameBytes; len(pipArchiveDir)+len(w.File) > bound {
		return fmt.Errorf("jobs: %s==%s: the wheel name is longer than an archive entry name of %d bytes allows", p.Name, p.Version, bound)
	}
	if pip.Normalize(parsed.Name) != pip.Normalize(p.Name) || !pip.SameVersion(parsed.Version, p.Version) {
		return fmt.Errorf("jobs: %s==%s: the wheel %s names another package", p.Name, p.Version, w.File)
	}
	if !wheelSha256.MatchString(w.Sha256) {
		return fmt.Errorf("jobs: %s==%s: the wheel %s has no valid sha256", p.Name, p.Version, w.File)
	}
	if w.Size <= 0 || w.Size > pip.MaxDownloadBytes {
		return fmt.Errorf("jobs: %s==%s: the wheel %s is recorded at %d bytes, outside 1 to %d", p.Name, p.Version, w.File, w.Size, pip.MaxDownloadBytes)
	}
	return nil
}

func (e *PipExport) wheelCache() string { return filepath.Join(e.Store.Root(), "cache", "wheels") }

// downloadAll is the second step: e.Settings.DownloadParallelism downloads
// at a time into downloads/, each moved into the wheel cache under its
// sha256. A cache entry is checked before use. The first error cancels the
// downloads still running and fails the step.
func (e *PipExport) downloadAll(ctx context.Context, emit func(Event), pkgs []PipPackage) ([]pipWheelFile, error) {
	start := time.Now()
	emitStep(emit, "download", store.Running, 0)
	fail := func(err error) ([]pipWheelFile, error) {
		emitFailedStep(emit, "download", time.Since(start), err)
		return nil, err
	}
	for _, dir := range []string{filepath.Join(e.Dir, "downloads"), e.wheelCache()} {
		if err := os.MkdirAll(dir, 0o770); err != nil {
			return fail(fmt.Errorf("jobs: create %s: %w", filepath.Base(dir), err))
		}
	}

	n := e.Settings.DownloadParallelism
	if n <= 0 {
		n = 16
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, n)
	results := make([]pipWheelFile, len(pkgs))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	done, hits := 0, 0
	for i, p := range pkgs {
		sem <- struct{}{}
		if dctx.Err() != nil {
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			w, hit, err := e.downloadOne(dctx, p)
			// Held while emit runs, so the progress events go out in order.
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				return
			}
			results[i] = w
			done++
			if hit {
				hits++
			}
			emit(progressEvent(done, len(pkgs), hits))
		})
	}
	wg.Wait()
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	if firstErr != nil {
		return fail(firstErr)
	}
	emitStep(emit, "download", store.Done, time.Since(start))
	return results, nil
}

// downloadOne puts one wheel in the wheel cache and reports whether it was
// there already.
func (e *PipExport) downloadOne(ctx context.Context, p PipPackage) (pipWheelFile, bool, error) {
	if err := ctx.Err(); err != nil {
		return pipWheelFile{}, false, err
	}
	w := *p.Wheel
	cachePath := filepath.Join(e.wheelCache(), w.Sha256+".whl")
	// The name claims the content: an entry left wrong by an earlier run
	// would otherwise ship. A mismatch drops it and downloads again.
	sum, ok, err := checkCachedWheel(cachePath, w)
	if err != nil {
		return pipWheelFile{}, false, fmt.Errorf("jobs: %s==%s: check the cached %s: %w", p.Name, p.Version, w.File, err)
	}
	if ok {
		return pipWheelFile{PipPackage: p, CachePath: cachePath, SHA512: sum}, true, nil
	}

	tmp := filepath.Join(e.Dir, "downloads", w.File)
	if _, err := e.Index.DownloadFile(ctx, pip.IndexFile{Filename: w.File, URL: w.URL, Sha256: w.Sha256, Size: w.Size}, tmp); err != nil {
		return pipWheelFile{}, false, fmt.Errorf("jobs: %s==%s: %w", p.Name, p.Version, err)
	}
	if err := moveFile(tmp, cachePath); err != nil {
		return pipWheelFile{}, false, fmt.Errorf("jobs: %s==%s: cache %s: %w", p.Name, p.Version, w.File, err)
	}
	// The tools account can rename entries in downloads/, so the move may
	// put a link or a FIFO in the cache in place of the checked download.
	// checkCachedWheel reads the entry again, and the sha512 comes from
	// that read.
	sum, ok, err = checkCachedWheel(cachePath, w)
	if err != nil {
		return pipWheelFile{}, false, fmt.Errorf("jobs: %s==%s: check the cached %s: %w", p.Name, p.Version, w.File, err)
	}
	if !ok {
		return pipWheelFile{}, false, fmt.Errorf("jobs: %s==%s: the cache entry for %s does not hold the downloaded wheel", p.Name, p.Version, w.File)
	}
	return pipWheelFile{PipPackage: p, CachePath: cachePath, SHA512: sum}, false, nil
}

// checkCachedWheel reports whether path holds a regular file of the
// wheel's recorded size and sha256, with its hex sha512. It removes an
// entry that does not, a link or a FIFO included.
func checkCachedWheel(path string, w PipWheel) (string, bool, error) {
	// The tools account can write the cache. O_NOFOLLOW reads no link's
	// target and O_NONBLOCK keeps a FIFO from holding the open; the type
	// check below then refuses both.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", false, nil
	case errors.Is(err, syscall.ELOOP):
		return "", false, removeCacheEntry(path)
	case err != nil:
		return "", false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	if st.Mode().IsRegular() && st.Size() == w.Size {
		h256, h512 := sha256.New(), sha512.New()
		if _, err := io.Copy(io.MultiWriter(h256, h512), f); err != nil {
			return "", false, err
		}
		if hex.EncodeToString(h256.Sum(nil)) == w.Sha256 {
			return hex.EncodeToString(h512.Sum(nil)), true, nil
		}
	}
	return "", false, removeCacheEntry(path)
}

// removeCacheEntry removes the entry at path, a link itself and never its
// target. An entry already gone is no error.
func removeCacheEntry(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeArchive is the third step: packages_pip.tar.gz with every wheel
// under out/. Each wheel is hashed again while it enters the archive, so
// a cache entry changed after its download fails the step.
func (e *PipExport) writeArchive(ctx context.Context, emit func(Event), wheels []pipWheelFile) (report.ArchiveManifest, error) {
	start := time.Now()
	emitStep(emit, "archive", store.Running, 0)
	fail := func(err error) (report.ArchiveManifest, error) {
		emitFailedStep(emit, "archive", time.Since(start), err)
		return report.ArchiveManifest{}, err
	}

	entries := make([]archive.Entry, 0, len(wheels))
	for _, w := range wheels {
		entries = append(entries, archive.Entry{
			Name: w.Wheel.File,
			Size: w.Wheel.Size,
			Open: func() (io.ReadCloser, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return openCachedWheel(w)
			},
		})
	}

	path := filepath.Join(e.Dir, archive.PipArchiveFile)
	f, err := createNew(path)
	if err != nil {
		return fail(fmt.Errorf("jobs: create the archive: %w", withoutPath(err)))
	}
	sum := sha256.New()
	writeErr := archive.WriteTarGz(io.MultiWriter(f, sum), strings.TrimSuffix(pipArchiveDir, "/"), entries)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fail(fmt.Errorf("jobs: write the archive: %w", writeErr))
	}
	st, err := os.Stat(path)
	if err != nil {
		return fail(fmt.Errorf("jobs: stat the archive: %w", withoutPath(err)))
	}
	emitStep(emit, "archive", store.Done, time.Since(start))
	return report.ArchiveManifest{SHA256: hex.EncodeToString(sum.Sum(nil)), Size: st.Size()}, nil
}

// openCachedWheel opens w's cache entry behind a reader that fails once
// the bytes read differ from the download's, in length or in either
// digest.
func openCachedWheel(w pipWheelFile) (io.ReadCloser, error) {
	return openUnchanged(w.CachePath, recorded{name: w.Wheel.File, size: w.Wheel.Size, sha256: w.Wheel.Sha256, sha512: w.SHA512})
}

// writeReports is the last step: manifest.json and its signature,
// report.trivy.json, report.cdx.json, findings.csv and summary.md, in the
// order Export writes them.
func (e *PipExport) writeReports(ctx context.Context, emit func(Event), wheels []pipWheelFile, arch report.ArchiveManifest, key store.SigningKey) error {
	start := time.Now()
	emitStep(emit, "reports", store.Running, 0)
	err := ctx.Err()
	if err == nil {
		err = e.writeManifest(wheels, arch, key)
	}
	var findings []rank.Finding
	if err == nil {
		findings, err = e.scan(ctx, wheels)
	}
	if err == nil {
		err = e.writeFindingsCSV(findings)
	}
	if err == nil {
		err = e.writeSummary(findings, wheels, arch)
	}
	if err != nil {
		emitFailedStep(emit, "reports", time.Since(start), err)
		return err
	}
	emitStep(emit, "reports", store.Done, time.Since(start))
	return nil
}

// scan scans the exported set as pkg:pypi components into
// report.trivy.json, folds each package's spellings there into one,
// converts that report into report.cdx.json, and returns its findings
// with each package name normalized, so the reports describe what ships
// and not what the analysis scanned.
func (e *PipExport) scan(ctx context.Context, wheels []pipWheelFile) ([]rank.Finding, error) {
	var components []sbom.Component
	for _, w := range wheels {
		components = append(components, sbom.PyPIComponents(w.Name, w.Version)...)
	}
	sbomPath := filepath.Join(e.Dir, "export.cdx-input.json")
	f, err := createNew(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("jobs: create the export scan's input: %w", withoutPath(err))
	}
	writeErr := sbom.WriteCycloneDX(f, components)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return nil, fmt.Errorf("jobs: write the export scan's input: %w", writeErr)
	}
	reportPath := filepath.Join(e.Dir, "report.trivy.json")
	if _, err := e.Trivy.ScanSBOM(ctx, sbomPath, reportPath); err != nil {
		return nil, fmt.Errorf("jobs: scan the exported set: %w", err)
	}
	data, err := readRegularFile(reportPath, trivyReportLimit)
	if err == nil {
		data, err = foldSpellings(data)
	}
	if err != nil {
		return nil, fmt.Errorf("jobs: read report.trivy.json: %w", withoutPath(err))
	}
	if err := e.Store.WriteFile(reportPath, data); err != nil {
		return nil, fmt.Errorf("jobs: write report.trivy.json: %w", withoutPath(err))
	}
	if _, err := e.Trivy.ConvertToCycloneDX(ctx, reportPath, filepath.Join(e.Dir, "report.cdx.json")); err != nil {
		return nil, fmt.Errorf("jobs: convert the export scan to CycloneDX: %w", err)
	}
	findings, err := rank.ReadTrivyJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("jobs: read report.trivy.json: %w", err)
	}
	// Trivy may name a package as its metadata or the SBOM spells it, such
	// as Jinja2 or typing.extensions; the set holds normalized names.
	for i := range findings {
		findings[i].Package = pip.Normalize(findings[i].Package)
	}
	return findings, nil
}

// foldSpellings rewrites a Trivy JSON report of an SBOM that
// sbom.PyPIComponents built, so that each package of the set appears once,
// under its normalized name. The SBOM gives a hyphenated name a second,
// dotted spelling for Trivy to match a CVE published under it, but the
// archive holds one wheel: the spelling's package entry goes, and its
// vulnerabilities move to the normalized package, each id once.
func foldSpellings(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	results, err := objects(doc, "Results")
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		if err := foldResult(result); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// foldResult folds the spellings of one result of a Trivy report in place.
func foldResult(result map[string]any) error {
	packages, err := objects(result, "Packages")
	if err != nil {
		return err
	}
	vulns, err := objects(result, "Vulnerabilities")
	if err != nil {
		return err
	}
	keptAt := make(map[string]int, len(packages))
	for i, pkg := range packages {
		key, normalized := packageKey(pkg["Name"], pkg["Version"])
		// The normalized spelling wins, whatever the report's order.
		if _, seen := keptAt[key]; !seen || normalized {
			keptAt[key] = i
		}
	}
	if packages != nil {
		kept := make([]any, 0, len(keptAt))
		for i, pkg := range packages {
			if key, _ := packageKey(pkg["Name"], pkg["Version"]); keptAt[key] == i {
				kept = append(kept, pkg)
			}
		}
		result["Packages"] = kept
	}

	if vulns == nil {
		return nil
	}
	folded := make([]any, 0, len(vulns))
	seen := make(map[string]bool, len(vulns))
	for _, vuln := range vulns {
		key, _ := packageKey(vuln["PkgName"], vuln["InstalledVersion"])
		if i, ok := keptAt[key]; ok {
			for _, f := range [][2]string{{"PkgName", "Name"}, {"PkgID", "ID"}, {"PkgIdentifier", "Identifier"}} {
				if value, ok := packages[i][f[1]]; ok {
					vuln[f[0]] = value
				}
			}
		}
		id, _ := vuln["VulnerabilityID"].(string)
		if seen[key+" "+id] {
			continue
		}
		seen[key+" "+id] = true
		folded = append(folded, vuln)
	}
	result["Vulnerabilities"] = folded
	return nil
}

// objects returns the elements of the list at doc[field], none when the
// field is absent or null. Trivy writes this report as the tools account,
// so a field that is not a list, or holds anything but objects, is refused
// before the fold writes into it.
func objects(doc map[string]any, field string) ([]map[string]any, error) {
	value := doc[field]
	if value == nil {
		return nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a list", field)
	}
	out := make([]map[string]any, len(list))
	for i, element := range list {
		obj, ok := element.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s holds a value that is not an object", field)
		}
		out[i] = obj
	}
	return out, nil
}

// packageKey names a package of a Trivy report by its normalized name and
// its version, and says whether the report spells the name normalized.
func packageKey(name, version any) (key string, normalized bool) {
	n, _ := name.(string)
	v, _ := version.(string)
	return pip.Normalize(n) + "@" + v, n == pip.Normalize(n)
}

// findingsByPackage gives each scanned package's distinct vulnerabilities,
// sorted by package, then version, then id. Two spellings of one project
// fold into one key, where each vulnerability counts once.
func findingsByPackage(findings []rank.Finding) [][]rank.Finding {
	ix := rank.NewIndex(findings)
	keys := slices.Sorted(maps.Keys(ix))
	out := make([][]rank.Finding, 0, len(keys))
	for _, key := range keys {
		set := ix.Set([]string{key})
		out = append(out, slices.SortedFunc(maps.Values(set), func(a, b rank.Finding) int {
			return strings.Compare(a.ID, b.ID)
		}))
	}
	return out
}

// writeFindingsCSV writes findings.csv, one row per vulnerability and
// package of the export scan. A package of the set names the files that
// pin it; a finding on a package outside the set keeps its row with none.
func (e *PipExport) writeFindingsCSV(findings []rank.Finding) error {
	pinned := make(map[string][]string, len(e.Analysis.Result.Packages))
	for _, p := range e.Analysis.Result.Packages {
		pinned[pip.Normalize(p.Name)+"@"+p.Version] = p.Files
	}
	var rows []report.PipFindingsRow
	for _, pkg := range findingsByPackage(findings) {
		for _, f := range pkg {
			rows = append(rows, report.PipFindingsRow{
				Package: f.Package, Version: f.Version, PinnedIn: pinned[f.Package+"@"+f.Version],
				VulnerabilityID: f.ID, Severity: f.Severity, FixedVersion: f.FixedVersion, Title: f.Title,
			})
		}
	}
	out, err := createNew(filepath.Join(e.Dir, "findings.csv"))
	if err != nil {
		return fmt.Errorf("jobs: create findings.csv: %w", withoutPath(err))
	}
	writeErr := report.WritePipFindingsCSV(out, rows)
	if closeErr := out.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fmt.Errorf("jobs: write findings.csv: %w", withoutPath(writeErr))
	}
	return nil
}

// writeSummary writes summary.md. Its counts and its critical and high
// CVEs come from the export scan, the rest from the analysis.
func (e *PipExport) writeSummary(findings []rank.Finding, wheels []pipWheelFile, arch report.ArchiveManifest) error {
	status := readAnalysisStatus(e.Analysis.Dir)
	var critical, high []rank.Finding
	for _, pkg := range findingsByPackage(findings) {
		for _, f := range pkg {
			switch f.Severity {
			case rank.Critical:
				critical = append(critical, f)
			case rank.High:
				high = append(high, f)
			}
		}
	}
	s := report.PipSummary{
		AnalysisDate: status.CreatedAt, TrivyDBDate: status.TrivyDBDate,
		TrivyVersion: status.TrivyVersion, ToolVersion: ToolVersion,
		Target:            e.Analysis.Result.Target,
		Files:             e.Analysis.Result.Files,
		InArchive:         rank.VectorOf(rank.Index{"export": findings}.Set([]string{"export"})),
		RemainingCritical: critical, RemainingHigh: high,
		Warnings:    e.Analysis.Result.Warnings,
		ArchiveSize: arch.Size, ArchiveSHA256: arch.SHA256, PackageCount: len(wheels),
	}
	out, err := createNew(filepath.Join(e.Dir, "summary.md"))
	if err != nil {
		return fmt.Errorf("jobs: create summary.md: %w", withoutPath(err))
	}
	writeErr := report.WritePipSummary(out, s)
	if closeErr := out.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fmt.Errorf("jobs: write summary.md: %w", withoutPath(writeErr))
	}
	return nil
}

// writeManifest writes manifest.json, with the analysis's target and set,
// and its signature with key.
func (e *PipExport) writeManifest(wheels []pipWheelFile, arch report.ArchiveManifest, key store.SigningKey) error {
	entries := make([]report.WheelEntry, len(wheels))
	for i, w := range wheels {
		entries[i] = report.WheelEntry{
			Name: pip.Normalize(w.Name), Version: w.Version, File: w.Wheel.File,
			SHA256: w.Wheel.Sha256, ShippedSHA512: w.SHA512,
		}
	}
	m := report.PipManifest{
		FormatVersion: report.PipManifestFormatVersion,
		Ecosystem:     store.Pip,
		ToolVersion:   ToolVersion,
		AnalysisID:    e.Analysis.ID,
		CreatedAt:     time.Now().UTC(),
		Target:        e.Analysis.Result.Target,
		Archive:       arch,
		Packages:      entries,
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("jobs: encode manifest.json: %w", err)
	}
	if len(data) > archive.MaxManifestSize {
		return fmt.Errorf("jobs: manifest.json would be %d bytes, larger than the %d bytes the import reads", len(data), archive.MaxManifestSize)
	}
	sig, err := key.SignManifest(data)
	if err != nil {
		return fmt.Errorf("jobs: sign manifest.json: %w", err)
	}
	if err := e.Store.WriteFile(filepath.Join(e.Dir, "manifest.json"), data); err != nil {
		return fmt.Errorf("jobs: write manifest.json: %w", withoutPath(err))
	}
	if err := e.Store.WriteFile(filepath.Join(e.Dir, archive.SignatureFile), sig); err != nil {
		return fmt.Errorf("jobs: write %s: %w", archive.SignatureFile, withoutPath(err))
	}
	return nil
}

// failed removes every file a failed or cancelled run wrote and records
// the outcome in status.json, so the export keeps only that file. It never
// returns an error, as Export.failed does not.
func (e *PipExport) failed(ctx context.Context, steps []stepRecord) {
	for _, name := range []string{
		"downloads", archive.PipArchiveFile, "manifest.json", archive.SignatureFile,
		"report.trivy.json", "report.cdx.json", "findings.csv", "summary.md", "export.cdx-input.json",
	} {
		if err := os.RemoveAll(filepath.Join(e.Dir, name)); err != nil {
			// The error's path can name a wheel, which the log never does.
			slog.Warn("jobs: pip export cleanup after failure", "path", name, "error", withoutPath(err))
		}
	}
	state := store.Failed
	if ctx.Err() != nil {
		state = store.Cancelled
	}
	status := exportStatusFile{State: state, AnalysisID: e.Analysis.ID, Steps: steps}
	if err := e.Store.WriteJSON(filepath.Join(e.Dir, "status.json"), status); err != nil {
		slog.Warn("jobs: write pip export status.json after failure", "error", withoutPath(err))
	}
}

// withoutPath keeps the cause of a file system error and drops its path.
func withoutPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
