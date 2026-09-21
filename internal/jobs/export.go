package jobs

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/report"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
	"github.com/MorganKryze/sealift/sbom"
)

// ToolVersion is sealift's own version, reported in manifest.json and
// summary.md. cmd/sealift overwrites it at build time with -ldflags.
var ToolVersion = "dev"

// ErrSignatureKeyMissing reports an export queued while settings.json still
// holds an empty signatureKey.
var ErrSignatureKeyMissing = errors.New("jobs: signatureKey is empty, set it in settings before exporting")

// ErrUnknownSelection reports a selection entry naming a version the
// analysis never resolved: neither a dependency's current version nor one
// of its candidates.
var ErrUnknownSelection = errors.New("jobs: selection names a version the analysis did not resolve")

// ErrTampered reports a downloaded tarball whose bytes do not match the
// integrity recorded in the analysis lockfile: the mirror or the network
// path between it and sealift may have altered the file.
var ErrTampered = errors.New("jobs: downloaded tarball does not match its recorded integrity, possible tampering")

// AnalysisRef points an export at the analysis it exports from.
type AnalysisRef struct {
	ID     string
	Dir    string // the committed analyses/<id> directory
	Result Result
}

// Export builds the package list from an analysis' selection, downloads
// and re-packs each tarball, writes the reproducible archive, and writes
// the reports beside it.
type Export struct {
	Store    *store.Store
	Registry *npm.Client
	Trivy    runner.Trivy
	Project  store.Project
	Settings store.Settings
	Analysis AnalysisRef
	Request  ExportRequest
	Dir      string
	ID       string
}

// ExportRequest is the input to an export: the versions selected per
// dependency and whether to include the current project tree. A dependency
// can select any subset of its current version and its candidates, not
// just one: other versions ship too, so one already sits in Nexus if the
// recommended one breaks the build on the air-gapped side.
// An empty or absent list for a dependency is the same as not selecting it.
type ExportRequest struct {
	Selection      map[string][]string `json:"selection"`      // dependency name to selected versions
	IncludeProject bool                `json:"includeProject"` // add the current project tree
}

// Kind identifies this job to the queue and in its events.
func (e *Export) Kind() string { return "export" }

// StoreID names the job by its store directory id, which the client uses.
func (e *Export) StoreID() string { return e.ID }

// Run executes the export's steps, emitting a "step" event around each one
// and "progress" events during the download step. Any failure, including
// cancellation, removes e.Dir before Run returns: only a complete export
// stays on disk. A successful Run leaves e.Dir ready for the caller to
// commit (rename it into place), since Export does not know the final
// path store.Pending renames to.
func (e *Export) Run(ctx context.Context, emit func(Event)) (err error) {
	defer func() {
		if err != nil {
			_ = os.RemoveAll(e.Dir)
		}
	}()

	if e.Settings.SignatureKey == "" {
		return ErrSignatureKeyMissing
	}

	pkgs, err := e.packageList(emit)
	if err != nil {
		return err
	}
	downloaded, err := e.downloadAll(ctx, emit, pkgs)
	if err != nil {
		return err
	}
	shipped, err := e.stripAll(ctx, emit, downloaded)
	if err != nil {
		return err
	}
	arch, err := e.writeArchive(ctx, emit, shipped)
	if err != nil {
		return err
	}
	if err := e.writeReports(ctx, emit, shipped, arch); err != nil {
		return err
	}
	if err := e.pruneWorkingFiles(); err != nil {
		return err
	}
	return nil
}

// pruneWorkingFiles removes everything writeArchive and writeReports only
// needed as an intermediate: downloads/ is empty by now (downloadOne moves
// every tarball into the shared cache as it goes), stripped/ holds a
// second copy of every rewritten tarball that writeArchive already read
// into the committed archive, and export.cdx-input.json is Trivy's scan
// input, not one of the export's own files. Left behind, the two
// directories double the export's size on disk, and the stray JSON leaks
// into ExportInfo.Files through the API.
func (e *Export) pruneWorkingFiles() error {
	for _, name := range []string{"downloads", "stripped", "export.cdx-input.json"} {
		if err := os.RemoveAll(filepath.Join(e.Dir, name)); err != nil {
			return fmt.Errorf("jobs: remove %s: %w", name, err)
		}
	}
	return nil
}

// packageList is step 1: the union of the lockfiles of every selected
// version of every dependency, plus the project lockfile when the flag is
// on, platform filtered and deduped by name and version.
func (e *Export) packageList(emit func(Event)) ([]npm.LockPackage, error) {
	start := time.Now()
	emitStep(emit, "package-list", store.Running, 0)

	if bad := ValidateSelection(e.Analysis.Result, e.Request.Selection); len(bad) > 0 {
		err := fmt.Errorf("%w: %s", ErrUnknownSelection, strings.Join(bad, ", "))
		emitFailedStep(emit, "package-list", time.Since(start), err)
		return nil, err
	}

	platform := npm.Platform{OS: e.Project.Target.OS, CPU: e.Project.Target.CPU, Libc: e.Project.Target.Libc}
	byKey := map[string]npm.LockPackage{}

	add := func(pkgs []npm.LockPackage) {
		for _, p := range platform.Filter(pkgs) {
			if _, ok := byKey[p.Key()]; !ok {
				byKey[p.Key()] = p
			}
		}
	}

	for _, name := range sortedKeys(e.Request.Selection) {
		for _, version := range e.Request.Selection[name] {
			lock, err := e.readLockfile(e.candidateLockfilePath(name, version))
			if err != nil {
				emitFailedStep(emit, "package-list", time.Since(start), err)
				return nil, err
			}
			add(lock)
		}
	}
	if e.Request.IncludeProject {
		lock, err := e.readLockfile(filepath.Join(e.Analysis.Dir, "project", "pnpm-lock.yaml"))
		if err != nil {
			emitFailedStep(emit, "package-list", time.Since(start), err)
			return nil, err
		}
		add(lock)
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pkgs := make([]npm.LockPackage, len(keys))
	for i, k := range keys {
		pkgs[i] = byKey[k]
	}
	emitStep(emit, "package-list", store.Done, time.Since(start))
	return pkgs, nil
}

// validSelections returns the "name@version" pairs an export may select
// from: each dependency's current version, plus every candidate the
// analysis ranked. The current version is resolved and scanned the same
// way a candidate is, so its lockfile lives at the same path.
func validSelections(r Result) map[string]bool {
	valid := map[string]bool{}
	for _, d := range r.Dependencies {
		valid[d.Name+"@"+d.Current] = true
		for _, c := range d.Candidates {
			valid[d.Name+"@"+c.Version] = true
		}
	}
	return valid
}

// ValidateSelection returns every "name@version" pair of sel that names a
// version the analysis did not resolve: neither a dependency's current
// version nor one of its candidates. It checks every version of every
// dependency and reports every offending pair, not just the first, so a
// caller (the API handler that queues an export, or packageList itself)
// can answer with all of them at once instead of making the client retry
// one field at a time.
func ValidateSelection(result Result, sel map[string][]string) []string {
	valid := validSelections(result)
	var bad []string
	for _, name := range sortedKeys(sel) {
		for _, version := range sel[name] {
			if !valid[name+"@"+version] {
				bad = append(bad, name+"@"+version)
			}
		}
	}
	return bad
}

func (e *Export) candidateLockfilePath(name, version string) string {
	return filepath.Join(e.Analysis.Dir, "candidates", name+"@"+version, "pnpm-lock.yaml")
}

func (e *Export) readLockfile(path string) ([]npm.LockPackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("jobs: read %s: %w", path, err)
	}
	defer f.Close()
	pkgs, err := npm.ParseLockfile(f)
	if err != nil {
		return nil, fmt.Errorf("jobs: %s: %w", path, err)
	}
	return pkgs, nil
}

// downloadedPackage is a tarball step 2 fetched into the tarball cache.
type downloadedPackage struct {
	npm.LockPackage
	CachePath string
	SHA512    string
}

// downloadAll is step 2: e.Settings.DownloadParallelism downloads at a
// time, https://registry.npmjs.org/<name>/-/<basename>-<version>.tgz,
// checked against the lockfile integrity and stored in the tarball cache
// keyed by sha512. npm.Client.DownloadFile already retries three times
// with backoff on network errors and never retries an integrity mismatch;
// that mismatch fails the export at once, with a possible-tampering
// message, and cancels the other downloads still in flight.
func (e *Export) downloadAll(ctx context.Context, emit func(Event), pkgs []npm.LockPackage) ([]downloadedPackage, error) {
	start := time.Now()
	emitStep(emit, "download", store.Running, 0)

	if err := os.MkdirAll(filepath.Join(e.Dir, "downloads"), 0o770); err != nil {
		werr := fmt.Errorf("jobs: create downloads dir: %w", err)
		emitFailedStep(emit, "download", time.Since(start), werr)
		return nil, werr
	}
	if err := os.MkdirAll(filepath.Join(e.Store.Root(), "cache", "tarballs"), 0o770); err != nil {
		werr := fmt.Errorf("jobs: create tarball cache: %w", err)
		emitFailedStep(emit, "download", time.Since(start), werr)
		return nil, werr
	}

	n := e.Settings.DownloadParallelism
	if n <= 0 {
		n = 16
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, n)
	results := make([]downloadedPackage, len(pkgs))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var done int32
	var cacheHits int32

	for i, p := range pkgs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p npm.LockPackage) {
			defer wg.Done()
			defer func() { <-sem }()
			d, hit, err := e.downloadOne(dctx, p)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				cancel()
				return
			}
			results[i] = d
			if hit {
				atomic.AddInt32(&cacheHits, 1)
			}
			emit(progressEvent(int(atomic.AddInt32(&done, 1)), len(pkgs), int(atomic.LoadInt32(&cacheHits))))
		}(i, p)
	}
	wg.Wait()

	if firstErr != nil {
		emitFailedStep(emit, "download", time.Since(start), firstErr)
		return nil, firstErr
	}
	emitStep(emit, "download", store.Done, time.Since(start))
	return results, nil
}

// downloadOne fetches one package into the tarball cache, reporting
// whether it was already there: hit is true only for the sha512 shortcut
// below, never for a package that still made a network request even if
// its bytes happened to already exist under another name.
func (e *Export) downloadOne(ctx context.Context, p npm.LockPackage) (pkg downloadedPackage, hit bool, err error) {
	if key, ok := sha512CacheKey(p.Integrity); ok {
		cachePath := filepath.Join(e.Store.Root(), "cache", "tarballs", key+".tgz")
		if st, err := os.Stat(cachePath); err == nil && st.Mode().IsRegular() {
			return downloadedPackage{LockPackage: p, CachePath: cachePath, SHA512: key}, true, nil
		}
	}

	tmpPath := filepath.Join(e.Dir, "downloads", npm.PackFileName(p.Name, p.Version))
	sha512Hex, err := e.Registry.DownloadFile(ctx, p.Name, p.Version, p.Integrity, tmpPath)
	if err != nil {
		if errors.Is(err, npm.ErrIntegrity) {
			return downloadedPackage{}, false, fmt.Errorf("%w: %s@%s: %w", ErrTampered, p.Name, p.Version, err)
		}
		return downloadedPackage{}, false, fmt.Errorf("jobs: download %s@%s: %w", p.Name, p.Version, err)
	}
	cachePath := filepath.Join(e.Store.Root(), "cache", "tarballs", sha512Hex+".tgz")
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return downloadedPackage{}, false, fmt.Errorf("jobs: cache %s@%s: %w", p.Name, p.Version, err)
	}
	return downloadedPackage{LockPackage: p, CachePath: cachePath, SHA512: sha512Hex}, false, nil
}

// sha512CacheKey returns the tarball cache's hex key when integrity is
// itself a sha512 SRI hash: that value already is the sha512 digest,
// base64 encoded, so decoding it costs nothing and lets downloadOne check
// the cache before making any network request. A sha1-only integrity
// (legacy packages) has no such shortcut: the sha512 digest is known only
// after downloading and hashing the bytes, so those packages always
// download, cache hit or not. That is an inherent limit of a cache keyed
// by a hash the lockfile does not always carry, not a bug to work around.
func sha512CacheKey(integrity string) (string, bool) {
	fields := strings.Fields(integrity)
	if len(fields) == 0 {
		return "", false
	}
	algo, encoded, ok := strings.Cut(fields[0], "-")
	if !ok || algo != "sha512" {
		return "", false
	}
	sum, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(sum), true
}

// shippedPackage is one tarball as it goes into the archive: the original
// package plus the file it ships from and whether that file lost its
// publishConfig.
type shippedPackage struct {
	npm.LockPackage
	File           string
	Path           string
	Size           int64
	SHA512         string // of the shipped bytes, equal to the original hash when not stripped
	OriginalSHA512 string
	Stripped       bool
}

// stripAll is step 3: package.json entries holding publishConfig get it
// removed and the tarball rewritten; every other tarball ships unchanged.
// It threads ctx through to stripOne, so a cancel between the end of the
// downloads and the end of the archive stops the export instead of
// stripping every remaining tarball first.
func (e *Export) stripAll(ctx context.Context, emit func(Event), downloaded []downloadedPackage) ([]shippedPackage, error) {
	start := time.Now()
	emitStep(emit, "strip", store.Running, 0)

	strippedDir := filepath.Join(e.Dir, "stripped")
	shipped := make([]shippedPackage, len(downloaded))
	for i, d := range downloaded {
		s, err := e.stripOne(ctx, strippedDir, d)
		if err != nil {
			emitFailedStep(emit, "strip", time.Since(start), err)
			return nil, err
		}
		shipped[i] = s
	}
	emitStep(emit, "strip", store.Done, time.Since(start))
	return shipped, nil
}

func (e *Export) stripOne(ctx context.Context, strippedDir string, d downloadedPackage) (shippedPackage, error) {
	if err := ctx.Err(); err != nil {
		return shippedPackage{}, err
	}

	f, err := os.Open(d.CachePath)
	if err != nil {
		return shippedPackage{}, fmt.Errorf("jobs: open %s: %w", d.CachePath, err)
	}
	defer f.Close()

	info, err := npm.InspectTarball(f)
	if err != nil {
		return shippedPackage{}, fmt.Errorf("jobs: inspect %s@%s: %w", d.Name, d.Version, err)
	}
	file := npm.PackFileName(d.Name, d.Version)
	if !info.HasPublishConfig {
		st, err := os.Stat(d.CachePath)
		if err != nil {
			return shippedPackage{}, fmt.Errorf("jobs: stat %s: %w", d.CachePath, err)
		}
		return shippedPackage{
			LockPackage: d.LockPackage, File: file, Path: d.CachePath, Size: st.Size(),
			SHA512: d.SHA512, OriginalSHA512: d.SHA512,
		}, nil
	}

	if err := os.MkdirAll(strippedDir, 0o770); err != nil {
		return shippedPackage{}, fmt.Errorf("jobs: create %s: %w", strippedDir, err)
	}
	outPath := filepath.Join(strippedDir, file)
	out, err := os.Create(outPath)
	if err != nil {
		return shippedPackage{}, fmt.Errorf("jobs: create %s: %w", outPath, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		out.Close()
		return shippedPackage{}, fmt.Errorf("jobs: rewind %s: %w", d.CachePath, err)
	}
	sum := sha512.New()
	stripErr := npm.StripPublishConfig(io.MultiWriter(out, sum), f)
	if closeErr := out.Close(); stripErr == nil {
		stripErr = closeErr
	}
	if stripErr != nil {
		return shippedPackage{}, fmt.Errorf("jobs: strip publishConfig from %s@%s: %w", d.Name, d.Version, stripErr)
	}
	st, err := os.Stat(outPath)
	if err != nil {
		return shippedPackage{}, fmt.Errorf("jobs: stat %s: %w", outPath, err)
	}
	return shippedPackage{
		LockPackage: d.LockPackage, File: file, Path: outPath, Size: st.Size(),
		SHA512: hex.EncodeToString(sum.Sum(nil)), OriginalSHA512: d.SHA512, Stripped: true,
	}, nil
}

// writeArchive builds packages_npm.tar.gz, with out/signature.key holding
// the configured key and no trailing newline. The same selection always
// gives the same archive bytes.
// archive.WriteTarGz calls each Entry's Open exactly once, in order, so
// checking ctx there is how this checks it between entries: WriteTarGz
// itself takes no context.
func (e *Export) writeArchive(ctx context.Context, emit func(Event), shipped []shippedPackage) (report.ArchiveManifest, error) {
	start := time.Now()
	emitStep(emit, "archive", store.Running, 0)

	entries := make([]archive.Entry, 0, len(shipped)+1)
	for _, s := range shipped {
		path := s.Path
		entries = append(entries, archive.Entry{
			Name: s.File,
			Size: s.Size,
			Open: func() (io.ReadCloser, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return os.Open(path)
			},
		})
	}
	key := e.Settings.SignatureKey
	entries = append(entries, archive.Entry{
		Name: "signature.key",
		Size: int64(len(key)),
		Open: func() (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return io.NopCloser(strings.NewReader(key)), nil
		},
	})

	path := filepath.Join(e.Dir, "packages_npm.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		werr := fmt.Errorf("jobs: create archive: %w", err)
		emitFailedStep(emit, "archive", time.Since(start), werr)
		return report.ArchiveManifest{}, werr
	}
	sum := sha256.New()
	writeErr := archive.WriteTarGz(io.MultiWriter(f, sum), "out", entries)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		werr := fmt.Errorf("jobs: write archive: %w", writeErr)
		emitFailedStep(emit, "archive", time.Since(start), werr)
		return report.ArchiveManifest{}, werr
	}
	st, err := os.Stat(path)
	if err != nil {
		werr := fmt.Errorf("jobs: stat archive: %w", err)
		emitFailedStep(emit, "archive", time.Since(start), werr)
		return report.ArchiveManifest{}, werr
	}
	emitStep(emit, "archive", store.Done, time.Since(start))
	return report.ArchiveManifest{SHA256: hex.EncodeToString(sum.Sum(nil)), Size: st.Size()}, nil
}

// writeReports is step 5: manifest.json, report.trivy.json, report.cdx.json,
// findings.csv and summary.md, all written next to the archive.
func (e *Export) writeReports(ctx context.Context, emit func(Event), shipped []shippedPackage, arch report.ArchiveManifest) error {
	start := time.Now()
	emitStep(emit, "reports", store.Running, 0)

	if err := e.writeManifest(shipped, arch); err != nil {
		emitFailedStep(emit, "reports", time.Since(start), err)
		return err
	}
	if err := e.writeTrivyReports(ctx, shipped); err != nil {
		emitFailedStep(emit, "reports", time.Since(start), err)
		return err
	}
	if err := e.writeFindingsCSV(); err != nil {
		emitFailedStep(emit, "reports", time.Since(start), err)
		return err
	}
	if err := e.writeSummary(shipped, arch); err != nil {
		emitFailedStep(emit, "reports", time.Since(start), err)
		return err
	}
	emitStep(emit, "reports", store.Done, time.Since(start))
	return nil
}

func (e *Export) writeManifest(shipped []shippedPackage, arch report.ArchiveManifest) error {
	entries := make([]report.PackageEntry, len(shipped))
	for i, s := range shipped {
		entries[i] = report.PackageEntry{
			Name: s.Name, Version: s.Version, File: s.File,
			OriginalIntegrity: s.Integrity, ShippedSHA512: s.SHA512, PublishConfigStripped: s.Stripped,
		}
	}
	m := report.Manifest{
		FormatVersion: report.ManifestFormatVersion,
		ToolVersion:   ToolVersion,
		AnalysisID:    e.Analysis.ID,
		CreatedAt:     time.Now().UTC(),
		Target:        e.Project.Target,
		Archive:       arch,
		Packages:      entries,
	}
	return e.Store.WriteJSON(filepath.Join(e.Dir, "manifest.json"), m)
}

// writeTrivyReports scans the exported set as its own CycloneDX document,
// so report.trivy.json and report.cdx.json describe exactly what ships,
// independently of the analysis' own candidate scans.
func (e *Export) writeTrivyReports(ctx context.Context, shipped []shippedPackage) error {
	components := make([]sbom.Component, len(shipped))
	for i, s := range shipped {
		components[i] = sbom.Component{Name: s.Name, Version: s.Version}
	}
	sbomPath := filepath.Join(e.Dir, "export.cdx-input.json")
	f, err := os.Create(sbomPath)
	if err != nil {
		return fmt.Errorf("jobs: create %s: %w", sbomPath, err)
	}
	writeErr := sbom.WriteCycloneDX(f, components)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fmt.Errorf("jobs: write exported sbom: %w", writeErr)
	}

	reportPath := filepath.Join(e.Dir, "report.trivy.json")
	if _, err := e.Trivy.ScanSBOM(ctx, sbomPath, reportPath); err != nil {
		return fmt.Errorf("jobs: scan exported set: %w", err)
	}
	cdxPath := filepath.Join(e.Dir, "report.cdx.json")
	if _, err := e.Trivy.ConvertToCycloneDX(ctx, reportPath, cdxPath); err != nil {
		return fmt.Errorf("jobs: convert exported report to cyclonedx: %w", err)
	}
	return nil
}

// writeFindingsCSV reads the analysis' own candidate scan, so the current
// and selected resolutions being compared are exactly what the analysis
// already resolved and scanned, and expands it with report.FindingsRows
// instead of the collapsed set rank.Index.Set gives: findings.csv needs
// one row per affected package. A dependency with
// several selected versions gets one report.DependencyResolution per
// version, each compared against the same current resolution, so
// findings.csv gets one row per selected version and vulnerability, as
// the spec's selected_version column implies.
func (e *Export) writeFindingsCSV() error {
	f, err := os.Open(filepath.Join(e.Analysis.Dir, "candidates.trivy.json"))
	if err != nil {
		return fmt.Errorf("jobs: read candidates.trivy.json: %w", err)
	}
	defer f.Close()
	findings, err := rank.ReadTrivyJSON(f)
	if err != nil {
		return fmt.Errorf("jobs: parse candidates.trivy.json: %w", err)
	}
	ix := rank.NewIndex(findings)

	platform := npm.Platform{OS: e.Project.Target.OS, CPU: e.Project.Target.CPU, Libc: e.Project.Target.Libc}
	names := sortedKeys(e.Request.Selection)
	var deps []report.DependencyResolution
	for _, name := range names {
		versions := e.Request.Selection[name]
		if len(versions) == 0 {
			continue
		}
		current := currentVersionOf(e.Analysis.Result, name)
		currentKeys, err := e.lockfileKeys(platform, name, current)
		if err != nil {
			return err
		}
		for _, version := range versions {
			selectedKeys, err := e.lockfileKeys(platform, name, version)
			if err != nil {
				return err
			}
			deps = append(deps, report.DependencyResolution{
				Name: name, CurrentVersion: current, SelectedVersion: version,
				CurrentKeys: currentKeys, SelectedKeys: selectedKeys,
			})
		}
	}

	out, err := os.Create(filepath.Join(e.Dir, "findings.csv"))
	if err != nil {
		return fmt.Errorf("jobs: create findings.csv: %w", err)
	}
	writeErr := report.WriteFindingsCSV(out, report.FindingsRows(ix, deps))
	if closeErr := out.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

func (e *Export) lockfileKeys(platform npm.Platform, name, version string) ([]string, error) {
	pkgs, err := e.readLockfile(e.candidateLockfilePath(name, version))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(pkgs))
	for _, p := range platform.Filter(pkgs) {
		keys = append(keys, p.Key())
	}
	return keys, nil
}

func currentVersionOf(r Result, name string) string {
	for _, d := range r.Dependencies {
		if d.Name == name {
			return d.Current
		}
	}
	return ""
}

// analysisStatus reads the few fields of the analysis' status.json that
// summary.md needs. It is a local, minimal copy rather than the type
// analysis.go owns: a field this export cannot read stays at its zero
// value instead of failing the export over a report of secondary
// importance.
type analysisStatus struct {
	CreatedAt    time.Time `json:"createdAt"`
	TrivyVersion string    `json:"trivyVersion"`
	TrivyDBDate  time.Time `json:"trivyDbDate"`
}

func (e *Export) readAnalysisStatus() analysisStatus {
	var status analysisStatus
	path := filepath.Join(e.Analysis.Dir, "status.json")
	if err := e.Store.ReadJSON(path, &status); err != nil {
		// summary.md still gets written with zero dates and versions: a
		// report of secondary importance should not fail the export over
		// a status.json that is missing or corrupt, but a silent miss here
		// is hard to diagnose from the outside.
		slog.Warn("jobs: could not read analysis status for summary.md", "path", path, "error", err)
	}
	return status
}

func (e *Export) writeSummary(shipped []shippedPackage, arch report.ArchiveManifest) error {
	status := e.readAnalysisStatus()

	var deps []report.DependencyChange
	var signals []report.SignalNote
	for _, d := range e.Analysis.Result.Dependencies {
		for _, selected := range e.Request.Selection[d.Name] {
			if selected == d.Current {
				continue
			}
			after := rank.Vector(d.Vector)
			if candidate, found := findCandidate(d.Candidates, selected); found {
				after = rank.Vector(candidate.Vector)
				for _, sig := range candidate.Signals {
					if !sig.Blocking {
						signals = append(signals, report.SignalNote{
							Dependency: d.Name, Version: selected,
							Signal: rank.Signal(sig.Name), Evidence: sig.Evidence,
						})
					}
				}
			}
			deps = append(deps, report.DependencyChange{
				Name: d.Name, CurrentVersion: d.Current, SelectedVersion: selected,
				Before: rank.Vector(d.Vector), After: after,
			})
		}
	}

	critical, high, err := e.remainingFindings()
	if err != nil {
		return err
	}

	// e.Analysis.Result.After is nil when the analysis' own step 9
	// (check-combined) never measured it: report.Summary keeps that
	// distinction rather than printing a vector of zeros that would read
	// as a clean bill of health.
	var after *rank.Vector
	if e.Analysis.Result.After != nil {
		v := rank.Vector(*e.Analysis.Result.After)
		after = &v
	}

	s := report.Summary{
		AnalysisDate: status.CreatedAt, TrivyDBDate: status.TrivyDBDate, TrivyVersion: status.TrivyVersion,
		ToolVersion: ToolVersion, Target: e.Project.Target,
		Before: rank.Vector(e.Analysis.Result.Before), After: after,
		Dependencies: deps, RemainingCritical: critical, RemainingHigh: high,
		Signals: signals, ArchiveSize: arch.Size, ArchiveSHA256: arch.SHA256, PackageCount: len(shipped),
	}

	out, err := os.Create(filepath.Join(e.Dir, "summary.md"))
	if err != nil {
		return fmt.Errorf("jobs: create summary.md: %w", err)
	}
	writeErr := report.WriteSummary(out, s)
	if closeErr := out.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

func findCandidate(cands []Candidate, version string) (Candidate, bool) {
	for _, c := range cands {
		if c.Version == version {
			return c, true
		}
	}
	return Candidate{}, false
}

// remainingFindings reads the export's own just-written report.trivy.json,
// so "remaining" reflects the vulnerabilities of the set actually shipped.
func (e *Export) remainingFindings() (critical, high []rank.Finding, err error) {
	f, err := os.Open(filepath.Join(e.Dir, "report.trivy.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("jobs: read report.trivy.json: %w", err)
	}
	defer f.Close()
	findings, err := rank.ReadTrivyJSON(f)
	if err != nil {
		return nil, nil, fmt.Errorf("jobs: parse report.trivy.json: %w", err)
	}
	for _, fnd := range findings {
		switch fnd.Severity {
		case rank.Critical:
			critical = append(critical, fnd)
		case rank.High:
			high = append(high, fnd)
		}
	}
	return critical, high, nil
}

// sortedKeys returns m's keys sorted, whatever the value type: it sorts
// both a selection's []string values and any plain map[string]string this
// file still builds.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// emitStep emits a "step" event with the payload shape analysis.go's
// stepData already defines, so both job kinds' step events share one
// TypeScript type on the frontend. err is nil for every state but Failed;
// emitFailedStep is the Failed-only call every step above actually uses,
// so the reason never ends up nowhere the way it would if only the
// server log recorded it.
func emitStep(emit func(Event), name string, state store.State, d time.Duration) {
	emit(Event{Kind: "step", Data: mustJSON(stepData{Name: name, State: state, DurationMs: d.Milliseconds()})})
}

// emitFailedStep is emitStep for state Failed, with the error that failed
// it.
func emitFailedStep(emit func(Event), name string, d time.Duration, err error) {
	emit(Event{Kind: "step", Data: mustJSON(stepData{Name: name, State: store.Failed, DurationMs: d.Milliseconds(), Error: err.Error()})})
}

// progressEvent builds a "progress" event with analysis.go's progressData
// shape, reporting the running cache-hit count alongside it: only an
// export's download step calls this.
func progressEvent(done, total, cacheHits int) Event {
	return Event{Kind: "progress", Data: mustJSON(progressData{Done: done, Total: total, CacheHits: &cacheHits})}
}
