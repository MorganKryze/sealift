package jobs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// platformOfPip is the pip target as the wheel tags and markers see it.
func platformOfPip(t store.PipTarget) pip.Platform {
	return pip.Platform{Python: t.Python, OS: t.OS, CPU: t.CPU, Glibc: t.Glibc}
}

// stepCheckPins reads the index page of every requirement the target
// installs and refuses the analysis, before uv runs, when one of them has
// no wheel the target can install or none its hashes list. uv stops at the
// first such package, so sealift names them all itself. A constraint is
// left to choose-wheels: it installs only when something requires it.
func (r *pipRun) stepCheckPins() error {
	return r.runStep("check-pins", func() error {
		r.pins = r.targetPins()
		var pkgs []runner.Resolved
		for _, p := range r.pins {
			if p.Constraint {
				continue
			}
			if !slices.ContainsFunc(pkgs, func(q runner.Resolved) bool { return q.Name == p.Key }) {
				pkgs = append(pkgs, runner.Resolved{Name: p.Key, Version: p.Version})
			}
		}
		choices, err := r.chooseWheels("check-pins", pkgs)
		if err != nil {
			return err
		}
		var blocking []PipBlocking
		for _, c := range choices {
			if c.blocking != nil {
				blocking = append(blocking, *c.blocking)
			}
		}
		return r.refuse(blocking)
	})
}

// stepChooseWheels records, for every package of the resolved set, the
// wheel the target's installer prefers, with the index's sha256. A yanked
// wheel, or a pin's wheel uploaded within the minimum release age, gets a
// warning.
func (r *pipRun) stepChooseWheels(resolved []runner.Resolved) error {
	return r.runStep("choose-wheels", func() error {
		choices, err := r.chooseWheels("choose-wheels", resolved)
		if err != nil {
			return err
		}
		days := r.a.Settings.MinReleaseAgeDays
		cut := r.releaseCut()
		var blocking []PipBlocking
		r.wheels = make(map[string]PipWheel, len(choices))
		for i, c := range choices {
			pkg := resolved[i]
			if c.blocking != nil {
				blocking = append(blocking, *c.blocking)
				continue
			}
			f := c.file
			r.wheels[pkg.Name] = PipWheel{File: f.Filename, URL: f.URL, Sha256: f.Sha256, Size: f.Size}
			if f.Yanked {
				reason := cleanText(f.YankedReason, yankedReasonLimit)
				if reason == "" {
					reason = "no reason given"
				}
				r.warnings = append(r.warnings, fmt.Sprintf("%s==%s is yanked on the index: %s", pkg.Name, pkg.Version, reason))
			}
			if f.UploadTime.After(cut) {
				r.warnings = append(r.warnings, fmt.Sprintf("%s==%s was uploaded on %s, within the %d-day minimum release age",
					pkg.Name, pkg.Version, f.UploadTime.UTC().Format(time.DateOnly), days))
			}
		}
		return r.refuse(blocking)
	})
}

// yankedReasonLimit bounds, in runes, the yank reason a warning quotes from
// the index.
const yankedReasonLimit = 200

// wheelChoice is the wheel chosen for one package, or why there is none.
type wheelChoice struct {
	file     pip.IndexFile // zero when blocked
	blocking *PipBlocking
}

// chooseWheels chooses a wheel for each package, in order. A page read
// once in this run is not read again. A package no pin of the target fixes
// chooses among the files uploaded before the minimum release age, the
// files uv resolved it from, so a wheel added to an old release later is
// never recorded.
func (r *pipRun) chooseWheels(step string, pkgs []runner.Resolved) ([]wheelChoice, error) {
	var missing []runner.Resolved
	for _, p := range pkgs {
		if _, ok := r.indexFiles[p.Name+"@"+p.Version]; !ok {
			missing = append(missing, p)
		}
	}
	fetched, err := fetchIndexFiles(r.ctx, r.a.Index, missing, r.a.Settings.ResolveParallelism, func(done int) {
		r.progress(step, done, len(missing))
	})
	if err != nil {
		return nil, err
	}
	if r.indexFiles == nil {
		r.indexFiles = make(map[string][]pip.IndexFile, len(fetched))
	}
	for i, p := range missing {
		r.indexFiles[p.Name+"@"+p.Version] = fetched[i]
	}
	platform := platformOfPip(r.a.Project.PipTarget)
	cut := r.releaseCut()
	choices := make([]wheelChoice, len(pkgs))
	for i, p := range pkgs {
		files := r.indexFiles[p.Name+"@"+p.Version]
		heldBack := false
		if !slices.ContainsFunc(r.pins, func(pin pip.Pin) bool { return pin.Key == p.Name }) {
			// uv drops a file with no upload time as well.
			old := slices.DeleteFunc(slices.Clone(files), func(f pip.IndexFile) bool {
				return f.UploadTime.IsZero() || !f.UploadTime.Before(cut)
			})
			heldBack, files = len(old) < len(files), old
		}
		file, blocking := chooseWheel(p, files, platform, r.hashesOf(p.Name), r.set.FilesOf(p.Name))
		if blocking != nil && heldBack {
			blocking.Detail += fmt.Sprintf(", counting only the files uploaded more than %d days ago", r.a.Settings.MinReleaseAgeDays)
		}
		choices[i] = wheelChoice{file: file, blocking: blocking}
	}
	return choices, nil
}

// fetchIndexFiles reads the index's files of each package, parallel pages
// at a time. A project the index does not know gets no files. It never
// fetches a file itself, only the pages that list them.
func fetchIndexFiles(ctx context.Context, c *pip.Client, pkgs []runner.Resolved, parallel int, onDone func(done int)) ([][]pip.IndexFile, error) {
	parallel = max(parallel, 1)
	files := make([][]pip.IndexFile, len(pkgs))
	errs := make([]error, len(pkgs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, p := range pkgs {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			f, err := c.Files(ctx, p.Name, p.Version)
			if errors.Is(err, pip.ErrNotFound) {
				f, err = nil, nil
			}
			if err != nil {
				err = fmt.Errorf("read the index page of %s==%s: %w", p.Name, p.Version, err)
			}
			files[i], errs[i] = f, err
			// Held while onDone runs, so the job's events go out one at a time.
			mu.Lock()
			defer mu.Unlock()
			done++
			onDone(done)
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

// chooseWheel picks the wheel of pkg the target's installer prefers. With
// hashes, it picks among the wheels they list, as pip does in
// hash-checking mode, and blocks the package when they list none the
// target can install. pinnedIn names the files that pin it.
func chooseWheel(pkg runner.Resolved, files []pip.IndexFile, p pip.Platform, hashes, pinnedIn []string) (pip.IndexFile, *PipBlocking) {
	best, kind := pip.ChooseWheel(files, p)
	if kind != "" {
		return pip.IndexFile{}, &PipBlocking{Name: pkg.Name, Version: pkg.Version, Kind: string(kind), Detail: blockingDetail[kind]}
	}
	if len(hashes) == 0 || slices.Contains(hashes, best.Sha256) {
		return best, nil
	}
	listed := slices.DeleteFunc(slices.Clone(files), func(f pip.IndexFile) bool { return !slices.Contains(hashes, f.Sha256) })
	if w, kind := pip.ChooseWheel(listed, p); kind == "" {
		return w, nil
	}
	return pip.IndexFile{}, &PipBlocking{
		Name: pkg.Name, Version: pkg.Version, Kind: hashMismatch,
		Detail: fmt.Sprintf("the --hash options in %s list no wheel the target can install, such as %s",
			strings.Join(pinnedIn, ", "), best.Filename),
	}
}

const hashMismatch = "hash-mismatch"

var blockingDetail = map[pip.Blocking]string{
	pip.SourceOnly:     "source distribution only",
	pip.OtherPlatforms: "wheels for other platforms only",
	pip.NoFiles:        "no files on the index",
}

// hashesOf returns the hashes every pin of key allows, empty when no pin
// of key carries one. The parser gives every pin of a key the same list.
func (r *pipRun) hashesOf(key string) []string {
	for _, p := range slices.Concat(r.set.Requirements, r.set.Constraints) {
		if p.Key == key && len(p.Hashes) > 0 {
			return p.Hashes
		}
	}
	return nil
}

// refuse fails the step when blocking names a package, after it logs each
// one and writes pip-result.json, so the result lists every package even
// where the failure names only the first few.
func (r *pipRun) refuse(blocking []PipBlocking) error {
	if len(blocking) == 0 {
		return nil
	}
	shown := make([]string, 0, shownProblems)
	for i, b := range blocking {
		line := r.describeBlocking(b)
		r.log(line)
		if i < shownProblems {
			shown = append(shown, line)
		}
	}
	if err := r.writeFailedResult(blocking); err != nil {
		return err
	}
	msg := fmt.Sprintf("%d %s no wheel the target can install: %s", len(blocking),
		plural(len(blocking), "package has", "packages have"), strings.Join(shown, "; "))
	if len(blocking) > shownProblems {
		msg += "; the result lists every one"
	}
	return errors.New(msg)
}

// describeBlocking names a blocked package, the files that pin it, and why.
func (r *pipRun) describeBlocking(b PipBlocking) string {
	name := b.Name + "==" + b.Version
	if files := r.set.FilesOf(b.Name); len(files) > 0 {
		name += " (" + strings.Join(files, ", ") + ")"
	}
	return name + ": " + b.Detail
}

// writeFailedResult writes pip-result.json for an analysis that stops on
// blocking packages. It lists no package: none was scanned, so no list
// can read as a clean scan.
func (r *pipRun) writeFailedResult(blocking []PipBlocking) error {
	result := PipResult{
		Target:   r.a.Project.PipTarget,
		Files:    nonNil(r.files),
		Packages: []PipPackage{},
		Blocking: blocking,
		Warnings: nonNil(r.warnings),
	}
	return r.a.Store.WriteJSON(r.resultPath(), result)
}

// uvBlockingRE finds the package uv names as having no wheel the target
// can install, as uv words it after "Because".
var uvBlockingRE = regexp.MustCompile(`(\S+)==(\S+) has no (usable wheels|wheels with a matching [A-Za-z ]+ tag)`)

// blockingFromUv reads, from uv's output, the package that stopped the
// resolution for want of a wheel. uv stops at the first such package, so
// it names at most one.
func blockingFromUv(output string) (PipBlocking, bool) {
	m := uvBlockingRE.FindStringSubmatch(output)
	if m == nil || !pip.ValidName(m[1]) || !pip.IsExactVersion(m[2]) {
		return PipBlocking{}, false
	}
	kind := pip.OtherPlatforms
	if m[3] == "usable wheels" {
		kind = pip.SourceOnly
	}
	return PipBlocking{Name: pip.Normalize(m[1]), Version: m[2], Kind: string(kind), Detail: blockingDetail[kind]}, true
}
