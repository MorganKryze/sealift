package jobs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// depInfo is one direct dependency together with the newer stable versions
// its packument lists, or the warning that stands in for them when the
// registry never answered.
type depInfo struct {
	dep       npm.Dependency
	packument npm.Packument
	newer     []string
	warning   string
}

// stepListCandidates is step 5: for each direct dependency, it fetches the
// full packument and keeps every newer stable version. A package whose
// metadata stays unreachable (the registry client already retries 3 times,
// see npm.Client.Attempts) gets marked and the job continues.
func (r *run) stepListCandidates(manifest npm.Manifest) []depInfo {
	var infos []depInfo
	// listOneCandidate never returns an error of its own: an unreachable
	// registry or an unparseable current version becomes a per-dependency
	// warning instead, so this step's own fn always succeeds and there is
	// nothing here for the discarded return value to lose.
	_ = r.runStep("list-candidates", func() error {
		total := len(manifest.Dependencies)
		for i, d := range manifest.Dependencies {
			infos = append(infos, r.listOneCandidate(d))
			r.progress(i+1, total)
		}
		return nil
	})
	return infos
}

// listOneCandidate fetches one dependency's packument and its newer stable
// versions, or the warning that stands in for them when the registry
// never answered or the current version does not parse as SemVer.
func (r *run) listOneCandidate(d npm.Dependency) depInfo {
	pk, err := r.a.Registry.Packument(r.ctx, d.Name)
	if err != nil {
		r.log(fmt.Sprintf("%s: metadata unreachable: %v", d.Name, err))
		return depInfo{dep: d, warning: fmt.Sprintf("metadata unreachable: %v", err)}
	}
	versions := make([]string, 0, len(pk.Versions))
	for v := range pk.Versions {
		versions = append(versions, v)
	}
	newer, nerr := npm.NewerStable(d.Version, versions)
	if nerr != nil {
		return depInfo{dep: d, packument: pk, warning: fmt.Sprintf("current version: %v", nerr)}
	}
	return depInfo{dep: d, packument: pk, newer: newer}
}

// candidateTask is one isolated resolution step 6 must run: a dependency
// pinned to one version, either the current one or a newer candidate.
type candidateTask struct {
	dep     npm.Dependency
	version string
	key     bool
	current bool
}

// candidateOutcome is the result of running one candidateTask.
type candidateOutcome struct {
	task   candidateTask
	pkgs   []npm.LockPackage
	lock   []byte
	output string
	err    error
}

// stepResolveCandidates is step 6: for each dependency, it resolves the
// current version and every newer candidate in isolation, key candidates
// first, resolveParallelism resolutions at a time. A candidate that fails
// to resolve is marked and the job continues; a failure writing a resolved
// candidate's own lockfile to disk fails the job instead, since a later
// export reading a missing lockfile would otherwise fail deep inside with
// no useful explanation.
func (r *run) stepResolveCandidates(deps []depInfo, manifest npm.Manifest, beforeIndex rank.Index) ([]candidateOutcome, error) {
	var outcomes []candidateOutcome
	err := r.runStep("resolve-candidates", func() error {
		tasks := buildCandidateTasks(deps, beforeIndex)
		packuments := make(map[string]npm.Packument, len(deps))
		for _, d := range deps {
			packuments[d.dep.Name] = d.packument
		}
		outcomes = r.a.resolveCandidateTasks(r.ctx, tasks, packuments, projectVersionsOf(manifest), r.progress)
		for _, o := range outcomes {
			if o.err != nil {
				r.log(fmt.Sprintf("%s@%s does not resolve: %v", o.task.dep.Name, o.task.version, o.err))
				continue
			}
			dir := filepath.Join(r.a.Dir, "candidates", o.task.dep.Name+"@"+o.task.version)
			if werr := os.MkdirAll(dir, 0o770); werr != nil {
				return werr
			}
			if werr := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), o.lock, 0o664); werr != nil {
				return werr
			}
		}
		return nil
	})
	return outcomes, err
}

// buildCandidateTasks orders the whole task list in two passes: every
// dependency's current version and key candidates first, in dependency
// order, then every dependency's remaining candidates, in dependency
// order. resolveCandidateTasks bounds the whole list with one semaphore,
// so this is what actually decides which candidates start first under a
// limited concurrency. A single dependency-major pass would let one
// dependency's non-key candidates queue ahead of another dependency's key
// one, and key candidates must go first.
func buildCandidateTasks(deps []depInfo, beforeIndex rank.Index) []candidateTask {
	var primary, rest []candidateTask
	for _, d := range deps {
		if d.warning != "" {
			continue
		}
		primary = append(primary, candidateTask{dep: d.dep, version: d.dep.Version, current: true})

		fixed := fixedVersionsOf(beforeIndex, d.dep.Name, d.dep.Version)
		keys := rank.KeyVersions(d.dep.Version, d.newer, fixed)
		ordered := orderKeyFirst(d.newer, keys)
		for _, v := range ordered {
			key := slices.Contains(keys, v)
			task := candidateTask{dep: d.dep, version: v, key: key}
			if key {
				primary = append(primary, task)
			} else {
				rest = append(rest, task)
			}
		}
	}
	return append(primary, rest...)
}

// fixedVersionsOf returns the FixedVersion strings Trivy reported for name
// at version, the dependency's own CVEs as opposed to its whole subtree's.
func fixedVersionsOf(index rank.Index, name, version string) []string {
	var fixed []string
	for _, f := range index.Set([]string{name + "@" + version}) {
		if f.FixedVersion != "" {
			fixed = append(fixed, f.FixedVersion)
		}
	}
	return fixed
}

// resolveCandidateTasks runs every task through a pool bounded by
// ResolveParallelism, launched in list order so a slot only opens up for
// task i+1 once an earlier one has started, which keeps key candidates
// ahead of the rest even under the concurrency limit.
func (a *Analysis) resolveCandidateTasks(ctx context.Context, tasks []candidateTask, packuments map[string]npm.Packument, projectVersions map[string]string, onProgress func(done, total int)) []candidateOutcome {
	n := a.Settings.ResolveParallelism
	if n <= 0 {
		n = 1
	}
	outcomes := make([]candidateOutcome, len(tasks))

	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, task := range tasks {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, task candidateTask) {
			defer wg.Done()
			defer func() { <-sem }()
			var peerDeps map[string]string
			if pk, ok := packuments[task.dep.Name]; ok {
				peerDeps = pk.Versions[task.version].PeerDependencies
			}
			manifestBytes := buildProbeManifest(task.dep.Name, task.version, peerDeps, projectVersions)
			lockRaw, output, err := a.resolve(ctx, manifestBytes)
			outcome := candidateOutcome{task: task, output: output, err: err}
			if err == nil {
				if parsed, perr := npm.ParseLockfile(bytes.NewReader(lockRaw)); perr != nil {
					outcome.err = perr
				} else {
					outcome.pkgs = platformOf(a.Project.Target).Filter(parsed)
					outcome.lock = lockRaw
				}
			}
			mu.Lock()
			outcomes[i] = outcome
			done++
			d := done
			mu.Unlock()
			onProgress(d, len(tasks))
		}(i, task)
	}
	wg.Wait()
	return outcomes
}

// projectVersionsOf maps every dependency the project declares to its own
// version, so buildProbeManifest can pin a candidate's peer dependency to
// the version the project itself already pins it to.
func projectVersionsOf(manifest npm.Manifest) map[string]string {
	versions := make(map[string]string, len(manifest.Dependencies))
	for _, d := range manifest.Dependencies {
		versions[d.Name] = d.Version
	}
	return versions
}

// stepScanCandidates is step 7: it scans the union of every candidate's
// filtered packages in two Trivy calls, key candidates first, and merges
// both reports into candidates.trivy.json.
func (r *run) stepScanCandidates(outcomes []candidateOutcome) (rank.Index, error) {
	var index rank.Index
	err := r.runStep("scan-candidates", func() error {
		var keyPkgs, restPkgs []npm.LockPackage
		for _, o := range outcomes {
			if o.err != nil {
				continue
			}
			if o.task.key || o.task.current {
				keyPkgs = append(keyPkgs, o.pkgs...)
			} else {
				restPkgs = append(restPkgs, o.pkgs...)
			}
		}

		keyPath := filepath.Join(r.a.Dir, "candidates.trivy.key.json")
		restPath := filepath.Join(r.a.Dir, "candidates.trivy.rest.json")
		defer os.Remove(keyPath)
		defer os.Remove(restPath)

		keyFindings, kerr := r.a.scanPackages(r.ctx, keyPkgs, keyPath)
		if kerr != nil {
			return fmt.Errorf("scan key candidates: %w", kerr)
		}
		r.progress(1, 2)

		restFindings, rerr := r.a.scanPackages(r.ctx, restPkgs, restPath)
		if rerr != nil {
			return fmt.Errorf("scan remaining candidates: %w", rerr)
		}
		r.progress(2, 2)

		if merr := mergeTrivyReports([]string{keyPath, restPath}, filepath.Join(r.a.Dir, "candidates.trivy.json")); merr != nil {
			return merr
		}

		index = rank.NewIndex(append(keyFindings, restFindings...))
		return nil
	})
	return index, err
}
