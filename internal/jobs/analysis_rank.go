package jobs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// cvesOf converts a vulnerability set (as rank.Index.Set returns it, and
// as VectorOf counts it) into the sorted list the contract carries:
// severity first, critical to unknown, then id, so the result never
// depends on map iteration order.
func cvesOf(set map[string]rank.Finding) []CVE {
	findings := make([]rank.Finding, 0, len(set))
	for _, f := range set {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity < findings[j].Severity
		}
		return findings[i].ID < findings[j].ID
	})
	cves := make([]CVE, len(findings))
	for i, f := range findings {
		cves[i] = CVE{ID: f.ID, Severity: severityText(f.Severity)}
	}
	return cves
}

// severityText renders sev the way Trivy prints it (upper case ASCII)
// through rank.Severity.MarshalText, falling back to String's own
// out-of-range guard rather than propagating an error a vulnerability
// count has no use for.
func severityText(sev rank.Severity) string {
	text, err := sev.MarshalText()
	if err != nil {
		return sev.String()
	}
	return string(text)
}

// stepRank is step 8: it builds each dependency's ranked result from its
// resolved candidates and writes candidates.json. A failure writing that
// file fails the job: a done analysis with no candidates.json would leave
// the interface with nothing to show for it, and no way to tell that
// apart from an analysis that genuinely found nothing to rank.
func (r *run) stepRank(deps []depInfo, outcomes []candidateOutcome, combinedIndex rank.Index) error {
	return r.runStep("rank", func() error {
		byDep := groupOutcomesByDep(outcomes)
		policy := rank.Policy{
			Now:           time.Now(),
			MinReleaseAge: time.Duration(r.a.Settings.MinReleaseAgeDays) * 24 * time.Hour,
			TargetNode:    r.a.Project.Target.Node,
		}
		for _, d := range deps {
			// Candidates starts as an empty slice, not nil: the contract
			// marks it a required array, and a dependency with nothing
			// newer to offer must still serialise it as [].
			dr := DependencyResult{Name: d.dep.Name, Current: d.dep.Version, CVEs: []CVE{}, Candidates: []Candidate{}}
			if d.warning != "" {
				r.result.Warnings = append(r.result.Warnings, d.dep.Name+": "+d.warning)
				r.result.Dependencies = append(r.result.Dependencies, dr)
				continue
			}
			group := byDep[d.dep.Name]
			r.rankDependency(&dr, d, group, combinedIndex, policy)
			r.result.Dependencies = append(r.result.Dependencies, dr)
		}
		return r.a.Store.WriteJSON(filepath.Join(r.a.Dir, "candidates.json"), r.result)
	})
}

func groupOutcomesByDep(outcomes []candidateOutcome) map[string][]candidateOutcome {
	byDep := make(map[string][]candidateOutcome)
	for _, o := range outcomes {
		byDep[o.task.dep.Name] = append(byDep[o.task.dep.Name], o)
	}
	return byDep
}

// rankDependency fills dr's vector, candidates and best version from
// group, the current-plus-candidate outcomes step 6 resolved for it.
func (r *run) rankDependency(dr *DependencyResult, d depInfo, group []candidateOutcome, combinedIndex rank.Index, policy rank.Policy) {
	var currentMeta npm.VersionMeta
	if d.packument.Versions != nil {
		currentMeta = d.packument.Versions[d.dep.Version]
	}
	currentFacts := factsOf(d.dep.Version, currentMeta, d.packument, r.a.Project.Target)

	var current candidateOutcome
	var others []candidateOutcome
	for _, o := range group {
		if o.task.current {
			current = o
		} else {
			others = append(others, o)
		}
	}
	if current.err != nil {
		// The current version's own isolated resolution failed, so there is
		// nothing to compare candidates against: dr.Vector would stay at its
		// zero value, and rank.Best would read that zero as "no CVEs", never
		// finding a candidate worse than it. Warn instead of leaving the
		// dependency looking clean, and skip ranking below.
		r.result.Warnings = append(r.result.Warnings, fmt.Sprintf(
			"%s: the current version %s does not resolve: %v", d.dep.Name, d.dep.Version, current.err))
	} else {
		set := combinedIndex.Set(keysOf(current.pkgs))
		dr.Vector = Vector(rank.VectorOf(set))
		dr.CVEs = cvesOf(set)
	}
	currentFacts.Resolves = current.err == nil

	// d.newer is already ascending SemVer order (npm.NewerStable); step 6
	// reordered it key-first, so recover the ascending order from d.newer's
	// own index rather than comparing version strings.
	ascending := make(map[string]int, len(d.newer))
	for i, v := range d.newer {
		ascending[v] = i
	}
	slices.SortFunc(others, func(a, b candidateOutcome) int {
		return ascending[a.task.version] - ascending[b.task.version]
	})

	var rankCandidates []rank.Candidate
	for _, o := range others {
		meta := d.packument.Versions[o.task.version]
		facts := factsOf(o.task.version, meta, d.packument, r.a.Project.Target)
		facts.Resolves = o.err == nil
		hits := rank.Signals(currentFacts, facts, policy)
		if o.err != nil {
			hits = append([]rank.Hit{{Signal: rank.Unresolvable, Evidence: o.err.Error()}}, hits...)
		}

		var vec Vector
		cves := []CVE{}
		if o.err == nil {
			set := combinedIndex.Set(keysOf(o.pkgs))
			vec = Vector(rank.VectorOf(set))
			cves = cvesOf(set)
		}
		published := ""
		if t, ok := d.packument.Published(o.task.version); ok {
			published = t.Format(time.RFC3339)
		}
		dr.Candidates = append(dr.Candidates, Candidate{
			Version:   o.task.version,
			Vector:    vec,
			CVEs:      cves,
			Signals:   toSignals(hits),
			Key:       o.task.key,
			Resolved:  o.err == nil,
			Published: published,
		})
		rankCandidates = append(rankCandidates, rank.Candidate{Version: o.task.version, Vector: rank.Vector(vec), Hits: hits})

		names := make([]string, len(hits))
		for i, h := range hits {
			names[i] = string(h.Signal)
		}
		r.emit(Event{Kind: "candidate", Data: mustJSON(candidateData{
			Dependency: d.dep.Name, Version: o.task.version, Vector: vec, Signals: names,
		})})
	}

	if current.err == nil {
		if best, ok := rank.Best(d.dep.Version, rank.Vector(dr.Vector), rankCandidates); ok {
			dr.Best = best.Version
		}
	}
}

// stepCheckCombined is step 9: it resolves the project with every best
// candidate at once. A conflict is shown with pnpm's output and recorded as
// a warning; candidates stay selectable, so the job does not fail.
func (r *run) stepCheckCombined(manifest npm.Manifest) {
	// Deliberately discarded: this step's own comment already covers the
	// pnpm conflict path, and it is the last of the nine steps, so even a
	// filesystem failure inside it has no later step whose own success it
	// could put in doubt the way steps 6 and 8 would.
	_ = r.runStep("check-combined", func() error {
		overrides := make(map[string]string)
		for _, dr := range r.result.Dependencies {
			if dr.Best != "" {
				overrides[dr.Name] = dr.Best
			}
		}
		lockRaw, output, err := r.a.resolve(r.ctx, buildFullManifest(manifest, overrides))
		if err != nil {
			r.log("pnpm: " + output)
			r.result.Warnings = append(r.result.Warnings, fmt.Sprintf("the best candidates together do not resolve: %v", err))
			return nil
		}
		if werr := os.MkdirAll(filepath.Join(r.a.Dir, "combined"), 0o770); werr != nil {
			return werr
		}
		if werr := os.WriteFile(filepath.Join(r.a.Dir, "combined", "pnpm-lock.yaml"), lockRaw, 0o664); werr != nil {
			return werr
		}
		parsed, perr := npm.ParseLockfile(bytes.NewReader(lockRaw))
		if perr != nil {
			return fmt.Errorf("parse combined lockfile: %w", perr)
		}
		pkgs := platformOf(r.a.Project.Target).Filter(parsed)
		findings, serr := r.a.scanPackages(r.ctx, pkgs, filepath.Join(r.a.Dir, "combined.trivy.json"))
		if serr != nil {
			return fmt.Errorf("scan combined: %w", serr)
		}
		after := Vector(rank.VectorOf(rank.NewIndex(findings).Set(keysOf(pkgs))))
		r.result.After = &after
		return nil
	})
}
