package jobs

import "github.com/MorganKryze/sealift/rank"

// projectedVector estimates the project's vulnerabilities once the
// selection replaces each changed dependency: the project's own set, less
// what only the replaced versions carried, plus what the selected versions
// carry. A dependency with several selected versions counts the best of
// them, the current one included, as an install keeps one. It reads the
// per-dependency sets the analysis measured, so a vulnerability that a
// replaced version and a kept dependency share stays counted.
func projectedVector(project []rank.Finding, deps []DependencyResult, selection map[string][]string) rank.Vector {
	set := map[string]rank.Severity{}
	add := func(id string, sev rank.Severity) {
		if prev, ok := set[id]; !ok || sev < prev {
			set[id] = sev
		}
	}
	for _, f := range project {
		add(f.ID, f.Severity)
	}

	var kept, added []CVE
	removed := map[string]bool{}
	for _, d := range deps {
		_, cves, replaced := pickedCVEs(d, selection[d.Name])
		if !replaced {
			kept = append(kept, d.CVEs...)
			continue
		}
		for _, c := range d.CVEs {
			removed[c.ID] = true
		}
		added = append(added, cves...)
	}
	for id := range removed {
		delete(set, id)
	}
	for _, c := range append(kept, added...) {
		add(c.ID, rank.ParseSeverity(c.Severity))
	}

	var v rank.Vector
	for _, sev := range set {
		v[sev]++
	}
	return v
}

// projectedFor is the estimate summary.md prints and cves.after signs.
// With the project tree, the lockfile keeps every current version beside
// the selected ones, so it counts the project's set and every version the
// archive holds, as review.left lists them.
func projectedFor(r Result, req ExportRequest, project []rank.Finding) rank.Vector {
	if !req.IncludeProject {
		return projectedVector(project, r.Dependencies, req.Selection)
	}
	set := map[string]rank.Severity{}
	add := func(id string, sev rank.Severity) {
		if prev, ok := set[id]; !ok || sev < prev {
			set[id] = sev
		}
	}
	for _, f := range project {
		add(f.ID, f.Severity)
	}
	for _, a := range askedOf(r, req) {
		for _, h := range a.held {
			for _, c := range h.cves {
				add(c.ID, rank.ParseSeverity(c.Severity))
			}
		}
	}
	var v rank.Vector
	for _, sev := range set {
		v[sev]++
	}
	return v
}

// pickedCVEs returns the best selected version of d, the version an install
// keeps, with its vulnerabilities and whether it replaces the current one.
// The version is empty when nothing of d is selected.
func pickedCVEs(d DependencyResult, selected []string) (string, []CVE, bool) {
	bestVersion, bestVec, bestCVEs, replaced := "", rank.Vector{}, []CVE(nil), false
	for _, version := range selected {
		vec, cves, isCandidate := rank.Vector(d.Vector), d.CVEs, false
		if version != d.Current {
			c, ok := findCandidate(d.Candidates, version)
			if !ok {
				continue
			}
			vec, cves, isCandidate = rank.Vector(c.Vector), c.CVEs, true
		}
		if bestVersion == "" || vec.Compare(bestVec) < 0 {
			bestVersion, bestVec, bestCVEs, replaced = version, vec, cves, isCandidate
		}
	}
	return bestVersion, bestCVEs, replaced
}
