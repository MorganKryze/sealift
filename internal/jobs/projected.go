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
		cves, replaced := pickedCVEs(d, selection[d.Name])
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

// pickedCVEs returns the vulnerabilities of the best selected version of d,
// and whether that version replaces the current one.
func pickedCVEs(d DependencyResult, selected []string) ([]CVE, bool) {
	bestVec, bestCVEs, replaced, found := rank.Vector{}, []CVE(nil), false, false
	for _, version := range selected {
		vec, cves, isCandidate := rank.Vector(d.Vector), d.CVEs, false
		if version != d.Current {
			c, ok := findCandidate(d.Candidates, version)
			if !ok {
				continue
			}
			vec, cves, isCandidate = rank.Vector(c.Vector), c.CVEs, true
		}
		if !found || vec.Compare(bestVec) < 0 {
			bestVec, bestCVEs, replaced, found = vec, cves, isCandidate, true
		}
	}
	return bestCVEs, replaced
}
