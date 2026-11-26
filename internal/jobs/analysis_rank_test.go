package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// TestRankDependency_CurrentVersionResolveFailure covers the case a design
// review flagged: when the current version's own isolated resolution
// fails, dr.Vector has nothing to hold but its zero value, and rank.Best
// would read that as "no CVEs", recommending nothing is wrong and picking
// a "best" candidate the user never asked to compare against anything.
// rankDependency must warn instead, and never call rank.Best for this
// dependency.
func TestRankDependency_CurrentVersionResolveFailure(t *testing.T) {
	r := &run{
		a:       &Analysis{Settings: store.Settings{Target: store.Target{Node: "22.17.1"}}},
		stepLog: stepLog{ctx: context.Background(), emit: func(Event) {}},
		result:  &Result{},
	}
	dep := npm.Dependency{Name: "foo", Version: "1.0.0"}
	d := depInfo{
		dep: dep,
		packument: npm.Packument{Name: "foo", Versions: map[string]npm.VersionMeta{
			"1.0.0": {Version: "1.0.0"},
			"1.1.0": {Version: "1.1.0"},
		}},
		newer: []string{"1.1.0"},
	}
	group := []candidateOutcome{
		{task: candidateTask{dep: dep, version: "1.0.0", current: true}, err: errors.New("no matching version found")},
		{task: candidateTask{dep: dep, version: "1.1.0", key: true}},
	}
	dr := DependencyResult{Name: dep.Name, Current: dep.Version}
	policy := rank.Policy{Now: time.Now(), TargetNode: "22.17.1"}

	r.rankDependency(&dr, d, group, rank.Index{}, policy)

	if dr.Best != "" {
		t.Errorf("Best = %q, want empty: the current version never resolved, so nothing is a valid comparison", dr.Best)
	}
	if dr.Vector != (Vector{}) {
		t.Errorf("Vector = %v, want the zero value: it must never be read as a real, clean count", dr.Vector)
	}
	if len(r.result.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want exactly one warning", r.result.Warnings)
	}
	if !strings.Contains(r.result.Warnings[0], "foo") || !strings.Contains(r.result.Warnings[0], "does not resolve") {
		t.Errorf("warning %q does not name the dependency and its failure", r.result.Warnings[0])
	}
}

// TestRankDependency_CVEsListTheVulnerabilitiesBehindTheVector proves dr's
// cves, on the current version and on each candidate, list the same
// vulnerabilities the vector counts: express@4.17.1's two known CVEs, and
// none for the clean 4.21.2 candidate rank/testdata's own real Trivy
// report carries.
func TestRankDependency_CVEsListTheVulnerabilitiesBehindTheVector(t *testing.T) {
	data, err := os.ReadFile("../../rank/testdata/trivy-report.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	findings, err := rank.ReadTrivyJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("ReadTrivyJSON: %v", err)
	}
	combinedIndex := rank.NewIndex(findings)

	r := &run{
		a:       &Analysis{Settings: store.Settings{Target: store.Target{Node: "22.17.1"}}},
		stepLog: stepLog{ctx: context.Background(), emit: func(Event) {}},
		result:  &Result{},
	}
	dep := npm.Dependency{Name: "express", Version: "4.17.1"}
	d := depInfo{
		dep: dep,
		packument: npm.Packument{Name: "express", Versions: map[string]npm.VersionMeta{
			"4.17.1": {Version: "4.17.1"},
			"4.21.2": {Version: "4.21.2"},
		}},
		newer: []string{"4.21.2"},
	}
	group := []candidateOutcome{
		{task: candidateTask{dep: dep, version: "4.17.1", current: true}, pkgs: []npm.LockPackage{{Name: "express", Version: "4.17.1"}}},
		{task: candidateTask{dep: dep, version: "4.21.2", key: true}, pkgs: []npm.LockPackage{{Name: "express", Version: "4.21.2"}}},
	}
	dr := DependencyResult{Name: dep.Name, Current: dep.Version}
	policy := rank.Policy{Now: time.Now(), TargetNode: "22.17.1"}

	r.rankDependency(&dr, d, group, combinedIndex, policy)

	wantIDs := []string{"CVE-2024-29041", "CVE-2024-43796"}
	if len(dr.CVEs) != len(wantIDs) {
		t.Fatalf("dr.CVEs = %+v, want %d entries", dr.CVEs, len(wantIDs))
	}
	for i, want := range wantIDs {
		if dr.CVEs[i].ID != want {
			t.Errorf("dr.CVEs[%d].ID = %q, want %q", i, dr.CVEs[i].ID, want)
		}
	}
	if len(dr.Candidates) != 1 || dr.Candidates[0].Version != "4.21.2" {
		t.Fatalf("dr.Candidates = %+v, want exactly the 4.21.2 candidate", dr.Candidates)
	}
	if len(dr.Candidates[0].CVEs) != 0 {
		t.Errorf("4.21.2 candidate's CVEs = %+v, want none", dr.Candidates[0].CVEs)
	}
}

// fakeVersion is one version of a fake packument: when it was published and
// the peers it declares.
type fakeVersion struct {
	version   string
	published time.Time
	peers     map[string]string
}

var longAgo = time.Date(2025, 3, 31, 14, 0, 0, 0, time.UTC)

// fakeDependency builds what steps 5 and 6 hand the rank step for one
// dependency: its packument and an outcome per version, each version
// resolving to the package alone, ascending as npm.NewerStable gives them.
func fakeDependency(name, current string, newer ...fakeVersion) (depInfo, []candidateOutcome) {
	dep := npm.Dependency{Name: name, Version: current}
	pk := npm.Packument{
		Name:     name,
		Versions: map[string]npm.VersionMeta{current: {Version: current}},
		Time:     map[string]json.RawMessage{current: publishedAt(longAgo.AddDate(-2, 0, 0))},
	}
	d := depInfo{dep: dep, packument: pk}
	outcomes := []candidateOutcome{{
		task: candidateTask{dep: dep, version: current, current: true},
		pkgs: []npm.LockPackage{{Name: name, Version: current}},
	}}
	for _, v := range newer {
		pk.Versions[v.version] = npm.VersionMeta{Version: v.version, PeerDependencies: v.peers}
		pk.Time[v.version] = publishedAt(v.published)
		d.newer = append(d.newer, v.version)
		outcomes = append(outcomes, candidateOutcome{
			task: candidateTask{dep: dep, version: v.version, key: true},
			pkgs: []npm.LockPackage{{Name: name, Version: v.version}},
		})
	}
	return d, outcomes
}

func publishedAt(t time.Time) json.RawMessage {
	raw, _ := json.Marshal(t)
	return raw
}

// newRankRun returns a run whose rank step writes candidates.json to a
// temporary directory, with a seven-day minimum release age.
func newRankRun(t *testing.T, review policy.Review) *run {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return &run{
		a: &Analysis{
			Store:    st,
			Dir:      t.TempDir(),
			Review:   review,
			Settings: store.Settings{MinReleaseAgeDays: 7},
			Project:  store.Project{Target: store.Target{Node: "22.17.1"}},
		},
		stepLog: stepLog{ctx: context.Background(), emit: func(Event) {}},
		result:  &Result{Dependencies: []DependencyResult{}, Warnings: []string{}},
	}
}

// rankAll runs the rank step over deps, each with its outcomes.
func rankAll(t *testing.T, r *run, index rank.Index, deps ...func() (depInfo, []candidateOutcome)) {
	t.Helper()
	var infos []depInfo
	var outcomes []candidateOutcome
	for _, dep := range deps {
		d, o := dep()
		infos = append(infos, d)
		outcomes = append(outcomes, o...)
	}
	if err := r.stepRank(infos, outcomes, index); err != nil {
		t.Fatalf("stepRank: %v", err)
	}
}

func dependencyNamed(t *testing.T, r *run, name string) DependencyResult {
	t.Helper()
	i := slices.IndexFunc(r.result.Dependencies, func(d DependencyResult) bool { return d.Name == name })
	if i < 0 {
		t.Fatalf("no result for %s in %+v", name, r.result.Dependencies)
	}
	return r.result.Dependencies[i]
}

// expressWithAJump is express 4.17.1 with a known CVE, 4.22.3 inside its
// line but published yesterday, and a clean 5.1.0.
func expressWithAJump() (depInfo, []candidateOutcome) {
	return fakeDependency("express", "4.17.1",
		fakeVersion{version: "4.22.3", published: time.Now().Add(-24 * time.Hour)},
		fakeVersion{version: "5.1.0", published: longAgo})
}

var expressIndex = rank.NewIndex([]rank.Finding{
	{ID: "CVE-2024-29041", Package: "express", Version: "4.17.1", Severity: rank.Medium, FixedVersion: "4.19.2, 5.0.0-beta.3"},
})

func TestRankProposesInsideTheLine(t *testing.T) {
	r := newRankRun(t, policy.DefaultReview())
	rankAll(t, r, expressIndex, expressWithAJump)

	got := dependencyNamed(t, r, "express")
	if got.Best != "" {
		t.Errorf("Best = %q, want none: 4.22.3 is too recent and 5.1.0 leaves major 4", got.Best)
	}
	if got.Jump != "5.1.0" {
		t.Errorf("Jump = %q, want 5.1.0", got.Jump)
	}
}

func TestRankProposesOtherMajorsWhenThePolicyAllows(t *testing.T) {
	review := policy.DefaultReview()
	review.ProposeOtherMajors = true
	r := newRankRun(t, review)
	rankAll(t, r, expressIndex, expressWithAJump)

	got := dependencyNamed(t, r, "express")
	if got.Best != "5.1.0" || got.Jump != "5.1.0" {
		t.Errorf("Best, Jump = %q, %q, want 5.1.0 for both", got.Best, got.Jump)
	}
}

func TestRankNamesTheJump(t *testing.T) {
	index := rank.NewIndex([]rank.Finding{
		{ID: "CVE-2024-29041", Package: "express", Version: "4.17.1", Severity: rank.Medium},
		{ID: "CVE-2025-00001", Package: "express", Version: "5.0.0", Severity: rank.Low},
	})
	r := newRankRun(t, policy.DefaultReview())
	rankAll(t, r, index,
		func() (depInfo, []candidateOutcome) {
			return fakeDependency("express", "4.17.1",
				fakeVersion{version: "4.21.2", published: longAgo},
				fakeVersion{version: "5.0.0", published: longAgo},
				fakeVersion{version: "5.1.0", published: longAgo})
		},
		func() (depInfo, []candidateOutcome) {
			return fakeDependency("lodash", "4.17.20", fakeVersion{version: "4.17.21", published: longAgo})
		})

	express := dependencyNamed(t, r, "express")
	if express.Best != "4.21.2" || express.Jump != "5.1.0" {
		t.Errorf("express Best, Jump = %q, %q, want 4.21.2 and 5.1.0, the outside candidate with fewer CVEs", express.Best, express.Jump)
	}
	lodash := dependencyNamed(t, r, "lodash")
	encoded, err := json.Marshal(lodash)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), `"jump"`) {
		t.Errorf("lodash has no version outside its line, so its result carries no jump: %s", encoded)
	}
}

func TestRankGroupsFamiliesFromPeers(t *testing.T) {
	r := newRankRun(t, policy.DefaultReview())
	rankAll(t, r, rank.Index{},
		func() (depInfo, []candidateOutcome) {
			return fakeDependency("react", "18.3.1", fakeVersion{version: "19.2.0", published: longAgo})
		},
		func() (depInfo, []candidateOutcome) {
			return fakeDependency("react-dom", "18.3.1",
				fakeVersion{version: "19.2.0", published: longAgo, peers: map[string]string{"react": "^19.2.0"}})
		},
		func() (depInfo, []candidateOutcome) {
			return fakeDependency("@types/react", "18.3.12", fakeVersion{version: "19.2.0", published: longAgo})
		},
		func() (depInfo, []candidateOutcome) {
			return fakeDependency("express", "4.17.1", fakeVersion{version: "5.1.0", published: longAgo})
		})

	want := []Family{{Name: "react 19", Members: []string{"@types/react", "react", "react-dom"}}}
	if !slices.EqualFunc(r.result.Families, want, func(a, b Family) bool {
		return a.Name == b.Name && slices.Equal(a.Members, b.Members)
	}) {
		t.Errorf("Families = %+v, want %+v", r.result.Families, want)
	}
	for _, name := range []string{"react", "react-dom", "@types/react"} {
		if got := dependencyNamed(t, r, name).Family; got != "react 19" {
			t.Errorf("%s Family = %q, want react 19", name, got)
		}
	}
	if got := dependencyNamed(t, r, "express"); got.Jump != "5.1.0" || got.Family != "" {
		t.Errorf("express Jump, Family = %q, %q, want a lone jump to 5.1.0", got.Jump, got.Family)
	}
}

// A package listed in both dependencies and devDependencies reaches the
// rank step twice under one name; the family must still see the peers of
// the entry whose jump declares them.
func TestRankKeepsThePeersOfADependencyListedTwice(t *testing.T) {
	r := newRankRun(t, policy.DefaultReview())
	react, _ := fakeDependency("react", "18.3.1", fakeVersion{version: "19.2.0", published: longAgo})
	reactDOM, _ := fakeDependency("react-dom", "18.3.1",
		fakeVersion{version: "19.2.0", published: longAgo, peers: map[string]string{"react": "^19.2.0"}},
		fakeVersion{version: "20.0.0", published: longAgo})
	devReactDOM := reactDOM
	devReactDOM.dep.Version = "19.2.0"
	r.result.Dependencies = []DependencyResult{
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "19.2.0", Jump: "20.0.0"},
	}

	r.setFamilies([]depInfo{react, reactDOM, devReactDOM})

	if len(r.result.Families) != 1 || r.result.Families[0].Name != "react 19" {
		t.Fatalf("Families = %+v, want the react 19 family", r.result.Families)
	}
	if got := r.result.Dependencies[1].Family; got != "react 19" {
		t.Errorf("react-dom 18.3.1 Family = %q, want react 19", got)
	}
	if got := r.result.Dependencies[2].Family; got != "" {
		t.Errorf("react-dom 19.2.0 jumps to 20.0.0, outside the family, but Family = %q", got)
	}
}

// The second entry of a name jumps elsewhere: its jump's peers say nothing
// about the first entry's jump, so the first must not join a family by them.
func TestRankKeepsADuplicateJumpsPeersToItself(t *testing.T) {
	r := newRankRun(t, policy.DefaultReview())
	react, _ := fakeDependency("react", "18.3.1", fakeVersion{version: "19.2.0", published: longAgo})
	reactDOM, _ := fakeDependency("react-dom", "18.3.1",
		fakeVersion{version: "19.2.0", published: longAgo},
		fakeVersion{version: "20.0.0", published: longAgo, peers: map[string]string{"react": "^19.2.0"}})
	devReactDOM := reactDOM
	devReactDOM.dep.Version = "19.2.0"
	r.result.Dependencies = []DependencyResult{
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "19.2.0", Jump: "20.0.0"},
	}

	r.setFamilies([]depInfo{react, reactDOM, devReactDOM})

	if len(r.result.Families) != 0 {
		t.Errorf("Families = %+v, want none: react-dom 19.2.0 declares no peer", r.result.Families)
	}
	for _, d := range r.result.Dependencies {
		if d.Family != "" {
			t.Errorf("%s %s Family = %q, want none", d.Name, d.Current, d.Family)
		}
	}
}

func TestRankKeepsEachCVEsPackageAndFix(t *testing.T) {
	index := rank.NewIndex([]rank.Finding{
		{ID: "CVE-2024-29041", Package: "express", Version: "4.17.1", Severity: rank.High, FixedVersion: "4.19.2, 5.0.0"},
		{ID: "CVE-2022-37620", Package: "html-minifier", Version: "4.0.0", Severity: rank.Medium},
	})
	r := newRankRun(t, policy.DefaultReview())
	d, outcomes := fakeDependency("express", "4.17.1")
	outcomes[0].pkgs = append(outcomes[0].pkgs, npm.LockPackage{Name: "html-minifier", Version: "4.0.0"})
	if err := r.stepRank([]depInfo{d}, outcomes, index); err != nil {
		t.Fatalf("stepRank: %v", err)
	}

	want := []CVE{
		{ID: "CVE-2024-29041", Severity: "HIGH", Package: "express@4.17.1", FixedIn: "4.19.2, 5.0.0"},
		{ID: "CVE-2022-37620", Severity: "MEDIUM", Package: "html-minifier@4.0.0", FixedIn: ""},
	}
	if got := dependencyNamed(t, r, "express").CVEs; !slices.Equal(got, want) {
		t.Errorf("CVEs = %+v, want %+v", got, want)
	}
	encoded, err := json.Marshal(want[1])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"fixedIn":""`) {
		t.Errorf("a CVE with no known fix must say so with an empty fixedIn, an absent one means unknown: %s", encoded)
	}
}

// One id found in two packages keeps both, each with its own fix, while the
// vector counts it once: the copy nobody can fix must not hide behind the
// one that has a fix.
func TestRankKeepsEveryPackageACVEIsFoundIn(t *testing.T) {
	index := rank.NewIndex([]rank.Finding{
		{ID: "CVE-2021-23337", Package: "lodash", Version: "4.17.20", Severity: rank.High, FixedVersion: "4.17.21"},
		{ID: "CVE-2021-23337", Package: "lodash.template", Version: "4.5.0", Severity: rank.High},
	})
	r := newRankRun(t, policy.DefaultReview())
	d, outcomes := fakeDependency("lodash", "4.17.20", fakeVersion{version: "4.17.21", published: longAgo})
	for i := range outcomes {
		outcomes[i].pkgs = append(outcomes[i].pkgs, npm.LockPackage{Name: "lodash.template", Version: "4.5.0"})
	}
	if err := r.stepRank([]depInfo{d}, outcomes, index); err != nil {
		t.Fatalf("stepRank: %v", err)
	}

	got := dependencyNamed(t, r, "lodash")
	want := []CVE{
		{ID: "CVE-2021-23337", Severity: "HIGH", Package: "lodash@4.17.20", FixedIn: "4.17.21"},
		{ID: "CVE-2021-23337", Severity: "HIGH", Package: "lodash.template@4.5.0", FixedIn: ""},
	}
	if !slices.Equal(got.CVEs, want) {
		t.Errorf("CVEs = %+v, want %+v", got.CVEs, want)
	}
	if got.Vector != (Vector{0, 1, 0, 0, 0}) {
		t.Errorf("Vector = %v, want the id counted once", got.Vector)
	}
	if len(got.Candidates) != 1 || !slices.Equal(got.Candidates[0].CVEs, want[1:]) {
		t.Errorf("4.17.21 = %+v, want it to keep the lodash.template copy with no fix", got.Candidates)
	}
}

func TestRankWritesAnEmptyFamiliesList(t *testing.T) {
	r := newRankRun(t, policy.DefaultReview())
	rankAll(t, r, rank.Index{}, func() (depInfo, []candidateOutcome) {
		return fakeDependency("lodash", "4.17.20", fakeVersion{version: "4.17.21", published: longAgo})
	})

	raw, err := os.ReadFile(filepath.Join(r.a.Dir, "candidates.json"))
	if err != nil {
		t.Fatalf("read candidates.json: %v", err)
	}
	var written map[string]json.RawMessage
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(written["families"]); got != "[]" {
		t.Errorf("families = %q, want []: a result without the key reads as one from an older release", got)
	}
}

func TestRankWritesAnAdvisoryForEveryCVEIdTheResultNames(t *testing.T) {
	data, err := os.ReadFile("../../rank/testdata/trivy-report.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	findings, err := rank.ReadTrivyJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("ReadTrivyJSON: %v", err)
	}
	r := newRankRun(t, policy.DefaultReview())
	express, expressOutcomes := fakeDependency("express", "4.17.1",
		fakeVersion{version: "4.19.2", published: longAgo},
		fakeVersion{version: "4.21.2", published: longAgo})
	expressOutcomes[0].pkgs = append(expressOutcomes[0].pkgs, npm.LockPackage{Name: "path-to-regexp", Version: "0.1.7"})
	lodash, lodashOutcomes := fakeDependency("lodash", "4.17.20", fakeVersion{version: "4.17.21", published: longAgo})
	if err := r.stepRank([]depInfo{express, lodash}, append(expressOutcomes, lodashOutcomes...), rank.NewIndex(findings)); err != nil {
		t.Fatalf("stepRank: %v", err)
	}

	named := map[string]bool{}
	for _, dr := range r.result.Dependencies {
		for _, c := range dr.CVEs {
			named[c.ID] = true
		}
		for _, cand := range dr.Candidates {
			for _, c := range cand.CVEs {
				named[c.ID] = true
			}
		}
	}
	if len(named) < 10 {
		t.Fatalf("the result names %d ids, want the fixture's express, path-to-regexp and lodash ids", len(named))
	}
	for id := range named {
		a, ok := r.result.Advisories[id]
		if !ok {
			t.Errorf("%s: the result names it, but the table holds no advisory", id)
			continue
		}
		if a.Title == "" || a.Published == "" || a.Summary != "" {
			t.Errorf("%s: advisory %+v, want a title and a date and no summary, as the fixture gives", id, a)
		}
	}
	for id := range r.result.Advisories {
		if !named[id] {
			t.Errorf("%s: the table holds an advisory the result never names", id)
		}
	}

	raw, err := os.ReadFile(filepath.Join(r.a.Dir, "candidates.json"))
	if err != nil {
		t.Fatalf("read candidates.json: %v", err)
	}
	var written Result
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(written.Advisories) != len(named) {
		t.Errorf("candidates.json holds %d advisories, want %d", len(written.Advisories), len(named))
	}
}

func TestAdvisoriesKeepTheFirstWordingInResultOrder(t *testing.T) {
	index := rank.NewIndex([]rank.Finding{
		{ID: "CVE-2026-00001", Package: "body-parser", Version: "1.19.0", Severity: rank.High, Title: "body-parser: the candidate's wording"},
		{ID: "CVE-2026-00001", Package: "express", Version: "4.17.1", Severity: rank.Low, Title: "express: the current version's wording"},
	})
	r := newRankRun(t, policy.DefaultReview())
	d, outcomes := fakeDependency("express", "4.17.1", fakeVersion{version: "4.18.0", published: longAgo})
	outcomes[1].pkgs = append(outcomes[1].pkgs, npm.LockPackage{Name: "body-parser", Version: "1.19.0"})
	if err := r.stepRank([]depInfo{d}, outcomes, index); err != nil {
		t.Fatalf("stepRank: %v", err)
	}

	if got := r.result.Advisories["CVE-2026-00001"].Title; got != "express: the current version's wording" {
		t.Errorf("title = %q, want the current version's wording, which the result lists first", got)
	}
}

func TestRankResultMarshalsAdvisoriesAsTheContractNamesThem(t *testing.T) {
	index := rank.NewIndex([]rank.Finding{{
		ID: "CVE-2025-58754", Package: "axios", Version: "1.7.9", Severity: rank.High,
		Title:       "axios: Axios DoS via lack of data size check",
		Description: "Axios decodes a data: URI into memory.",
		Published:   time.Date(2025, 9, 12, 2, 15, 46, 873_000_000, time.UTC),
	}})
	r := newRankRun(t, policy.DefaultReview())
	rankAll(t, r, index, func() (depInfo, []candidateOutcome) { return fakeDependency("axios", "1.7.9") })

	encoded, err := json.Marshal(r.result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `"advisories":{"CVE-2025-58754":{"title":"axios: Axios DoS via lack of data size check","summary":"Axios decodes a data: URI into memory.","published":"2025-09-12T02:15:46Z"}}`
	if !strings.Contains(string(encoded), want) {
		t.Errorf("result = %s, want it to hold %s", encoded, want)
	}

	clean := newRankRun(t, policy.DefaultReview())
	rankAll(t, clean, index, func() (depInfo, []candidateOutcome) { return fakeDependency("lodash", "4.17.21") })
	raw, err := os.ReadFile(filepath.Join(clean.a.Dir, "candidates.json"))
	if err != nil {
		t.Fatalf("read candidates.json: %v", err)
	}
	if strings.Contains(string(raw), `"advisories"`) {
		t.Errorf("a result that names no CVE carries no advisories key: %s", raw)
	}
}
