package rank

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSignals(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	policy := Policy{Now: now, MinReleaseAge: 7 * 24 * time.Hour, TargetNode: "22.17.1"}
	current := Facts{Version: "4.21.2", HasProvenance: true, Publisher: "alice"}
	clean := Facts{Version: "4.22.0", Published: now.AddDate(0, 0, -30), NodeCompatible: true, Resolves: true, HasProvenance: true, Publisher: "alice"}

	if hits := Signals(current, clean, policy); len(hits) != 0 {
		t.Fatalf("clean candidate got %v", hits)
	}

	risky := Facts{
		Version:          "5.0.0",
		Published:        now.AddDate(0, 0, -2),
		Deprecated:       "use 5.0.1",
		NodeRange:        ">=24",
		HasInstallScript: true,
		Publisher:        "mallory",
	}
	var got []string
	for _, h := range Signals(current, risky, policy) {
		got = append(got, fmt.Sprintf("%s|%t|%s", h.Signal, h.Signal.Blocking(), h.Evidence))
	}
	want := []string{
		"too-recent|true|published on 2026-09-15, 2 days ago; the minimum is 7 days",
		`node-mismatch|true|engines.node ">=24" excludes Node 22.17.1`,
		"does-not-resolve|true|pnpm could not resolve this version with the project's peer dependencies",
		"deprecated|true|use 5.0.1",
		"install-script-added|false|runs an install script; 4.21.2 does not",
		"provenance-lost|false|4.21.2 has a provenance attestation; this version has none",
		"publisher-changed|false|published by mallory; 4.21.2 was published by alice",
		"major-jump|false|leaves major version 4",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("signals:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSignalsMissingPublishedIsTooRecent(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	policy := Policy{Now: now, MinReleaseAge: 7 * 24 * time.Hour, TargetNode: "22.17.1"}
	current := Facts{Version: "4.21.2", HasProvenance: true, Publisher: "alice"}
	clean := Facts{Version: "4.22.0", Published: now.AddDate(0, 0, -30), NodeCompatible: true, Resolves: true, HasProvenance: true, Publisher: "alice"}
	unpublished := clean
	unpublished.Published = time.Time{}

	hits := Signals(current, unpublished, policy)
	want := []Hit{{TooRecent, "the registry lists no publication time"}}
	if !slices.Equal(hits, want) {
		t.Errorf("hits = %v, want %v", hits, want)
	}
}

func TestJumpOf(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     Jump
	}{
		{"4.21.2", "4.21.9", SameMinor},
		{"4.21.2", "4.22.0", SameMajor},
		{"4.21.2", "5.0.0", OtherMajor},
		{"4.21.2", "latest", OtherMajor},
	} {
		if got := JumpOf(tc.from, tc.to); got != tc.want {
			t.Errorf("JumpOf(%s, %s) = %d, want %d", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestBest(t *testing.T) {
	blocked := []Hit{{Signal: TooRecent}}
	for _, tc := range []struct {
		name       string
		current    Vector
		candidates []Candidate
		want       string // "" for no best candidate
	}{
		{
			name:    "fewest vulnerabilities wins",
			current: Vector{0, 1, 0, 0, 0},
			candidates: []Candidate{
				{Version: "4.22.0", Vector: Vector{0, 0, 1, 0, 0}},
				{Version: "4.23.0", Vector: Vector{0, 0, 0, 0, 0}},
			},
			want: "4.23.0",
		},
		{
			name:    "tie goes to the smallest jump",
			current: Vector{0, 1, 0, 0, 0},
			candidates: []Candidate{
				{Version: "5.0.0", Vector: Vector{}},
				{Version: "4.22.0", Vector: Vector{}},
				{Version: "4.21.5", Vector: Vector{}},
			},
			want: "4.21.5",
		},
		{
			name:    "then to the lower version",
			current: Vector{0, 1, 0, 0, 0},
			candidates: []Candidate{
				{Version: "4.23.0", Vector: Vector{}},
				{Version: "4.22.0", Vector: Vector{}},
			},
			want: "4.22.0",
		},
		{
			name:    "blocked candidates never win",
			current: Vector{0, 1, 0, 0, 0},
			candidates: []Candidate{
				{Version: "4.21.5", Vector: Vector{}, Hits: blocked},
				{Version: "4.22.0", Vector: Vector{0, 0, 0, 1, 0}},
			},
			want: "4.22.0",
		},
		{
			name:       "no improvement, no best",
			current:    Vector{0, 0, 0, 1, 0},
			candidates: []Candidate{{Version: "4.22.0", Vector: Vector{0, 0, 0, 1, 0}}},
		},
		{
			name:       "everything blocked",
			current:    Vector{1, 0, 0, 0, 0},
			candidates: []Candidate{{Version: "4.22.0", Hits: blocked}},
		},
	} {
		best, ok := Best("4.21.2", tc.current, tc.candidates)
		if tc.want == "" {
			if ok {
				t.Errorf("%s: got %s, want none", tc.name, best.Version)
			}
			continue
		}
		if !ok || best.Version != tc.want {
			t.Errorf("%s: got %q (%v), want %s", tc.name, best.Version, ok, tc.want)
		}
	}
}

func TestKeyVersions(t *testing.T) {
	newer := []string{"4.21.3", "4.22.0", "4.22.1", "4.22.3", "5.0.0", "5.2.1"}
	got := KeyVersions("4.21.2", newer, []string{"4.22.1, 5.0.0-beta.3", "not-a-version"})
	if want := []string{"4.22.1", "5.0.0", "4.21.3", "4.22.3", "5.2.1"}; !slices.Equal(got, want) {
		t.Errorf("KeyVersions = %v, want %v", got, want)
	}
	if got := KeyVersions("1.0.0", nil, nil); len(got) != 0 {
		t.Errorf("no newer versions: got %v", got)
	}
}

func TestDiff(t *testing.T) {
	before := map[string]Finding{"CVE-A": {ID: "CVE-A", Version: "1.0.0"}, "CVE-B": {ID: "CVE-B", Version: "1.0.0"}}
	after := map[string]Finding{"CVE-B": {ID: "CVE-B", Version: "2.0.0"}, "CVE-C": {ID: "CVE-C", Version: "2.0.0"}}
	var got []string
	for _, c := range Diff(before, after) {
		got = append(got, c.Finding.ID+" "+string(c.Status)+" "+c.Finding.Version)
	}
	if want := []string{"CVE-A fixed 1.0.0", "CVE-B remaining 2.0.0", "CVE-C introduced 2.0.0"}; !slices.Equal(got, want) {
		t.Errorf("Diff = %v, want %v", got, want)
	}
}
