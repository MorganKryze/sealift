package rank

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/trivy-report.json: `trivy sbom --format json` (Trivy 0.72.0) on
// several versions of express, lodash, path-to-regexp and axios.
func loadFixtureIndex(t *testing.T) Index {
	t.Helper()
	f, err := os.Open("testdata/trivy-report.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	findings, err := ReadTrivyJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	return NewIndex(findings)
}

func TestIndexFixture(t *testing.T) {
	ix := loadFixtureIndex(t)
	for _, tc := range []struct {
		keys    []string
		wantIDs []string
		vector  Vector
	}{
		{[]string{"express@4.17.1"}, []string{"CVE-2024-29041", "CVE-2024-43796"}, Vector{0, 0, 1, 1, 0}},
		{[]string{"express@4.19.2"}, []string{"CVE-2024-43796"}, Vector{0, 0, 0, 1, 0}},
		{[]string{"express@4.21.2"}, nil, Vector{}},
		{[]string{"lodash@4.17.20"}, nil, Vector{0, 2, 3, 0, 0}},
		{[]string{"express@4.17.1", "path-to-regexp@0.1.7"}, nil, Vector{0, 3, 1, 1, 0}},
	} {
		set := ix.Set(tc.keys)
		if got := VectorOf(set); got != tc.vector {
			t.Errorf("%v: vector %v, want %v", tc.keys, got, tc.vector)
		}
		if tc.wantIDs != nil {
			var ids []string
			for id := range set {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tc.wantIDs) {
				t.Errorf("%v: IDs %v, want %v", tc.keys, ids, tc.wantIDs)
			}
		}
	}
}

func TestSetKeepsMostSeriousSeverity(t *testing.T) {
	ix := NewIndex([]Finding{
		{ID: "CVE-1", Package: "a", Version: "1.0.0", Severity: Low},
		{ID: "CVE-1", Package: "b", Version: "1.0.0", Severity: High},
	})
	if got := ix.Set([]string{"a@1.0.0", "b@1.0.0"})["CVE-1"].Severity; got != High {
		t.Errorf("severity = %v, want high", got)
	}
}

func TestVectorCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b Vector
		want int
	}{
		{Vector{0, 0, 0, 0, 0}, Vector{0, 0, 0, 0, 1}, -1},
		{Vector{1, 0, 0, 0, 0}, Vector{0, 9, 9, 9, 9}, 1},
		{Vector{0, 2, 1, 0, 0}, Vector{0, 2, 1, 0, 0}, 0},
	} {
		if got := tc.a.Compare(tc.b); got != tc.want {
			t.Errorf("%v.Compare(%v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestReadTrivyJSONRejectsWrongSchema(t *testing.T) {
	for _, body := range []string{`{"SchemaVersion": 99, "Results": []}`, `{}`} {
		if _, err := ReadTrivyJSON(strings.NewReader(body)); err == nil {
			t.Errorf("%s: want an error", body)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"CRITICAL": Critical, "high": High, "MEDIUM": Medium, "LOW": Low, "UNKNOWN": Unknown, "": Unknown} {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSeverityStringDoesNotPanicOutOfRange(t *testing.T) {
	if got := Severity(99).String(); got != "invalid" {
		t.Errorf("String() of an out-of-range severity = %q, want %q", got, "invalid")
	}
}

func TestSeverityMarshalText(t *testing.T) {
	for sev, want := range map[Severity]string{Critical: "CRITICAL", High: "HIGH", Medium: "MEDIUM", Low: "LOW", Unknown: "UNKNOWN"} {
		got, err := sev.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", sev, err)
		}
		if string(got) != want {
			t.Errorf("MarshalText(%v) = %q, want %q", sev, got, want)
		}
	}
	if _, err := Severity(99).MarshalText(); err == nil {
		t.Error("MarshalText of an out-of-range severity: want an error, got nil")
	}
}
