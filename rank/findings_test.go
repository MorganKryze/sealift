package rank

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
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

func TestReadTrivyJSONKeepsDescriptionAndPublishedDate(t *testing.T) {
	const body = `{"SchemaVersion": 2, "Results": [{"Vulnerabilities": [
		{"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1.0.0", "Severity": "HIGH",
		 "Title": "a: one", "Description": "First line.\n\nSecond \u2060 part.", "PublishedDate": "2026-02-09T21:15:49.01Z"},
		{"VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "2.0.0", "Severity": "LOW",
		 "Title": "b: two", "PublishedDate": "not a date"},
		{"VulnerabilityID": "CVE-3", "PkgName": "c", "InstalledVersion": "3.0.0", "Severity": "MEDIUM"}
	]}]}`
	findings, err := ReadTrivyJSON(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	first := findings[0]
	if first.Description != "First line.\n\nSecond \u2060 part." {
		t.Errorf("description = %q, want it byte for byte", first.Description)
	}
	want := time.Date(2026, 2, 9, 21, 15, 49, 10_000_000, time.UTC)
	if !first.Published.Equal(want) || first.Published.Location() != time.UTC {
		t.Errorf("published = %v, want %v in UTC", first.Published, want)
	}
	for _, f := range findings[1:] {
		if !f.Published.IsZero() {
			t.Errorf("%s: published = %v, want zero", f.ID, f.Published)
		}
		if f.Description != "" {
			t.Errorf("%s: description = %q, want empty", f.ID, f.Description)
		}
	}
	if findings[1].Title != "b: two" || findings[1].Severity != Low || findings[2].Severity != Medium {
		t.Errorf("rest of the report misread: %+v", findings[1:])
	}
}

func TestReadTrivyJSONLeavesOutADateOutsideYearsOneTo9999InUTC(t *testing.T) {
	// RFC 3339 writes a year in four digits, so a date past either end in
	// UTC could be read here and then never answered as a date.
	for _, c := range []struct {
		date string
		want time.Time
	}{
		{"0000-01-01T00:00:00+01:00", time.Time{}},
		{"0000-06-15T12:00:00Z", time.Time{}},
		{"0001-01-01T00:30:00+01:00", time.Time{}},
		{"0001-01-01T00:00:01Z", time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC)},
		{"9999-12-31T23:59:59Z", time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"9999-12-31T23:30:00-01:00", time.Time{}},
	} {
		body := `{"SchemaVersion": 2, "Results": [{"Vulnerabilities": [
			{"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1.0.0", "Severity": "HIGH",
			 "Title": "a: one", "PublishedDate": "` + c.date + `"}]}]}`
		findings, err := ReadTrivyJSON(strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", c.date, err)
		}
		if len(findings) != 1 || findings[0].Title != "a: one" {
			t.Fatalf("%s: findings = %+v, want the one finding read", c.date, findings)
		}
		if got := findings[0].Published; !got.Equal(c.want) || got.Location() != time.UTC {
			t.Errorf("%s: published = %v, want %v in UTC", c.date, got, c.want)
		}
	}
}
