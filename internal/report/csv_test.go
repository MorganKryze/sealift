package report

import (
	"bytes"
	"testing"

	"github.com/MorganKryze/sealift/rank"
)

func TestFindingsRowsOnePerAffectedPackage(t *testing.T) {
	ix := rank.NewIndex([]rank.Finding{
		{ID: "CVE-OLD", Package: "widgets", Version: "1.0.0", Severity: rank.High, FixedVersion: "2.0.0", Title: "old bug"},
		{ID: "CVE-SHARED", Package: "shared", Version: "1.5.0", Severity: rank.Critical, Title: "shared bug"},
		{ID: "CVE-NEW", Package: "widgets", Version: "2.0.0", Severity: rank.Medium, Title: "new bug"},
		{ID: "CVE-NEW", Package: "extra", Version: "1.0.0", Severity: rank.Medium, Title: "new bug"},
	})

	deps := []DependencyResolution{
		{
			Name:            "widgets",
			CurrentVersion:  "1.0.0",
			SelectedVersion: "2.0.0",
			CurrentKeys:     []string{"widgets@1.0.0", "shared@1.5.0"},
			SelectedKeys:    []string{"widgets@2.0.0", "shared@1.5.0", "extra@1.0.0"},
		},
	}

	rows := FindingsRows(ix, deps)
	if len(rows) != 4 {
		t.Fatalf("len(rows) = %d, want 4: %+v", len(rows), rows)
	}

	var buf bytes.Buffer
	if err := WriteFindingsCSV(&buf, rows); err != nil {
		t.Fatal(err)
	}

	want := `dependency,current_version,selected_version,package,package_version,vulnerability_id,severity,status,fixed_version,title
widgets,1.0.0,2.0.0,extra,1.0.0,CVE-NEW,medium,introduced,,new bug
widgets,1.0.0,2.0.0,widgets,2.0.0,CVE-NEW,medium,introduced,,new bug
widgets,1.0.0,2.0.0,widgets,1.0.0,CVE-OLD,high,fixed,2.0.0,old bug
widgets,1.0.0,2.0.0,shared,1.5.0,CVE-SHARED,critical,remaining,,shared bug
`
	if buf.String() != want {
		t.Errorf("findings.csv =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestFindingsRowsNoChange(t *testing.T) {
	ix := rank.NewIndex(nil)
	rows := FindingsRows(ix, []DependencyResolution{
		{Name: "quiet", CurrentVersion: "1.0.0", SelectedVersion: "1.1.0", CurrentKeys: []string{"quiet@1.0.0"}, SelectedKeys: []string{"quiet@1.1.0"}},
	})
	if len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0", len(rows))
	}
}
