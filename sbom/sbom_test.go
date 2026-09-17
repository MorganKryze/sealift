package sbom_test

import (
	"os"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/sbom"
)

func TestPURL(t *testing.T) {
	for _, tc := range []struct{ name, version, want string }{
		{"express", "4.21.2", "pkg:npm/express@4.21.2"},
		{"@esbuild/linux-x64", "0.25.0", "pkg:npm/%40esbuild/linux-x64@0.25.0"},
	} {
		if got := sbom.PURL(tc.name, tc.version); got != tc.want {
			t.Errorf("PURL(%s, %s) = %s, want %s", tc.name, tc.version, got, tc.want)
		}
	}
}

func TestWriteCycloneDXSortsAndDedupes(t *testing.T) {
	var b strings.Builder
	err := sbom.WriteCycloneDX(&b, []sbom.Component{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "express", Version: "4.21.2"},
		{Name: "lodash", Version: "4.17.21"},
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.21.2",
      "name": "express",
      "version": "4.21.2",
      "purl": "pkg:npm/express@4.21.2"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21"
    }
  ]
}
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func ExampleWriteCycloneDX() {
	_ = sbom.WriteCycloneDX(os.Stdout, []sbom.Component{{Name: "@esbuild/linux-x64", Version: "0.25.0"}})
	// Output:
	// {
	//   "bomFormat": "CycloneDX",
	//   "specVersion": "1.6",
	//   "version": 1,
	//   "components": [
	//     {
	//       "type": "library",
	//       "bom-ref": "pkg:npm/%40esbuild/linux-x64@0.25.0",
	//       "name": "@esbuild/linux-x64",
	//       "version": "0.25.0",
	//       "purl": "pkg:npm/%40esbuild/linux-x64@0.25.0"
	//     }
	//   ]
	// }
}
