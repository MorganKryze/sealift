package sbom_test

import (
	"os"
	"slices"
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

func TestPyPIPURL(t *testing.T) {
	for _, tc := range []struct{ name, version, want string }{
		{"jinja2", "3.1.2", "pkg:pypi/jinja2@3.1.2"},
		{"Mypy_Extensions", "1.0.0", "pkg:pypi/mypy-extensions@1.0.0"},
		{"zope.interface", "7.1.1", "pkg:pypi/zope-interface@7.1.1"},
	} {
		if got := sbom.PyPIPURL(tc.name, tc.version); got != tc.want {
			t.Errorf("PyPIPURL(%s, %s) = %s, want %s", tc.name, tc.version, got, tc.want)
		}
	}
}

// npmDocument is the document WriteCycloneDX wrote for npm packages before
// components had a type, byte for byte.
const npmDocument = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/%40esbuild/linux-x64@0.25.0",
      "name": "@esbuild/linux-x64",
      "version": "0.25.0",
      "purl": "pkg:npm/%40esbuild/linux-x64@0.25.0"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.21.2",
      "name": "express",
      "version": "4.21.2",
      "purl": "pkg:npm/express@4.21.2"
    }
  ]
}
`

func TestWriteCycloneDXKeepsNPMOutput(t *testing.T) {
	for _, typ := range []string{"", "npm"} {
		var b strings.Builder
		err := sbom.WriteCycloneDX(&b, []sbom.Component{
			{Name: "express", Version: "4.21.2", Type: typ},
			{Name: "@esbuild/linux-x64", Version: "0.25.0", Type: typ},
			{Name: "express", Version: "4.21.2", Type: "npm"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if b.String() != npmDocument {
			t.Errorf("type %q: got:\n%s\nwant:\n%s", typ, b.String(), npmDocument)
		}
	}
}

func TestWriteCycloneDXWritesPyPIComponents(t *testing.T) {
	var b strings.Builder
	if err := sbom.WriteCycloneDX(&b, []sbom.Component{{Name: "Jinja2", Version: "3.1.2", Type: "pypi"}}); err != nil {
		t.Fatal(err)
	}
	const want = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:pypi/jinja2@3.1.2",
      "name": "Jinja2",
      "version": "3.1.2",
      "purl": "pkg:pypi/jinja2@3.1.2"
    }
  ]
}
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestPyPIComponents(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		want          []string
	}{
		{"jinja2", "3.1.2", []string{"jinja2"}},
		{"Jinja2", "3.1.2", []string{"jinja2"}},
		{"plone-namedfile", "5.0.0", []string{"plone-namedfile", "plone.namedfile"}},
		{"plone.namedfile", "5.0.0", []string{"plone-namedfile", "plone.namedfile"}},
		{"Mypy_Extensions", "1.0.0", []string{"mypy-extensions", "mypy.extensions"}},
		{"zope.interface-ext", "1.0.0", []string{"zope-interface-ext", "zope.interface.ext"}},
	} {
		got := sbom.PyPIComponents(tc.name, tc.version)
		var names []string
		for _, c := range got {
			names = append(names, c.Name)
			if c.Version != tc.version || c.Type != "pypi" {
				t.Errorf("PyPIComponents(%s, %s) holds %+v, want version %s and type pypi", tc.name, tc.version, c, tc.version)
			}
		}
		if !slices.Equal(names, tc.want) {
			t.Errorf("PyPIComponents(%s, %s) names = %v, want %v", tc.name, tc.version, names, tc.want)
		}
	}
}

func TestWriteCycloneDXKeepsBOMRefsUnique(t *testing.T) {
	var b strings.Builder
	if err := sbom.WriteCycloneDX(&b, sbom.PyPIComponents("plone.namedfile", "5.0.0")); err != nil {
		t.Fatal(err)
	}
	const want = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:pypi/plone-namedfile@5.0.0",
      "name": "plone-namedfile",
      "version": "5.0.0",
      "purl": "pkg:pypi/plone-namedfile@5.0.0"
    },
    {
      "type": "library",
      "bom-ref": "plone.namedfile@5.0.0",
      "name": "plone.namedfile",
      "version": "5.0.0",
      "purl": "pkg:pypi/plone-namedfile@5.0.0"
    }
  ]
}
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestWriteCycloneDXRefusesAnUnknownType(t *testing.T) {
	var b strings.Builder
	err := sbom.WriteCycloneDX(&b, []sbom.Component{{Name: "serde", Version: "1.0.0", Type: "cargo"}})
	if err == nil || !strings.Contains(err.Error(), `unknown purl type "cargo"`) {
		t.Fatalf("WriteCycloneDX = %v, want the unknown type refused", err)
	}
	if b.Len() != 0 {
		t.Errorf("wrote %q before refusing", b.String())
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
