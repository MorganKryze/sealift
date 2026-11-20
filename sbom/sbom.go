// Package sbom writes CycloneDX software bills of materials for npm and
// PyPI packages.
package sbom

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/MorganKryze/sealift/pip"
)

// Component is one package version.
type Component struct {
	Name, Version string
	Type          string // purl type: empty or "npm", or "pypi"
}

// PURL returns the package URL of an npm package, such as
// pkg:npm/express@4.21.2 or pkg:npm/%40esbuild/linux-x64@0.25.0.
func PURL(name, version string) string {
	if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return "pkg:npm/%40" + scope[1:] + "/" + rest + "@" + version
	}
	return "pkg:npm/" + name + "@" + version
}

// PyPIPURL returns the package URL of a PyPI package, with its name
// normalized as the index does, such as pkg:pypi/mypy-extensions@1.0.0.
func PyPIPURL(name, version string) string {
	return "pkg:pypi/" + pip.Normalize(name) + "@" + version
}

// PyPIComponents returns the components that stand for one PyPI package in
// an SBOM Trivy scans: the normalized name and, when that name holds a
// hyphen, a second spelling with dots. Trivy matches a PyPI package on
// its component name and folds case and underscores but not dots, so a
// project published as plone.namedfile matches only under that spelling.
// A published name that mixes dots with hyphens or underscores, such as
// a.b-c, matches under neither spelling.
func PyPIComponents(name, version string) []Component {
	name = pip.Normalize(name)
	components := []Component{{Name: name, Version: version, Type: "pypi"}}
	if strings.Contains(name, "-") {
		components = append(components, Component{Name: strings.ReplaceAll(name, "-", "."), Version: version, Type: "pypi"})
	}
	return components
}

// purlOf returns c's package URL. An unknown type is an error: a purl
// Trivy cannot match would read as a package with no known CVE.
func purlOf(c Component) (string, error) {
	switch c.Type {
	case "npm":
		return PURL(c.Name, c.Version), nil
	case "pypi":
		return PyPIPURL(c.Name, c.Version), nil
	}
	return "", fmt.Errorf("sbom: unknown purl type %q for %s@%s", c.Type, c.Name, c.Version)
}

type document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Components  []component `json:"components"`
}

type component struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// WriteCycloneDX writes a CycloneDX 1.6 JSON document listing each component
// once, sorted by name, then version, then type. `trivy sbom` scans the
// result.
func WriteCycloneDX(w io.Writer, components []Component) error {
	sorted := slices.Clone(components)
	for i := range sorted {
		if sorted[i].Type == "" {
			sorted[i].Type = "npm"
		}
	}
	slices.SortFunc(sorted, func(a, b Component) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version), strings.Compare(a.Type, b.Type))
	})
	sorted = slices.Compact(sorted)

	doc := document{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1, Components: make([]component, 0, len(sorted))}
	refs := map[string]bool{}
	for _, c := range sorted {
		purl, err := purlOf(c)
		if err != nil {
			return err
		}
		ref := purl
		if refs[purl] {
			// CycloneDX wants each bom-ref unique, and the spellings of one
			// PyPI project share a purl.
			ref = c.Name + "@" + c.Version
		}
		refs[purl] = true
		doc.Components = append(doc.Components, component{Type: "library", BOMRef: ref, Name: c.Name, Version: c.Version, PURL: purl})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
