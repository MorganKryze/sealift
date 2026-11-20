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
	for _, c := range sorted {
		purl, err := purlOf(c)
		if err != nil {
			return err
		}
		doc.Components = append(doc.Components, component{Type: "library", BOMRef: purl, Name: c.Name, Version: c.Version, PURL: purl})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
