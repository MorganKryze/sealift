// Package sbom writes CycloneDX software bills of materials for npm packages.
package sbom

import (
	"cmp"
	"encoding/json"
	"io"
	"slices"
	"strings"
)

// Component is one npm package version.
type Component struct {
	Name    string
	Version string
}

// PURL returns the package URL of an npm package, such as
// pkg:npm/express@4.21.2 or pkg:npm/%40esbuild/linux-x64@0.25.0.
func PURL(name, version string) string {
	if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return "pkg:npm/%40" + scope[1:] + "/" + rest + "@" + version
	}
	return "pkg:npm/" + name + "@" + version
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
// once, sorted by name, then version. `trivy sbom` scans the result.
func WriteCycloneDX(w io.Writer, components []Component) error {
	sorted := slices.Clone(components)
	slices.SortFunc(sorted, func(a, b Component) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version))
	})
	sorted = slices.Compact(sorted)

	doc := document{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1, Components: make([]component, 0, len(sorted))}
	for _, c := range sorted {
		purl := PURL(c.Name, c.Version)
		doc.Components = append(doc.Components, component{Type: "library", BOMRef: purl, Name: c.Name, Version: c.Version, PURL: purl})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
