package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
	"github.com/MorganKryze/sealift/sbom"
)

// probeManifest is the package.json content of an isolated resolution: one
// dependency at the version being probed, plus the project's own pinned
// version of each of its peer dependencies that the project declares (spec
// section 4, "Candidate resolution").
type probeManifest struct {
	Name         string            `json:"name"`
	Private      bool              `json:"private"`
	Dependencies map[string]string `json:"dependencies"`
}

// buildProbeManifest builds the manifest for resolving depName at version
// in isolation. peerDeps is that version's own peerDependencies, from its
// packument; projectVersions maps every dependency the project declares to
// its own version. Only a peer the project itself declares gets pinned.
func buildProbeManifest(depName, version string, peerDeps, projectVersions map[string]string) []byte {
	deps := map[string]string{depName: version}
	for peer := range peerDeps {
		if v, ok := projectVersions[peer]; ok {
			deps[peer] = v
		}
	}
	return mustJSON(probeManifest{Name: "probe", Private: true, Dependencies: deps})
}

// buildFullManifest re-encodes manifest as a package.json, applying
// overrides to the versions of the named dependencies.
func buildFullManifest(manifest npm.Manifest, overrides map[string]string) []byte {
	deps := map[string]string{}
	devDeps := map[string]string{}
	optDeps := map[string]string{}
	for _, d := range manifest.Dependencies {
		version := d.Version
		if v, ok := overrides[d.Name]; ok && v != "" {
			version = v
		}
		switch d.Kind {
		case npm.Dev:
			devDeps[d.Name] = version
		case npm.Optional:
			optDeps[d.Name] = version
		default:
			deps[d.Name] = version
		}
	}
	doc := struct {
		Name                 string            `json:"name"`
		Private              bool              `json:"private"`
		Dependencies         map[string]string `json:"dependencies,omitempty"`
		DevDependencies      map[string]string `json:"devDependencies,omitempty"`
		OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	}{Name: "project", Private: true}
	if len(deps) > 0 {
		doc.Dependencies = deps
	}
	if len(devDeps) > 0 {
		doc.DevDependencies = devDeps
	}
	if len(optDeps) > 0 {
		doc.OptionalDependencies = optDeps
	}
	return mustJSON(doc)
}

// resolve runs one pnpm resolution in a fresh directory under the volume's
// cache and returns the raw lockfile bytes and pnpm's combined output.
func (a *Analysis) resolve(ctx context.Context, manifest []byte) ([]byte, string, error) {
	dir, err := a.Store.NewResolveDir()
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	res, err := a.Pnpm.Resolve(ctx, runner.ResolveInput{Dir: dir, Manifest: manifest, Target: a.Project.Target})
	if err != nil {
		return nil, res.Output, err
	}
	return res.Lockfile, res.Output, nil
}

// scanPackages writes pkgs as a CycloneDX SBOM and scans it with Trivy,
// writing the report to outPath and returning the findings it lists. An
// empty pkgs still produces a valid, empty report.
func (a *Analysis) scanPackages(ctx context.Context, pkgs []npm.LockPackage, outPath string) ([]rank.Finding, error) {
	sbomPath := outPath + ".cdx.json"
	defer os.Remove(sbomPath)

	f, err := os.Create(sbomPath)
	if err != nil {
		return nil, err
	}
	werr := sbom.WriteCycloneDX(f, componentsOf(pkgs))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, fmt.Errorf("write sbom: %w", werr)
	}

	if _, err := a.Trivy.ScanSBOM(ctx, sbomPath, outPath); err != nil {
		return nil, fmt.Errorf("trivy scan: %w", err)
	}

	report, err := os.Open(outPath)
	if err != nil {
		return nil, err
	}
	defer report.Close()
	return rank.ReadTrivyJSON(report)
}

func componentsOf(pkgs []npm.LockPackage) []sbom.Component {
	components := make([]sbom.Component, len(pkgs))
	for i, p := range pkgs {
		components[i] = sbom.Component{Name: p.Name, Version: p.Version}
	}
	return components
}

func keysOf(pkgs []npm.LockPackage) []string {
	keys := make([]string, len(pkgs))
	for i, p := range pkgs {
		keys[i] = p.Key()
	}
	return keys
}

func platformOf(t store.Target) npm.Platform {
	return npm.Platform{OS: t.OS, CPU: t.CPU, Libc: t.Libc}
}

// trivyReport is the subset of a Trivy JSON report mergeTrivyReports reads
// and writes: enough to concatenate two reports' results without touching
// the vulnerabilities themselves.
type trivyReport struct {
	SchemaVersion int               `json:"SchemaVersion"`
	Results       []json.RawMessage `json:"Results"`
}

// mergeTrivyReports concatenates the Results array of every report at
// paths into one report written to outPath.
func mergeTrivyReports(paths []string, outPath string) error {
	merged := trivyReport{SchemaVersion: 2}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		var report trivyReport
		if err := json.Unmarshal(data, &report); err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		merged.Results = append(merged.Results, report.Results...)
	}
	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0o664)
}

// factsOf builds rank.Facts for one packument version. Resolves is left at
// its zero value; the caller sets it once it knows whether step 6 resolved
// this version.
func factsOf(version string, meta npm.VersionMeta, pk npm.Packument, target store.Target) rank.Facts {
	published, _ := pk.Published(version)
	nodeRange := meta.Engines["node"]
	compatible, _ := npm.SatisfiesNode(nodeRange, target.Node)
	return rank.Facts{
		Version:          version,
		Published:        published,
		Deprecated:       string(meta.Deprecated),
		NodeRange:        nodeRange,
		NodeCompatible:   compatible,
		HasInstallScript: meta.HasInstallScript(),
		HasProvenance:    meta.HasProvenance(),
		Publisher:        meta.NPMUser.Name,
	}
}

// orderKeyFirst returns newer with every version in keys moved to the
// front, in the order KeyVersions gave them, keeping the rest ascending.
func orderKeyFirst(newer, keys []string) []string {
	ordered := make([]string, 0, len(newer))
	ordered = append(ordered, keys...)
	for _, v := range newer {
		if !slices.Contains(keys, v) {
			ordered = append(ordered, v)
		}
	}
	return ordered
}

func toSignals(hits []rank.Hit) []Signal {
	signals := make([]Signal, len(hits))
	for i, h := range hits {
		signals[i] = Signal{Name: string(h.Signal), Evidence: h.Evidence, Blocking: h.Signal.Blocking()}
	}
	return signals
}
