package runner

import "context"

// Trivy scans a CycloneDX document for known vulnerabilities, converts a
// scan report to CycloneDX, and refreshes the vulnerability database.
type Trivy interface {
	// ScanSBOM scans the CycloneDX document at sbomPath and writes a JSON
	// report to outPath. It returns the combined output.
	ScanSBOM(ctx context.Context, sbomPath, outPath string) (string, error)
	// ConvertToCycloneDX converts the JSON report at reportPath into a
	// CycloneDX document at outPath. It returns the combined output.
	ConvertToCycloneDX(ctx context.Context, reportPath, outPath string) (string, error)
	// UpdateDB downloads the vulnerability database. It returns the
	// combined output.
	UpdateDB(ctx context.Context) (string, error)
}

// TrivyCLI runs the trivy binary.
type TrivyCLI struct {
	bin      string
	cacheDir string
	asUser   *Credential
}

// NewTrivyCLI builds a TrivyCLI that runs bin with its vulnerability
// database cache under cacheDir. asUser is nil outside the container.
func NewTrivyCLI(bin, cacheDir string, asUser *Credential) *TrivyCLI {
	return &TrivyCLI{bin: bin, cacheDir: cacheDir, asUser: asUser}
}

// ScanSBOM scans the CycloneDX document at sbomPath and writes a JSON
// report to outPath. It skips a database download: the caller refreshes
// the database once per job, not once per scan.
func (c *TrivyCLI) ScanSBOM(ctx context.Context, sbomPath, outPath string) (string, error) {
	return run(ctx, "", c.bin, []string{
		"sbom", sbomPath,
		"--format", "json",
		"--skip-db-update",
		"--output", outPath,
		"--cache-dir", c.cacheDir,
	}, c.asUser)
}

// ConvertToCycloneDX converts the JSON report at reportPath into a
// CycloneDX document at outPath. convert reads an existing report and
// touches no database, but --cache-dir is a global trivy flag that
// defaults to a path under HOME regardless of the subcommand; passing it
// explicitly, as ScanSBOM already does, keeps this from depending on
// HOME being set to something the caller can write.
func (c *TrivyCLI) ConvertToCycloneDX(ctx context.Context, reportPath, outPath string) (string, error) {
	return run(ctx, "", c.bin, []string{
		"convert",
		"--format", "cyclonedx",
		"--cache-dir", c.cacheDir,
		"--output", outPath,
		reportPath,
	}, c.asUser)
}

// UpdateDB downloads the vulnerability database only, without scanning
// anything.
func (c *TrivyCLI) UpdateDB(ctx context.Context) (string, error) {
	return run(ctx, "", c.bin, []string{
		"image",
		"--download-db-only",
		"--cache-dir", c.cacheDir,
	}, c.asUser)
}
