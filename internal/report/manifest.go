// Package report builds the files an export writes beside its archive:
// manifest.json, findings.csv and summary.md.
package report

import (
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// ManifestFormatVersion is the current schema version of manifest.json. It
// changes only when a field is added, removed or reinterpreted.
const ManifestFormatVersion = 2

// Manifest is the content of an export's manifest.json: what the archive
// holds and what it was built from.
type Manifest struct {
	FormatVersion int             `json:"formatVersion"`
	ToolVersion   string          `json:"toolVersion"`
	AnalysisID    string          `json:"analysisId"`
	CreatedAt     time.Time       `json:"createdAt"`
	Target        store.Target    `json:"target"`
	Archive       ArchiveManifest `json:"archive"`
	Packages      []PackageEntry  `json:"packages"`
}

// ArchiveManifest describes the archive file itself.
type ArchiveManifest struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// PackageEntry describes one tarball the archive carries.
type PackageEntry struct {
	Name                  string `json:"name"`
	Version               string `json:"version"`
	File                  string `json:"file"`
	OriginalIntegrity     string `json:"originalIntegrity"`
	ShippedSHA512         string `json:"shippedSha512"`
	PublishConfigStripped bool   `json:"publishConfigStripped"`
}

// PipManifestFormatVersion is the schema version of a pip export's
// manifest.json. The ecosystem field tells it apart from an npm manifest.
const PipManifestFormatVersion = 3

// PipManifest is the content of a pip export's manifest.json.
type PipManifest struct {
	FormatVersion int             `json:"formatVersion"`
	Ecosystem     store.Ecosystem `json:"ecosystem"`
	ToolVersion   string          `json:"toolVersion"`
	AnalysisID    string          `json:"analysisId"`
	CreatedAt     time.Time       `json:"createdAt"`
	Target        store.PipTarget `json:"target"`
	Archive       ArchiveManifest `json:"archive"`
	Packages      []WheelEntry    `json:"packages"`
}

// WheelEntry describes one wheel a pip archive carries: sha256 is the
// index's, shippedSha512 that of the same bytes.
type WheelEntry struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	File          string `json:"file"`
	SHA256        string `json:"sha256"`
	ShippedSHA512 string `json:"shippedSha512"`
}
