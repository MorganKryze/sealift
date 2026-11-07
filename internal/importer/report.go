package importer

import (
	"fmt"
	"io"
)

// The three outcomes of an import.
const (
	OutcomeComplete   = "complete"
	OutcomeIncomplete = "incomplete"
	OutcomeRefused    = "refused"
)

// Report is the account of one import run, as printed and as written to JSON.
type Report struct {
	Outcome       string      `json:"outcome"`
	Reason        string      `json:"reason"`
	Unencrypted   bool        `json:"unencrypted"`
	ImportVersion string      `json:"importVersion"`
	Archive       ArchiveInfo `json:"archive"`
	ToolVersion   string      `json:"toolVersion"`
	AnalysisID    string      `json:"analysisId"`
	Target        TargetInfo  `json:"target"`
	Nexus         NexusInfo   `json:"nexus"`
	Counts        Counts      `json:"counts"`
	Packages      []Result    `json:"packages"`
	// ArchiveChecked says whether the archive passed its checks against the
	// manifest and the signature key. It is nil only in a record written by
	// sealift 0.4.0 or earlier.
	ArchiveChecked *bool `json:"archiveChecked,omitempty"`
}

// ArchiveInfo names the archive and holds the digest and size its manifest declares.
type ArchiveInfo struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// TargetInfo is the platform the manifest says the packages were resolved for.
type TargetInfo struct {
	OS      string `json:"os"`
	CPU     string `json:"cpu"`
	Libc    string `json:"libc"`
	Node    string `json:"node"`
	PnpmVer string `json:"pnpmVer"`
}

// NexusInfo is the repository the import published to.
type NexusInfo struct {
	URL        string `json:"url"`
	Repository string `json:"repository"`
}

// Counts totals the packages by state.
type Counts struct {
	Published int `json:"published"`
	Present   int `json:"present"`
	Failed    int `json:"failed"`
}

// ExitCode is 0 for a complete import, 1 for an incomplete one and 3 for a
// refused archive. 2 is left to usage and settings errors.
func (r Report) ExitCode() int {
	switch r.Outcome {
	case OutcomeComplete:
		return 0
	case OutcomeIncomplete:
		return 1
	default:
		return 3
	}
}

// WriteText prints the report for a person: a summary line, the archive, the
// import's own version, the manifest and the Nexus repository, then one line
// per package with its file.
func (r Report) WriteText(w io.Writer) error {
	mark := ""
	if r.Unencrypted {
		mark = " (unencrypted)"
	}
	p := &printer{w: w}
	p.linef("import %s%s: %d published, %d present, %d failed", r.Outcome, mark, r.Counts.Published, r.Counts.Present, r.Counts.Failed)
	if r.Unencrypted {
		p.linef("warning: the connection to nexus is not encrypted")
	}
	if r.Reason != "" {
		p.linef("reason: %s", r.Reason)
	}
	archive := "archive: " + r.Archive.File
	if r.Archive.SHA256 != "" {
		archive += fmt.Sprintf(", sha256 %s, %d bytes", r.Archive.SHA256, r.Archive.Size)
	}
	p.linef("%s", archive)
	p.linef("import version: %s", r.ImportVersion)
	if r.ToolVersion != "" || r.AnalysisID != "" {
		t := r.Target
		p.linef("manifest: sealift %s, analysis %s, target %s %s %s, node %s, pnpm %s", r.ToolVersion, r.AnalysisID, t.OS, t.CPU, t.Libc, t.Node, t.PnpmVer)
	}
	p.linef("nexus: %s, repository %s", r.Nexus.URL, r.Nexus.Repository)
	for _, pkg := range r.Packages {
		line := fmt.Sprintf("%s@%s %s %s", pkg.Name, pkg.Version, pkg.State, pkg.File)
		if pkg.Reason != "" {
			line += ": " + pkg.Reason
		}
		if pkg.Note != "" {
			line += " (" + pkg.Note + ")"
		}
		p.linef("%s", line)
	}
	return p.err
}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) linef(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
	}
}
