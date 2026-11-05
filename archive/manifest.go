package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/MorganKryze/sealift/npm"
)

// MaxManifestSize is the largest manifest.json ParseManifest reads: 16 MiB.
const MaxManifestSize = 16 << 20

// maxFileNameBytes is the longest package file name a manifest may list: 255 bytes.
const maxFileNameBytes = 255

// Manifest is what the import reads of an export's manifest.json. Fields this
// version does not know are ignored; formatVersion decides what is required.
type Manifest struct {
	FormatVersion int
	ToolVersion   string
	AnalysisID    string
	CreatedAt     string
	Target        Target
	Archive       Summary
	Packages      []Package
}

// Target is the platform and toolchain the packages were resolved for.
type Target struct {
	OS, CPU, Libc, Node, PnpmVer string
}

// Summary describes the archive file itself.
type Summary struct {
	SHA256 string
	Size   int64
}

// Package describes one tarball the archive carries.
type Package struct {
	Name, Version, File   string
	OriginalIntegrity     string
	ShippedSHA512         string
	PublishConfigStripped bool
}

// Refusal is the reason an archive or its manifest cannot be imported.
type Refusal struct {
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

func refuse(format string, args ...any) *Refusal {
	return &Refusal{Reason: fmt.Sprintf(format, args...)}
}

// packageFile is the shape of a tarball name under out/. The class holds what
// npm.PackFileName can produce from a valid name and an exact version.
var packageFile = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._~+-]*\.tgz$`)

var (
	hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexSHA512 = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// rawManifest keeps a missing field apart from a zero one.
type rawManifest struct {
	FormatVersion *int       `json:"formatVersion"`
	ToolVersion   string     `json:"toolVersion"`
	AnalysisID    string     `json:"analysisId"`
	CreatedAt     string     `json:"createdAt"`
	Target        *rawTarget `json:"target"`
	Archive       *struct {
		SHA256 string `json:"sha256"`
		Size   *int64 `json:"size"`
	} `json:"archive"`
	Packages []rawPackage `json:"packages"`
}

type rawPackage struct {
	Name                  string `json:"name"`
	Version               string `json:"version"`
	File                  string `json:"file"`
	OriginalIntegrity     string `json:"originalIntegrity"`
	ShippedSHA512         string `json:"shippedSha512"`
	PublishConfigStripped *bool  `json:"publishConfigStripped"`
}

// rawTarget maps the JSON names of a target, which differ from the Go names.
type rawTarget struct {
	OS      string `json:"os"`
	CPU     string `json:"cpu"`
	Libc    string `json:"libc"`
	Node    string `json:"node"`
	PnpmVer string `json:"pnpmVer"`
}

// ParseManifest reads and checks a manifest.json. Any problem comes back as a
// *Refusal.
func ParseManifest(r io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxManifestSize+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read the manifest: %w", err)
	}
	if len(data) > MaxManifestSize {
		return Manifest{}, refuse("the manifest is larger than %d bytes", MaxManifestSize)
	}
	var doc rawManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return Manifest{}, refuse("the manifest is not valid JSON: %s", jsonProblem(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Manifest{}, refuse("the manifest holds data after the manifest")
	}
	return checkManifest(doc)
}

func checkManifest(raw rawManifest) (Manifest, error) {
	if raw.FormatVersion == nil || *raw.FormatVersion != 1 {
		return Manifest{}, refuse("formatVersion is missing or not 1, the only version this import reads")
	}
	for _, f := range []struct{ name, value string }{
		{"toolVersion", raw.ToolVersion},
		{"analysisId", raw.AnalysisID},
		{"createdAt", raw.CreatedAt},
	} {
		if f.value == "" {
			return Manifest{}, refuse("%s is missing", f.name)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, raw.CreatedAt); err != nil {
		return Manifest{}, refuse("createdAt is not an RFC 3339 time")
	}
	target := raw.Target
	if target == nil {
		target = &rawTarget{}
	}
	for _, f := range []struct{ name, value string }{
		{"target.os", target.OS}, {"target.cpu", target.CPU}, {"target.libc", target.Libc},
		{"target.node", target.Node}, {"target.pnpmVer", target.PnpmVer},
	} {
		if f.value == "" {
			return Manifest{}, refuse("%s is missing", f.name)
		}
	}
	if raw.Archive == nil || !hexSHA256.MatchString(raw.Archive.SHA256) {
		return Manifest{}, refuse("archive.sha256 is missing or not a lowercase hex sha256")
	}
	if raw.Archive.Size == nil || *raw.Archive.Size <= 0 {
		return Manifest{}, refuse("archive.size is missing or not positive")
	}
	m := Manifest{
		FormatVersion: 1, ToolVersion: raw.ToolVersion, AnalysisID: raw.AnalysisID, CreatedAt: raw.CreatedAt,
		Target:  Target{OS: target.OS, CPU: target.CPU, Libc: target.Libc, Node: target.Node, PnpmVer: target.PnpmVer},
		Archive: Summary{SHA256: raw.Archive.SHA256, Size: *raw.Archive.Size},
	}
	if len(raw.Packages) == 0 {
		return Manifest{}, refuse("the manifest lists no package")
	}
	files := map[string]bool{}
	versions := map[string]bool{}
	for i, p := range raw.Packages {
		pkg, err := checkPackage(i, p)
		if err != nil {
			return Manifest{}, err
		}
		if files[pkg.File] {
			return Manifest{}, refuse("%q is listed twice", pkg.File)
		}
		files[pkg.File] = true
		id := pkg.Name + "@" + pkg.Version
		if versions[id] {
			return Manifest{}, refuse("%q is listed twice", id)
		}
		versions[id] = true
		m.Packages = append(m.Packages, pkg)
	}
	return m, nil
}

func checkPackage(i int, p rawPackage) (Package, error) {
	at := func(field string) string { return fmt.Sprintf("packages[%d].%s", i, field) }
	for _, f := range []struct{ name, value string }{
		{"name", p.Name}, {"version", p.Version}, {"file", p.File},
		{"originalIntegrity", p.OriginalIntegrity}, {"shippedSha512", p.ShippedSHA512},
	} {
		if f.value == "" {
			return Package{}, refuse("%s is missing", at(f.name))
		}
	}
	if p.PublishConfigStripped == nil {
		return Package{}, refuse("%s is missing", at("publishConfigStripped"))
	}
	if len(p.File) > maxFileNameBytes || !packageFile.MatchString(p.File) {
		return Package{}, refuse("%s is not a plain file name ending in .tgz: %q", at("file"), p.File)
	}
	if !npm.ValidName(p.Name) {
		return Package{}, refuse("%s is not a valid package name: %q", at("name"), p.Name)
	}
	if !npm.IsExactVersion(p.Version) {
		return Package{}, refuse("%s is not an exact version: %q", at("version"), p.Version)
	}
	if !hexSHA512.MatchString(p.ShippedSHA512) {
		return Package{}, refuse("%s is not a lowercase hex sha512", at("shippedSha512"))
	}
	if _, _, err := npm.ParseIntegrity(p.OriginalIntegrity); err != nil {
		return Package{}, refuse("%s is not a usable integrity string", at("originalIntegrity"))
	}
	return Package{
		Name: p.Name, Version: p.Version, File: p.File,
		OriginalIntegrity: p.OriginalIntegrity, ShippedSHA512: p.ShippedSHA512,
		PublishConfigStripped: *p.PublishConfigStripped,
	}, nil
}

// jsonProblem names a decoding problem without echoing manifest content.
func jsonProblem(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("syntax error at byte %d", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Sprintf("field %s has the wrong type", typ.Field)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected end of input"
	}
	return "unreadable"
}
