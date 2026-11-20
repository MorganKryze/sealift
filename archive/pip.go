package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"time"

	"github.com/MorganKryze/sealift/pip"
)

// Ecosystem names the package manager an export's manifest belongs to.
type Ecosystem string

// The ecosystems a manifest can belong to.
const (
	NPM Ecosystem = "npm"
	Pip Ecosystem = "pip"
)

// PipFormatVersion is the formatVersion of a pip manifest.
const PipFormatVersion = 3

// PipArchiveFile is the name of the archive a pip export writes.
const PipArchiveFile = "packages_pip.tar.gz"

// maxWheelFileBytes is the longest wheel file name a pip manifest may list:
// 251 bytes, so that out/<file> fits the 255-byte entry name bound.
const maxWheelFileBytes = 251

// wheelFile is the shape of a wheel name under out/: the characters a valid
// project name, an exact version, a build tag and the tags can hold.
var wheelFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._!+-]*\.whl$`)

// ManifestEcosystem reads formatVersion and ecosystem alone; call it after
// CheckSignature. 2 with no ecosystem or "npm" is NPM, 3 with "pip" is Pip,
// anything else a *Refusal that repeats no value.
func ManifestEcosystem(data []byte) (Ecosystem, error) {
	var doc struct {
		FormatVersion *int    `json:"formatVersion"`
		Ecosystem     *string `json:"ecosystem"`
	}
	if err := decodeManifest(data, &doc); err != nil {
		return "", err
	}
	switch {
	case doc.FormatVersion == nil:
		return "", refuse("formatVersion is missing")
	case *doc.FormatVersion == 2:
		if doc.Ecosystem != nil && *doc.Ecosystem != string(NPM) {
			return "", refuse("formatVersion 2 is an npm manifest, and its ecosystem is not npm")
		}
		return NPM, nil
	case *doc.FormatVersion == PipFormatVersion:
		if doc.Ecosystem == nil || *doc.Ecosystem != string(Pip) {
			return "", refuse("formatVersion 3 is a pip manifest, and its ecosystem is not pip")
		}
		return Pip, nil
	}
	return "", refuse("formatVersion is not 2 or 3, the versions this import reads")
}

// decodeManifest decodes one JSON document and refuses anything after it.
func decodeManifest(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return refuse("the manifest is not valid JSON: %s", jsonProblem(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return refuse("the manifest holds data after the manifest")
	}
	return nil
}

// PipManifest is what the import reads of a pip export's manifest.json.
// Fields this version does not know are ignored.
type PipManifest struct {
	FormatVersion int
	Ecosystem     Ecosystem
	ToolVersion   string
	AnalysisID    string
	CreatedAt     string
	Target        PipTarget
	Archive       Summary
	Packages      []Wheel
}

// PipTarget is the interpreter and system the wheels were chosen for.
type PipTarget struct{ Python, OS, CPU, Glibc, UvVer string }

// Wheel describes one wheel a pip archive carries.
type Wheel struct {
	Name, Version, File string // Name normalized; File a wheel name of at most 251 bytes naming Name and Version
	SHA256              string // the index's, lowercase hex
	ShippedSHA512       string // of the same bytes, lowercase hex
}

// rawPipManifest keeps a missing field apart from a zero one.
type rawPipManifest struct {
	FormatVersion *int    `json:"formatVersion"`
	Ecosystem     *string `json:"ecosystem"`
	ToolVersion   string  `json:"toolVersion"`
	AnalysisID    string  `json:"analysisId"`
	CreatedAt     string  `json:"createdAt"`
	Target        *struct {
		Python string `json:"python"`
		OS     string `json:"os"`
		CPU    string `json:"cpu"`
		Glibc  string `json:"glibc"`
		UvVer  string `json:"uvVer"`
	} `json:"target"`
	Archive *struct {
		SHA256 string `json:"sha256"`
		Size   *int64 `json:"size"`
	} `json:"archive"`
	Packages []rawWheel `json:"packages"`
}

// rawWheel has Wheel's fields in Wheel's order, so one converts to the other.
type rawWheel struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	File          string `json:"file"`
	SHA256        string `json:"sha256"`
	ShippedSHA512 string `json:"shippedSha512"`
}

// ParsePipManifest checks a manifest.json of formatVersion 3. It trusts
// nothing in data: callers verify the manifest's signature first. Any problem
// comes back as a *Refusal.
func ParsePipManifest(data []byte) (PipManifest, error) {
	var raw rawPipManifest
	if err := decodeManifest(data, &raw); err != nil {
		return PipManifest{}, err
	}
	if raw.FormatVersion == nil || *raw.FormatVersion != PipFormatVersion {
		return PipManifest{}, refuse("formatVersion is missing or not 3, the version of a pip manifest")
	}
	if raw.Ecosystem == nil || *raw.Ecosystem != string(Pip) {
		return PipManifest{}, refuse("ecosystem is missing or not pip")
	}
	header := []struct{ name, value string }{
		{"toolVersion", raw.ToolVersion}, {"analysisId", raw.AnalysisID}, {"createdAt", raw.CreatedAt},
	}
	if err := checkFields(header); err != nil {
		return PipManifest{}, err
	}
	if _, err := time.Parse(time.RFC3339Nano, raw.CreatedAt); err != nil {
		return PipManifest{}, refuse("createdAt is not an RFC 3339 time")
	}
	var target PipTarget
	if raw.Target != nil {
		target = PipTarget{Python: raw.Target.Python, OS: raw.Target.OS, CPU: raw.Target.CPU, Glibc: raw.Target.Glibc, UvVer: raw.Target.UvVer}
	}
	// The target is checked as text only, never more strictly than the store
	// checks it, so every export the store allowed parses here.
	if err := checkFields([]struct{ name, value string }{
		{"target.python", target.Python}, {"target.os", target.OS}, {"target.cpu", target.CPU},
		{"target.glibc", target.Glibc}, {"target.uvVer", target.UvVer},
	}); err != nil {
		return PipManifest{}, err
	}
	if raw.Archive == nil || !hexSHA256.MatchString(raw.Archive.SHA256) {
		return PipManifest{}, refuse("archive.sha256 is missing or not a lowercase hex sha256")
	}
	if raw.Archive.Size == nil || *raw.Archive.Size <= 0 {
		return PipManifest{}, refuse("archive.size is missing or not positive")
	}
	m := PipManifest{
		FormatVersion: PipFormatVersion, Ecosystem: Pip,
		ToolVersion: raw.ToolVersion, AnalysisID: raw.AnalysisID, CreatedAt: raw.CreatedAt,
		Target: target, Archive: Summary{SHA256: raw.Archive.SHA256, Size: *raw.Archive.Size},
	}
	if len(raw.Packages) == 0 {
		return PipManifest{}, refuse("the manifest lists no package")
	}
	names := map[string]bool{}
	for i, p := range raw.Packages {
		w, err := checkWheel(i, p)
		if err != nil {
			return PipManifest{}, err
		}
		// One wheel per package: a second entry of a name, of the same
		// version or another, is refused.
		if names[w.Name] {
			return PipManifest{}, refuse("%s is listed twice: a pip archive carries one wheel per package", w.Name)
		}
		names[w.Name] = true
		m.Packages = append(m.Packages, w)
	}
	return m, nil
}

// checkFields refuses the first field that is empty, then the first that
// checkText refuses.
func checkFields(fields []struct{ name, value string }) error {
	for _, f := range fields {
		if f.value == "" {
			return refuse("%s is missing", f.name)
		}
	}
	for _, f := range fields {
		if err := checkText(f.name, f.value); err != nil {
			return err
		}
	}
	return nil
}

// checkWheel checks one entry. Its refusals name the field and repeat a file
// or a name only once it has passed its class.
func checkWheel(i int, p rawWheel) (Wheel, error) {
	at := func(field string) string { return fmt.Sprintf("packages[%d].%s", i, field) }
	for _, f := range []struct{ name, value string }{
		{"name", p.Name}, {"version", p.Version}, {"file", p.File},
		{"sha256", p.SHA256}, {"shippedSha512", p.ShippedSHA512},
	} {
		if f.value == "" {
			return Wheel{}, refuse("%s is missing", at(f.name))
		}
	}
	if len(p.File) > maxWheelFileBytes || !wheelFile.MatchString(p.File) {
		return Wheel{}, refuse("%s is not a plain file name ending in .whl of at most %d bytes", at("file"), maxWheelFileBytes)
	}
	wheel, err := pip.ParseWheelName(p.File)
	if err != nil {
		return Wheel{}, refuse("%s is not a wheel name", at("file"))
	}
	if !pip.ValidName(p.Name) || pip.Normalize(p.Name) != p.Name {
		return Wheel{}, refuse("%s is not a normalized package name", at("name"))
	}
	if len(p.Version) > maxVersionBytes {
		return Wheel{}, refuse("%s is longer than %d bytes", at("version"), maxVersionBytes)
	}
	if !pip.IsExactVersion(p.Version) {
		return Wheel{}, refuse("%s is not an exact version", at("version"))
	}
	if pip.Normalize(wheel.Name) != p.Name {
		return Wheel{}, refuse("%s names another package than %s", p.File, at("name"))
	}
	if !pip.SameVersion(wheel.Version, p.Version) {
		return Wheel{}, refuse("%s names another version than %s", p.File, at("version"))
	}
	if !hexSHA256.MatchString(p.SHA256) {
		return Wheel{}, refuse("%s is not a lowercase hex sha256", at("sha256"))
	}
	if !hexSHA512.MatchString(p.ShippedSHA512) {
		return Wheel{}, refuse("%s is not a lowercase hex sha512", at("shippedSha512"))
	}
	return Wheel(p), nil
}

// CheckedWheel is a wheel that passed every check, copied to Path.
type CheckedWheel struct {
	Wheel  Wheel
	Path   string // the copy in opts.Dir, mode 0600
	SHA512 []byte
}

// VerifyPip applies Verify's checks and bounds to a packages_pip.tar.gz and
// checks each wheel's sha512 and sha256; results in manifest order. As with
// Verify, a wrong archive size or sha256 is named before any other problem,
// and files already copied stay in opts.Dir after an error.
func VerifyPip(r io.Reader, m PipManifest, opts VerifyOptions) ([]CheckedWheel, error) {
	if !filepath.IsAbs(opts.Dir) {
		return nil, errors.New("archive: VerifyPip needs an absolute directory")
	}
	files := make([]expected, len(m.Packages))
	for i, w := range m.Packages {
		shipped, err := hex.DecodeString(w.ShippedSHA512)
		if err != nil {
			return nil, refuse("%s: shippedSha512 is not hex", w.File)
		}
		index, err := hex.DecodeString(w.SHA256)
		if err != nil {
			return nil, refuse("%s: sha256 is not hex", w.File)
		}
		files[i] = expected{file: w.File, sha512: shipped, newH: sha256.New, want: index, what: "sha256"}
	}
	copies, err := verifyStream(r, m.Archive, files, opts)
	if err != nil {
		return nil, err
	}
	checked := make([]CheckedWheel, len(copies))
	for i, c := range copies {
		checked[i] = CheckedWheel{Wheel: m.Packages[i], Path: c.path, SHA512: c.sha512}
	}
	return checked, nil
}
