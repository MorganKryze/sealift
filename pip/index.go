package pip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxPageBytes   = 32 << 20
	requestTimeout = 60 * time.Second
	simpleJSON     = "application/vnd.pypi.simple.v1+json"
)

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrNotFound reports that the index does not know the project.
var ErrNotFound = errors.New("pip: not found on the index")

// IndexFile is one file of a release as the index lists it.
type IndexFile struct {
	Filename, URL, Sha256 string // URL is absolute, http or https
	Size                  int64
	RequiresPython        string
	Yanked                bool
	YankedReason          string
	UploadTime            time.Time // zero when the index gives none
}

// Client reads the JSON simple API of a package index.
type Client struct {
	Index string // the simple index base URL
	HTTP  *http.Client
}

type simplePage struct {
	Meta struct {
		APIVersion string `json:"api-version"`
	} `json:"meta"`
	Files []struct {
		Filename       string            `json:"filename"`
		URL            string            `json:"url"`
		Hashes         map[string]string `json:"hashes"`
		RequiresPython string            `json:"requires-python"`
		Yanked         json.RawMessage   `json:"yanked"`
		Size           int64             `json:"size"`
		UploadTime     string            `json:"upload-time"`
	} `json:"files"`
}

// Files lists the files the index publishes for one version of a project,
// source distributions included.
func (c *Client) Files(ctx context.Context, name, version string) ([]IndexFile, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("pip: %q is not a valid project name", name)
	}
	if !IsExactVersion(version) {
		return nil, fmt.Errorf("pip: %q is not a valid version", version)
	}
	norm := Normalize(name)
	pageURL, err := url.Parse(strings.TrimSuffix(c.Index, "/") + "/" + norm + "/")
	if err != nil {
		return nil, fmt.Errorf("pip: index URL: %w", err)
	}
	body, err := c.get(ctx, pageURL.String())
	if err != nil {
		return nil, err
	}
	var pg simplePage
	if err := json.Unmarshal(body, &pg); err != nil {
		return nil, fmt.Errorf("pip: the page for %s is not valid JSON: %w", norm, err)
	}
	if v, _, _ := strings.Cut(pg.Meta.APIVersion, "."); v != "1" {
		return nil, fmt.Errorf("pip: the page for %s has api-version %q, only 1.x is read", norm, pg.Meta.APIVersion)
	}

	var out []IndexFile
	for _, e := range pg.Files {
		if !fileIsRelease(e.Filename, norm, version) {
			continue
		}
		f := IndexFile{Filename: e.Filename, Size: e.Size, RequiresPython: e.RequiresPython}
		if e.URL == "" {
			return nil, fmt.Errorf("pip: %s has no url", e.Filename)
		}
		ref, err := url.Parse(e.URL)
		if err != nil {
			return nil, fmt.Errorf("pip: %s has an unreadable url", e.Filename)
		}
		abs := pageURL.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return nil, fmt.Errorf("pip: %s has a url that is not http or https", e.Filename)
		}
		if abs.User != nil {
			return nil, fmt.Errorf("pip: %s has a url with credentials", e.Filename)
		}
		abs.Fragment = ""
		f.URL = abs.String()
		f.Sha256 = strings.ToLower(e.Hashes["sha256"])
		if !sha256RE.MatchString(f.Sha256) {
			return nil, fmt.Errorf("pip: %s has no valid sha256", e.Filename)
		}
		f.Yanked, f.YankedReason = readYanked(e.Yanked)
		if t, err := time.Parse(time.RFC3339Nano, e.UploadTime); err == nil {
			f.UploadTime = t
		}
		out = append(out, f)
	}
	return out, nil
}

func readYanked(raw json.RawMessage) (bool, string) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return true, s
	}
	return false, ""
}

func (c *Client) get(ctx context.Context, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("pip: index request: %w", err)
	}
	req.Header.Set("Accept", simpleJSON)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pip: index request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("pip: the index answered status %d", resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != simpleJSON {
		return nil, fmt.Errorf("pip: the index answered %q, not the JSON simple API", mt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pip: reading the index page: %w", err)
	}
	if len(body) > maxPageBytes {
		return nil, errors.New("pip: the index page is larger than 32 MiB")
	}
	return body, nil
}

// fileIsRelease reports whether a file name is a wheel or a source
// distribution of the project at the version.
func fileIsRelease(file, norm, version string) bool {
	if w, err := ParseWheelName(file); err == nil {
		return Normalize(w.Name) == norm && SameVersion(w.Version, version)
	}
	for _, ext := range []string{".tar.gz", ".zip"} {
		stem, ok := strings.CutSuffix(file, ext)
		if !ok || len(file) > maxFileNameBytes || strings.ContainsAny(file, "/\\") {
			continue
		}
		for i := 0; i < len(stem); i++ {
			if stem[i] == '-' && Normalize(stem[:i]) == norm && SameVersion(stem[i+1:], version) {
				return true
			}
		}
	}
	return false
}

// Blocking says why no wheel was chosen.
type Blocking string

const (
	// SourceOnly means the release has source distributions and no wheel.
	SourceOnly Blocking = "source-only"
	// OtherPlatforms means every wheel is for another interpreter or platform.
	OtherPlatforms Blocking = "other-platforms"
	// NoFiles means the index lists no file for the version.
	NoFiles Blocking = "no-files"
)

// ChooseWheel picks the wheel the target's installer prefers. The second
// result is empty when a wheel is chosen.
func ChooseWheel(files []IndexFile, p Platform) (IndexFile, Blocking) {
	if len(files) == 0 {
		return IndexFile{}, NoFiles
	}
	tags, err := Tags(p)
	if err != nil {
		return IndexFile{}, OtherPlatforms
	}
	rank := make(map[Tag]int, len(tags))
	for i, t := range tags {
		rank[t] = i
	}
	var best IndexFile
	var bestName WheelName
	bestRank := -1
	sawWheel := false
	for _, f := range files {
		w, err := ParseWheelName(f.Filename)
		if err != nil {
			continue
		}
		sawWheel = true
		if !requiresPythonAllows(f.RequiresPython, p.Python) {
			continue
		}
		r := -1
		for _, t := range w.Tags {
			if i, ok := rank[t]; ok && (r < 0 || i < r) {
				r = i
			}
		}
		if r < 0 {
			continue
		}
		if bestRank < 0 || r < bestRank || (r == bestRank && preferred(f, w, best, bestName)) {
			best, bestName, bestRank = f, w, r
		}
	}
	switch {
	case bestRank >= 0:
		return best, ""
	case sawWheel:
		return IndexFile{}, OtherPlatforms
	default:
		return IndexFile{}, SourceOnly
	}
}

// preferred reports whether a beats b on equal rank: the higher build tag,
// then the file name ascending.
func preferred(a IndexFile, aw WheelName, b IndexFile, bw WheelName) bool {
	if c := compareBuild(aw.Build, bw.Build); c != 0 {
		return c > 0
	}
	return a.Filename < b.Filename
}

// compareBuild orders build tags by their leading number, then as text; no
// tag ranks below any tag.
func compareBuild(a, b string) int {
	na, ra := splitBuild(a)
	nb, rb := splitBuild(b)
	if na != nb {
		if na > nb {
			return 1
		}
		return -1
	}
	return strings.Compare(ra, rb)
}

func splitBuild(s string) (int, string) {
	if s == "" {
		return -1, ""
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		n = 1 << 30
	}
	return n, s[i:]
}

// requiresPythonAllows evaluates a requires-python specifier against a
// version. A specifier it cannot read allows nothing.
func requiresPythonAllows(spec, python string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	target, ok := releaseOf(python)
	if !ok {
		return false
	}
	for _, clause := range strings.Split(spec, ",") {
		ok, valid := clauseAllows(strings.TrimSpace(clause), target)
		if !valid || !ok {
			return false
		}
	}
	return true
}

var operators = []string{"===", "~=", "==", "!=", "<=", ">=", "<", ">"}

func clauseAllows(clause string, target []int) (allowed, valid bool) {
	var op string
	for _, o := range operators {
		if strings.HasPrefix(clause, o) {
			op = o
			break
		}
	}
	if op == "" || op == "===" {
		return false, false
	}
	operand := strings.TrimSpace(clause[len(op):])
	wild := false
	if op == "==" || op == "!=" {
		if s, ok := strings.CutSuffix(operand, ".*"); ok {
			operand, wild = s, true
		}
	}
	v, ok := releaseOf(operand)
	if !ok {
		return false, false
	}
	switch op {
	case "~=":
		if len(v) < 2 {
			return false, false
		}
		prefix := v[:len(v)-1]
		return compareRelease(target, v) >= 0 && hasPrefix(target, prefix), true
	case "==", "!=":
		eq := compareRelease(target, v) == 0
		if wild {
			eq = hasPrefix(target, v)
		}
		return eq == (op == "=="), true
	}
	c := compareRelease(target, v)
	switch op {
	case ">=":
		return c >= 0, true
	case ">":
		return c > 0, true
	case "<=":
		return c <= 0, true
	default:
		return c < 0, true
	}
}

// releaseOf reads a plain dotted release such as 3.11.2.
func releaseOf(s string) ([]int, bool) {
	if s == "" || len(s) > maxVersionBytes {
		return nil, false
	}
	var out []int
	for _, seg := range strings.Split(s, ".") {
		n, err := strconv.Atoi(seg)
		if err != nil || n < 0 || seg[0] == '+' || seg[0] == '-' {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func compareRelease(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

func hasPrefix(v, prefix []int) bool {
	return len(v) >= len(prefix) && slices.Equal(v[:len(prefix)], prefix)
}
