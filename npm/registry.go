package npm

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // old packages publish sha1 integrity only
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// ErrNotFound reports a package or tarball the registry does not have.
var ErrNotFound = errors.New("not found in registry")

// ErrIntegrity reports downloaded bytes that do not match the expected integrity.
var ErrIntegrity = errors.New("integrity mismatch")

// Packument is the registry document of a package.
type Packument struct {
	Name     string                     `json:"name"`
	Versions map[string]VersionMeta     `json:"versions"`
	Time     map[string]json.RawMessage `json:"time"`
}

// Published returns the publication time of a version.
func (p Packument) Published(version string) (time.Time, bool) {
	var t time.Time
	raw, ok := p.Time[version]
	if !ok || json.Unmarshal(raw, &t) != nil {
		return time.Time{}, false
	}
	return t, true
}

// VersionMeta holds the fields of one published version that sealift reads.
type VersionMeta struct {
	Version          string                     `json:"version"`
	Deprecated       Deprecation                `json:"deprecated"`
	Engines          Engines                    `json:"engines"`
	Scripts          map[string]json.RawMessage `json:"scripts"`
	PeerDependencies map[string]string          `json:"peerDependencies"`
	NPMUser          struct {
		Name string `json:"name"`
	} `json:"_npmUser"`
	Dist struct {
		Integrity    string          `json:"integrity"`
		Attestations json.RawMessage `json:"attestations"`
	} `json:"dist"`
}

// HasInstallScript reports whether the version runs a preinstall, install
// or postinstall script.
func (v VersionMeta) HasInstallScript() bool {
	for _, name := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := v.Scripts[name]; ok {
			return true
		}
	}
	return false
}

// HasProvenance reports whether the registry lists attestations for the version.
func (v VersionMeta) HasProvenance() bool {
	return len(v.Dist.Attestations) > 0 && string(v.Dist.Attestations) != "null"
}

// Engines maps an engine name to its version range. Old packages publish an
// array instead; it decodes to no ranges. A null value reads as "". Another
// value that is not a string is dropped and the other ranges are kept, except
// under node: a value other than 0 or false reads as "not a string: " and its
// JSON, cut to 64 bytes, a range no Node satisfies: pnpm 10 and 11 match no
// Node against such a value and skip 0 and false as they skip null. pnpm 12
// skips every value that is not a string; sealift cannot run pnpm 12 today,
// since its package has no bin/pnpm.cjs, so revisit this if it ever does.
type Engines map[string]string

// UnmarshalJSON implements json.Unmarshaler.
func (e *Engines) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return nil
	}
	m := make(Engines, len(raw))
	for name, value := range raw {
		var r string
		if json.Unmarshal(value, &r) == nil {
			m[name] = r
		} else if name == "node" && !zeroOrFalse(value) {
			var text bytes.Buffer
			_ = json.Compact(&text, value)
			t := text.String()
			if len(t) > 64 {
				t = strings.ToValidUTF8(t[:64], "")
			}
			m[name] = "not a string: " + t
		}
	}
	*e = m
	return nil
}

func zeroOrFalse(value json.RawMessage) bool {
	var n float64
	var b bool
	return json.Unmarshal(value, &n) == nil && n == 0 || json.Unmarshal(value, &b) == nil && !b
}

// Deprecation holds a deprecation message. A value that is not a string
// decodes to "".
type Deprecation string

// UnmarshalJSON implements json.Unmarshaler.
func (d *Deprecation) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*d = Deprecation(s)
	}
	return nil
}

// maxPackument bounds a packument, which sealift decodes in memory. The full
// document carries every version: renovate's ran 73 MiB on registry.npmjs.org
// in November 2026, the largest one measured.
const maxPackument = 256 << 20

// errTooLarge reports a registry document over maxPackument. It is not
// retried: the registry would send the same document again.
var errTooLarge = fmt.Errorf("document over the %d MiB bound", maxPackument>>20)

// maxTarball bounds a package tarball, which sealift writes to disk before
// checking its integrity. The largest public tarballs run a few hundred MiB,
// so 1 GiB admits every real package while a hostile registry cannot fill
// the volume. A variable so a test can lower it.
var maxTarball int64 = 1 << 30

// errTarballTooLarge reports a tarball over maxTarball. It is not retried:
// the registry would send the same tarball again.
var errTarballTooLarge = errors.New("tarball over the bound")

// Client reads an npm registry. The zero value reads DefaultRegistry.
type Client struct {
	Registry string                        // defaults to DefaultRegistry
	HTTP     *http.Client                  // defaults to http.DefaultClient
	Attempts int                           // tries per request, defaults to 3
	Backoff  func(retry int) time.Duration // wait before retry n, defaults to 500ms doubling
}

// Packument fetches the full registry document of a package.
func (c *Client) Packument(ctx context.Context, name string) (Packument, error) {
	var p Packument
	err := c.do(ctx, c.registry()+"/"+url.PathEscape(name), "application/json", func(body io.Reader) error {
		p = Packument{}
		// One byte past the bound shows the document is larger: it is
		// refused whole, never decoded from a cut-short read.
		lr := &io.LimitedReader{R: body, N: maxPackument + 1}
		err := json.NewDecoder(lr).Decode(&p)
		if err == nil {
			_, err = io.Copy(io.Discard, lr)
		}
		if lr.N == 0 {
			return errTooLarge
		}
		return err
	})
	if err != nil {
		return Packument{}, fmt.Errorf("packument %s: %w", name, err)
	}
	return p, nil
}

// DownloadFile saves a package tarball at path after checking it against an
// SRI integrity string (sha512 or sha1). It writes path+".part" and renames
// it on success, so path never holds a partial or corrupt file. Network and
// server errors get retried; ErrNotFound and ErrIntegrity do not.
//
// It also returns the sha512 hex digest of the downloaded bytes, computed
// whatever the integrity algorithm was: an export's cache key and manifest
// always use sha512, even for the legacy packages that publish sha1 only.
func (c *Client) DownloadFile(ctx context.Context, name, version, integrity, path string) (string, error) {
	newHash, want, err := ParseIntegrity(integrity)
	if err != nil {
		return "", err
	}
	part := path + ".part"
	var sha512Hex string
	err = c.do(ctx, TarballURL(c.registry(), name, version), "application/octet-stream", func(body io.Reader) error {
		// Another account may write the directory. Whatever sits at the
		// .part path goes, and O_EXCL refuses anything planted there again:
		// through a link, the bytes would land in its target.
		if err := os.Remove(part); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o666)
		if err != nil {
			return err
		}
		h := newHash()
		sum512 := sha512.New()
		// One byte past the bound shows the tarball is larger.
		lr := &io.LimitedReader{R: body, N: maxTarball + 1}
		_, copyErr := io.Copy(io.MultiWriter(f, h, sum512), lr)
		if err := errors.Join(copyErr, f.Close()); err != nil {
			return err
		}
		if lr.N == 0 {
			return fmt.Errorf("%w of %d bytes", errTarballTooLarge, maxTarball)
		}
		if !bytes.Equal(h.Sum(nil), want) {
			return ErrIntegrity
		}
		sha512Hex = hex.EncodeToString(sum512.Sum(nil))
		return os.Rename(part, path)
	})
	if err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("download %s@%s: %w", name, version, err)
	}
	return sha512Hex, nil
}

func (c *Client) do(ctx context.Context, u, accept string, fn func(io.Reader) error) error {
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.backoff(attempt - 1)):
			}
		}
		err = c.try(ctx, u, accept, fn)
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrIntegrity) || errors.Is(err, errTooLarge) || errors.Is(err, errTarballTooLarge) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (c *Client) try(ctx context.Context, u, accept string, fn func(io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", accept)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return fn(resp.Body)
}

func (c *Client) registry() string {
	if c.Registry == "" {
		return DefaultRegistry
	}
	return strings.TrimSuffix(c.Registry, "/")
}

func (c *Client) backoff(retry int) time.Duration {
	if c.Backoff != nil {
		return c.Backoff(retry)
	}
	return 500 * time.Millisecond << (retry - 1)
}

// ParseIntegrity returns the hash and the digest an SRI string asks for: sha512
// when it lists one, sha1 only when it lists nothing else.
func ParseIntegrity(sri string) (func() hash.Hash, []byte, error) {
	fields := strings.Fields(sri)
	if len(fields) == 0 {
		return nil, nil, errors.New("empty integrity")
	}
	var sha1Sum []byte
	onlySHA1 := true
	for _, field := range fields {
		entry, _, _ := strings.Cut(field, "?") // SRI allows options after the digest
		algo, encoded, ok := strings.Cut(entry, "-")
		if !ok {
			return nil, nil, fmt.Errorf("integrity %q: missing algorithm", sri)
		}
		switch algo {
		case "sha512":
			sum, err := decodeDigest(sri, encoded, sha512.Size)
			return sha512.New, sum, err
		case "sha1":
			sum, err := decodeDigest(sri, encoded, sha1.Size)
			if err != nil {
				return nil, nil, err
			}
			sha1Sum = sum
		default:
			onlySHA1 = false
		}
	}
	// sha1 stands in only where a package publishes nothing else: beside a
	// hash sealift cannot check, it would turn a refusal into a weaker pass.
	if sha1Sum == nil || !onlySHA1 {
		return nil, nil, fmt.Errorf("integrity %q: unsupported algorithm", sri)
	}
	return sha1.New, sha1Sum, nil
}

func decodeDigest(sri, encoded string, size int) ([]byte, error) {
	sum, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("integrity %q: %w", sri, err)
	}
	if len(sum) != size {
		return nil, fmt.Errorf("integrity %q: digest is %d bytes, want %d", sri, len(sum), size)
	}
	return sum, nil
}
