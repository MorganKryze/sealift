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
	"net/http"
	"net/url"
	"os"
	"strings"
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
// array instead; it decodes to an empty map.
type Engines map[string]string

// UnmarshalJSON implements json.Unmarshaler.
func (e *Engines) UnmarshalJSON(b []byte) error {
	var m map[string]string
	if json.Unmarshal(b, &m) == nil {
		*e = m
	}
	return nil
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
		return json.NewDecoder(body).Decode(&p)
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
	newHash, want, err := parseIntegrity(integrity)
	if err != nil {
		return "", err
	}
	part := path + ".part"
	var sha512Hex string
	err = c.do(ctx, TarballURL(c.registry(), name, version), "application/octet-stream", func(body io.Reader) error {
		f, err := os.Create(part)
		if err != nil {
			return err
		}
		h := newHash()
		sum512 := sha512.New()
		_, copyErr := io.Copy(io.MultiWriter(f, h, sum512), body)
		if err := errors.Join(copyErr, f.Close()); err != nil {
			return err
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
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrIntegrity) || ctx.Err() != nil {
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

func parseIntegrity(sri string) (func() hash.Hash, []byte, error) {
	fields := strings.Fields(sri)
	if len(fields) == 0 {
		return nil, nil, errors.New("empty integrity")
	}
	algo, encoded, ok := strings.Cut(fields[0], "-")
	if !ok {
		return nil, nil, fmt.Errorf("integrity %q: missing algorithm", sri)
	}
	sum, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("integrity %q: %w", sri, err)
	}
	switch algo {
	case "sha512":
		return sha512.New, sum, nil
	case "sha1":
		return sha1.New, sum, nil
	}
	return nil, nil, fmt.Errorf("integrity %q: unsupported algorithm", sri)
}
