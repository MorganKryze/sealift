// Package nexus talks to a Nexus 3 hosted npm or pypi repository over its
// REST API.
package nexus

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/MorganKryze/sealift/npm"
)

const (
	// maxMessageChars is the longest text from Nexus that reaches an error.
	maxMessageChars = 300
	// maxErrorBody is how much of an error response is read to find that text.
	maxErrorBody = 8 << 10
	// maxRepositoryList is the largest repository listing the client decodes.
	maxRepositoryList = 1 << 20
	// dialTimeout and handshakeTimeout bound connection setup.
	dialTimeout      = 30 * time.Second
	handshakeTimeout = 30 * time.Second
	// headerTimeout bounds the wait for response headers; an upload is
	// not cut short by a client-wide deadline.
	headerTimeout = 5 * time.Minute
)

// Format is the Nexus format of a repository.
type Format string

// The two formats an import publishes to.
const (
	FormatNPM  Format = "npm"
	FormatPyPI Format = "pypi"
)

// ErrRepository marks a repository Nexus does not list, or lists in another
// format or type. CheckRepository wraps it; an unreachable Nexus or a 401 or
// 403 does not.
var ErrRepository = errors.New("nexus: no hosted repository of that name and format")

// repositoryError keeps its own text and wraps ErrRepository.
type repositoryError struct{ msg string }

func (e *repositoryError) Error() string { return e.msg }
func (e *repositoryError) Unwrap() error { return ErrRepository }

// Config holds the address and credentials of one Nexus repository.
// An empty Format reads as npm.
type Config struct {
	URL        *url.URL
	Repository string
	Format     Format
	User       string
	Password   []byte
	CAFile     string
}

// Error is an HTTP answer from Nexus that is not a success.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("nexus answered %d", e.Status)
	}
	return fmt.Sprintf("nexus answered %d: %s", e.Status, e.Message)
}

// Client is a Nexus client for one repository.
type Client struct {
	base    url.URL
	repo    string
	format  Format
	user    string
	pass    []byte
	secrets []string
	http    *http.Client
}

// New builds a client that trusts the system roots plus CAFile, refuses
// redirects, uses no proxy and never skips certificate verification.
func New(cfg Config) (*Client, error) {
	if cfg.URL == nil || cfg.URL.Host == "" || (cfg.URL.Scheme != "http" && cfg.URL.Scheme != "https") {
		return nil, errors.New("nexus url must be http or https with a host")
	}
	if cfg.Repository == "" {
		return nil, errors.New("nexus repository is empty")
	}
	format := cfg.Format
	switch format {
	case "":
		format = FormatNPM
	case FormatNPM, FormatPyPI:
	default:
		return nil, fmt.Errorf("nexus format %q is neither npm nor pypi", format)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificates: %w", err)
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %q holds no certificate", cfg.CAFile)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// The credentials go to the configured address only, so no proxy from the
	// environment may sit between the client and Nexus.
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialTimeout}).DialContext
	tr.TLSHandshakeTimeout = handshakeTimeout
	tr.ResponseHeaderTimeout = headerTimeout
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}

	c := &Client{
		base:   *cfg.URL,
		repo:   cfg.Repository,
		format: format,
		user:   cfg.User,
		pass:   cfg.Password,
		http: &http.Client{
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	c.base.User, c.base.RawQuery, c.base.Fragment = nil, "", ""
	if len(cfg.Password) > 0 {
		basic := base64.StdEncoding.EncodeToString([]byte(cfg.User + ":" + string(cfg.Password)))
		c.secrets = []string{basic, string(cfg.Password)}
	}
	return c, nil
}

// CheckRepository confirms that Nexus accepts the credentials and holds the
// repository as a hosted repository of the client's format.
func (c *Client) CheckRepository(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, c.endpoint("/service/rest/v1/repositories", ""), nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.statusError(resp)
	}
	var repos []struct {
		Name   string `json:"name"`
		Format string `json:"format"`
		Type   string `json:"type"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRepositoryList)).Decode(&repos); err != nil {
		return errors.New("nexus repository list is not readable JSON")
	}
	for _, r := range repos {
		if r.Name != c.repo {
			continue
		}
		if r.Format != string(c.format) || r.Type != "hosted" {
			return &repositoryError{fmt.Sprintf("nexus repository %q is %s %s, not %s hosted", c.repo, c.clean(r.Format), c.clean(r.Type), c.format)}
		}
		return nil
	}
	return &repositoryError{fmt.Sprintf("nexus repository %q not found", c.repo)}
}

// Fetch copies the tarball of name@version to w. It reports found false on a
// 404, and fails when the copy is longer than limit bytes.
func (c *Client) Fetch(ctx context.Context, name, version string, w io.Writer, limit int64) (bool, error) {
	if !plainSegment(name) || !plainSegment(version) {
		return false, errors.New("package name or version is not usable in a URL path")
	}
	path := npm.TarballURL("/repository/"+c.repo, name, version)
	resp, err := c.do(ctx, http.MethodGet, c.endpoint(path, ""), nil, "")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, c.statusError(resp)
	}
	return true, c.copyLimited(w, resp.Body, limit)
}

// copyLimited copies body to w and fails past limit bytes.
func (c *Client) copyLimited(w io.Writer, body io.Reader, limit int64) error {
	n, err := io.Copy(w, io.LimitReader(body, limit+1))
	if err != nil {
		return fmt.Errorf("nexus unreachable: %s", c.clean(err.Error()))
	}
	if n > limit {
		return fmt.Errorf("nexus copy is larger than %d bytes", limit)
	}
	return nil
}

// Upload sends one file as a component, in the form field "<format>.asset".
func (c *Client) Upload(ctx context.Context, file string, r io.Reader) error {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	done := make(chan struct{})
	go func() {
		defer close(done)
		part, err := mw.CreateFormFile(string(c.format)+".asset", file)
		if err == nil {
			_, err = io.Copy(part, r)
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()
	resp, err := c.do(ctx, http.MethodPost, c.endpoint("/service/rest/v1/components", "repository="+url.QueryEscape(c.repo)), pr, mw.FormDataContentType())
	pr.CloseWithError(errors.New("upload ended"))
	<-done
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.statusError(resp)
	}
	return nil
}

func (c *Client) endpoint(path, query string) string {
	u := c.base
	u.Path, u.RawPath, u.RawQuery = strings.TrimSuffix(c.base.Path, "/")+path, "", query
	return u.String()
}

func (c *Client) do(ctx context.Context, method, target string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("nexus request: %s", c.clean(err.Error()))
	}
	req.SetBasicAuth(c.user, string(c.pass))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("nexus unreachable: %s", c.clean(err.Error()))
	}
	return resp, nil
}

func (c *Client) statusError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return &Error{Status: resp.StatusCode, Message: c.clean(string(b))}
}

// clean removes control characters and secrets from text, then cuts it.
func (c *Client) clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = c.scrub(s)
	if r := []rune(s); len(r) > maxMessageChars {
		s = string(r[:maxMessageChars])
	}
	return s
}

func (c *Client) scrub(s string) string {
	for _, secret := range c.secrets {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	return s
}

// plainSegment reports whether s can be joined into a URL path without
// reaching another location.
func plainSegment(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\\?#%") && !strings.Contains(s, "..")
}
