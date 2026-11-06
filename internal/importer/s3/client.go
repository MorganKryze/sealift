// Package s3 is a minimal MinIO client: list, head, read and delete, signed with Signature
// Version 4. It never writes an object.
package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxListBytes bounds a ListObjectsV2 answer.
	MaxListBytes = 4 << 20
	// MaxErrorBytes bounds an error answer read from the server.
	MaxErrorBytes = 8 << 10

	// maxMessageChars bounds server text that reaches an error string.
	maxMessageChars = 300
	// maxKeys is the most keys S3 returns in one page.
	maxKeys = 1000
	// maxKeyBytes is S3's limit on an object key.
	maxKeyBytes = 1024
	// minBucketLen and maxBucketLen are S3's limits on a bucket name.
	minBucketLen = 3
	maxBucketLen = 63

	defaultRegion         = "us-east-1"
	dialTimeout           = 10 * time.Second // connection setup
	tlsHandshakeTimeout   = 10 * time.Second // handshake
	responseHeaderTimeout = 30 * time.Second // wait for the first answer bytes
)

// Config describes one MinIO endpoint. The caller keeps ownership of the key slices.
type Config struct {
	URL       *url.URL
	Region    string
	AccessKey []byte
	SecretKey []byte
	CAFile    string
	Now       func() time.Time
}

// Object is one stored object as MinIO describes it. ETag keeps its quotes.
type Object struct {
	Key          string
	ETag         string
	Size         int64
	LastModified time.Time
}

// Listing is one page of objects.
type Listing struct {
	Objects   []Object
	Truncated bool
}

// Error is an answer MinIO gave. Message is scrubbed of credentials, cleaned and cut.
type Error struct {
	Status        int
	Code, Message string
}

func (e *Error) Error() string {
	s := "s3: status " + strconv.Itoa(e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

var (
	// ErrNotFound reports a missing key.
	ErrNotFound = errors.New("s3: no such key")
	// ErrChanged reports a failed If-Match: the object is no longer the one listed.
	ErrChanged = errors.New("s3: the object changed")
)

// IsNoBucket reports whether err says the bucket does not exist.
func IsNoBucket(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "NoSuchBucket"
}

// Client talks to one MinIO endpoint.
type Client struct {
	hc        *http.Client
	base      *url.URL
	region    string
	accessKey []byte
	secretKey []byte
	now       func() time.Time
}

// New builds a client that trusts the system roots plus CAFile, refuses redirects and ignores proxies.
func New(cfg Config) (*Client, error) {
	u := cfg.URL
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("s3: the endpoint needs an http or https URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("s3: the endpoint URL must hold no user, query or fragment")
	}
	if len(cfg.AccessKey) == 0 || len(cfg.SecretKey) == 0 {
		return nil, errors.New("s3: the access key and the secret key are required")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("s3: read the CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("s3: the CA file holds no certificate")
		}
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	region := cfg.Region
	if region == "" {
		region = defaultRegion
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	base := *u
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawPath = ""
	return &Client{
		hc: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		base:      &base,
		region:    region,
		accessKey: bytes.Clone(cfg.AccessKey),
		secretKey: bytes.Clone(cfg.SecretKey),
		now:       now,
	}, nil
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)

func checkBucket(bucket string) error {
	if len(bucket) < minBucketLen || len(bucket) > maxBucketLen || !bucketName.MatchString(bucket) ||
		strings.Contains(bucket, "..") {
		return errors.New("s3: the bucket name breaks S3's rules")
	}
	return nil
}

func checkKey(key string) error {
	if key == "" || len(key) > maxKeyBytes || !utf8.ValidString(key) {
		return errors.New("s3: the key is empty, over 1024 bytes or not UTF-8")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "." || seg == ".." {
			return errors.New("s3: the key holds a dot segment")
		}
	}
	for _, r := range key {
		if unicode.IsControl(r) {
			return errors.New("s3: the key holds a control character")
		}
	}
	return nil
}

// request is one signed call. The scrub list is what must never reach an error.
type request struct {
	method, bucket, key string
	query               [][2]string
	ifMatch             string
}

func (c *Client) do(ctx context.Context, r request) (*http.Response, []string, error) {
	if err := checkBucket(r.bucket); err != nil {
		return nil, nil, err
	}
	path := "/" + r.bucket
	if r.key != "" {
		path += "/" + r.key
	}
	uri := canonicalURI(c.base.Path + path)
	query := canonicalQuery(r.query)

	u := *c.base
	parsed, err := url.Parse(u.Scheme + "://" + u.Host + uri)
	if err != nil {
		return nil, nil, errors.New("s3: the request path is not valid")
	}
	parsed.RawQuery = query

	now := c.now().UTC()
	headers := map[string]string{
		"host":                 u.Host,
		"x-amz-content-sha256": emptyBodyHash,
		"x-amz-date":           now.Format(stampLayout),
	}
	if r.ifMatch != "" {
		headers["if-match"] = r.ifMatch
	}
	auth, sig := sign(signInput{
		Method: r.method, URI: uri, Query: query, Headers: headers, PayloadHash: emptyBodyHash,
		Region: c.region, AccessKey: c.accessKey, SecretKey: c.secretKey, Time: now,
	})

	req, err := http.NewRequestWithContext(ctx, r.method, parsed.String(), nil)
	if err != nil {
		return nil, nil, errors.New("s3: the request is not valid")
	}
	for name, v := range headers {
		if name != "host" {
			req.Header.Set(name, v)
		}
	}
	req.Header.Set("Authorization", auth)

	scrub := []string{string(c.accessKey), string(c.secretKey), sig}
	resp, err := c.hc.Do(req)
	if err != nil {
		// The *url.Error holds the URL; the inner error is enough.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, fmt.Errorf("s3: %s: %w", strings.ToLower(r.method), err)
	}
	return resp, scrub, nil
}

// List returns one ListObjectsV2 page of at most limit keys under prefix.
func (c *Client) List(ctx context.Context, bucket, prefix string, limit int) (Listing, error) {
	if limit < 1 {
		return Listing{}, errors.New("s3: limit must be at least 1")
	}
	if limit > maxKeys {
		limit = maxKeys
	}
	if len(prefix) > maxKeyBytes || !utf8.ValidString(prefix) {
		return Listing{}, errors.New("s3: the prefix is over 1024 bytes or not UTF-8")
	}
	q := [][2]string{{"list-type", "2"}, {"max-keys", strconv.Itoa(limit)}}
	if prefix != "" {
		q = append(q, [2]string{"prefix", prefix})
	}
	resp, scrub, err := c.do(ctx, request{method: http.MethodGet, bucket: bucket, query: q})
	if err != nil {
		return Listing{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Listing{}, statusError(resp, scrub)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxListBytes+1))
	if err != nil {
		return Listing{}, fmt.Errorf("s3: read the listing: %w", err)
	}
	if len(raw) > MaxListBytes {
		return Listing{}, fmt.Errorf("s3: the listing is over %d bytes (MaxListBytes)", MaxListBytes)
	}
	var doc struct {
		IsTruncated bool `xml:"IsTruncated"`
		Contents    []struct {
			Key          string    `xml:"Key"`
			LastModified time.Time `xml:"LastModified"`
			ETag         string    `xml:"ETag"`
			Size         int64     `xml:"Size"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return Listing{}, errors.New("s3: the listing is not valid XML")
	}
	out := Listing{Objects: make([]Object, 0, len(doc.Contents)), Truncated: doc.IsTruncated}
	for _, o := range doc.Contents {
		out.Objects = append(out.Objects, Object{Key: o.Key, ETag: o.ETag, Size: o.Size, LastModified: o.LastModified})
	}
	return out, nil
}

// Head returns the object's metadata.
func (c *Client) Head(ctx context.Context, bucket, key string) (Object, error) {
	if err := checkKey(key); err != nil {
		return Object{}, err
	}
	resp, scrub, err := c.do(ctx, request{method: http.MethodHead, bucket: bucket, key: key})
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Object{}, statusError(resp, scrub)
	}
	return objectOf(key, resp)
}

// Get streams the object, on condition that its ETag is still etag. The caller closes the body.
func (c *Client) Get(ctx context.Context, bucket, key, etag string) (io.ReadCloser, Object, error) {
	if err := checkKey(key); err != nil {
		return nil, Object{}, err
	}
	if etag == "" {
		return nil, Object{}, errors.New("s3: a read needs the ETag it expects")
	}
	resp, scrub, err := c.do(ctx, request{method: http.MethodGet, bucket: bucket, key: key, ifMatch: etag})
	if err != nil {
		return nil, Object{}, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, Object{}, statusError(resp, scrub)
	}
	obj, err := objectOf(key, resp)
	if err != nil {
		resp.Body.Close()
		return nil, Object{}, err
	}
	return resp.Body, obj, nil
}

// Delete removes the object. MinIO answers 204 for a key that is already gone.
func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	resp, scrub, err := c.do(ctx, request{method: http.MethodDelete, bucket: bucket, key: key})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return statusError(resp, scrub)
	}
	return nil
}

func objectOf(key string, resp *http.Response) (Object, error) {
	if resp.ContentLength < 0 {
		return Object{}, errors.New("s3: the answer carries no length")
	}
	o := Object{Key: key, ETag: resp.Header.Get("ETag"), Size: resp.ContentLength}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		t, err := http.ParseTime(lm)
		if err != nil {
			return Object{}, errors.New("s3: the answer's Last-Modified is not a date")
		}
		o.LastModified = t
	}
	return o, nil
}

// statusError reads a bounded error body and maps the status.
func statusError(resp *http.Response, scrub []string) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBytes))
	code, msg := parseError(raw)
	code, msg = clean(code, scrub), clean(msg, scrub)
	switch {
	case resp.StatusCode == http.StatusPreconditionFailed:
		return ErrChanged
	case resp.StatusCode == http.StatusNotFound && code != "NoSuchBucket":
		return ErrNotFound
	}
	return &Error{Status: resp.StatusCode, Code: code, Message: msg}
}

// parseError pulls Code and Message out of a possibly cut XML error. Control characters go first:
// they are illegal in XML and would stop the decoder.
func parseError(raw []byte) (code, message string) {
	raw = bytes.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, raw)
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = false
	var in string
	var c, m strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			in = t.Name.Local
		case xml.EndElement:
			in = ""
		case xml.CharData:
			switch in {
			case "Code":
				c.Write(t)
			case "Message":
				m.Write(t)
			}
		}
	}
	return c.String(), m.String()
}

var signatureValue = regexp.MustCompile(`(?i)signature=[0-9a-f]+`)

// clean removes credentials, then control characters, then cuts to maxMessageChars.
func clean(s string, secrets []string) string {
	s = strings.ToValidUTF8(s, "")
	s = strip(s)
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	s = signatureValue.ReplaceAllString(s, "signature=***")
	s = strip(s)
	if utf8.RuneCountInString(s) > maxMessageChars {
		s = string([]rune(s)[:maxMessageChars])
	}
	return s
}

func strip(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
