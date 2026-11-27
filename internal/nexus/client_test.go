package nexus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testUser     = "sealift-import"
	testPassword = "test-password"
)

func newClient(t *testing.T, srv *httptest.Server, caFile string) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{URL: u, Repository: "npm-hosted", User: testUser, Password: []byte(testPassword), CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientErrorsCarryNoCredentials(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPassword))
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "denied for "+r.Header.Get("Authorization")+" password "+testPassword+" token "+basic)
	}))
	gone := httptest.NewServer(http.NotFoundHandler())
	goneClient := newClient(t, gone, "")
	gone.Close()

	calls := map[string]func(*Client) error{
		"check": func(c *Client) error { return c.CheckRepository(context.Background()) },
		"fetch": func(c *Client) error {
			_, err := c.Fetch(context.Background(), "left-pad", "1.0.0", io.Discard, 1<<20)
			return err
		},
		"upload": func(c *Client) error {
			return c.Upload(context.Background(), "left-pad-1.0.0.tgz", strings.NewReader("x"))
		},
	}
	for name, call := range calls {
		for label, c := range map[string]*Client{"echo": newClient(t, echo, ""), "unreachable": goneClient} {
			err := call(c)
			if err == nil {
				t.Fatalf("%s/%s: no error", name, label)
			}
			for _, secret := range []string{testPassword, basic} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("%s/%s: error holds %q: %v", name, label, secret, err)
				}
			}
		}
	}
	echo.Close()
}

func TestClientRefusesRedirect(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	c := newClient(t, srv, "")

	err := c.CheckRepository(context.Background())
	var ne *Error
	if !asError(err, &ne) || ne.Status != http.StatusFound {
		t.Fatalf("want a 302 Error, got %v", err)
	}
	_, err = c.Fetch(context.Background(), "left-pad", "1.0.0", io.Discard, 10)
	if !asError(err, &ne) || ne.Status != http.StatusFound {
		t.Fatalf("fetch: want a 302 Error, got %v", err)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the redirect target saw %d requests", n)
	}
}

func asError(err error, target **Error) bool {
	return errors.As(err, target)
}

func TestClientTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"name":"npm-hosted","format":"npm","type":"hosted"}]`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)

	t.Run("no CA fails verification", func(t *testing.T) {
		err := newClient(t, srv, "").CheckRepository(context.Background())
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("want a certificate error, got %v", err)
		}
	})
	t.Run("CA file passes", func(t *testing.T) {
		if err := newClient(t, srv, ca).CheckRepository(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing CA file", func(t *testing.T) {
		missing := filepath.Join(dir, "absent.pem")
		_, err := New(Config{URL: u, Repository: "npm-hosted", CAFile: missing})
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("want an error naming %s, got %v", missing, err)
		}
	})
	t.Run("CA file without certificate", func(t *testing.T) {
		_, err := New(Config{URL: u, Repository: "npm-hosted", CAFile: junk})
		if err == nil || !strings.Contains(err.Error(), junk) {
			t.Fatalf("want an error naming %s, got %v", junk, err)
		}
	})
}

func TestClientNew(t *testing.T) {
	good, _ := url.Parse("https://nexus.example.internal")
	ftp, _ := url.Parse("ftp://nexus.example.internal")
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"no url":     {Config{Repository: "r"}, "http or https"},
		"ftp":        {Config{URL: ftp, Repository: "r"}, "http or https"},
		"repository": {Config{URL: good}, "repository is empty"},
	} {
		_, err := New(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}

func TestErrorMessageCleaned(t *testing.T) {
	body := strings.Repeat("ab\x07\ncd\x00", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	err := newClient(t, srv, "").CheckRepository(context.Background())
	var ne *Error
	if !asError(err, &ne) || ne.Status != 503 {
		t.Fatalf("want a 503 Error, got %v", err)
	}
	want := strings.Repeat("abcd", 100)[:300]
	if ne.Message != want {
		t.Fatalf("message = %q, want %q", ne.Message, want)
	}
}

func TestClientRepositoryAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"missing":    {`[{"name":"other","format":"npm","type":"hosted"}]`, `"npm-hosted" not found`},
		"wrong form": {`[{"name":"npm-hosted","format":"maven2","type":"hosted"}]`, "maven2 hosted"},
		"wrong type": {`[{"name":"npm-hosted","format":"npm","type":"proxy"}]`, "npm proxy"},
		"not json":   {`<html>`, "not readable"},
		"found":      {`[{"name":"npm-hosted","format":"npm","type":"hosted"}]`, ""},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, tc.body) }))
		err := newClient(t, srv, "").CheckRepository(context.Background())
		srv.Close()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}

func TestFetchLimitAndPath(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		_, _ = io.WriteString(w, strings.Repeat("z", 50))
	}))
	defer srv.Close()
	c := newClient(t, srv, "")
	var sb strings.Builder
	found, err := c.Fetch(context.Background(), "@scope/pkg", "1.2.3", &sb, 50)
	if err != nil || !found || sb.Len() != 50 {
		t.Fatalf("found=%v err=%v len=%d", found, err, sb.Len())
	}
	if got := path.Load(); got != "/repository/npm-hosted/@scope/pkg/-/pkg-1.2.3.tgz" {
		t.Fatalf("path = %v", got)
	}
	if _, err := c.Fetch(context.Background(), "pkg", "1.0.0", io.Discard, 49); err == nil || !strings.Contains(err.Error(), "larger than 49") {
		t.Fatalf("want a limit error, got %v", err)
	}
	if _, err := c.Fetch(context.Background(), "../x", "1.0.0", io.Discard, 49); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("want a path error, got %v", err)
	}
}

func TestClientIgnoresProxyEnvironment(t *testing.T) {
	tr, ok := newClient(t, httptest.NewServer(http.NotFoundHandler()), "").http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not an http.Transport")
	}
	// ProxyFromEnvironment reads the environment once per process, so a
	// setenv test would prove nothing.
	if tr.Proxy != nil {
		t.Fatal("the client routes requests through a proxy, which would carry the credentials")
	}
}

func TestRepositoryFieldsCleaned(t *testing.T) {
	hostile := strings.Repeat("\x1b[31m\x07x", 50000)
	for name, body := range map[string]string{
		"format": `[{"name":"npm-hosted","format":` + jsonString(hostile) + `,"type":"hosted"}]`,
		"type":   `[{"name":"npm-hosted","format":"npm","type":` + jsonString(hostile) + `}]`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		err := newClient(t, srv, "").CheckRepository(context.Background())
		srv.Close()
		if err == nil {
			t.Fatalf("%s: want an error", name)
		}
		if !strings.Contains(err.Error(), "not npm hosted") || len(err.Error()) > 2*maxMessageChars || strings.ContainsAny(err.Error(), "\x1b\x07") {
			t.Errorf("%s: %d bytes, %q", name, len(err.Error()), err.Error()[:80])
		}
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestTransportErrorsCut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n"+strings.Repeat("a", 100000)+"\r\n\r\n")
		conn.Close()
	}))
	defer srv.Close()
	c := newClient(t, srv, "")
	_, fetchErr := c.Fetch(context.Background(), "pkg", "1.0.0", io.Discard, 10)
	for name, err := range map[string]error{
		"check":  c.CheckRepository(context.Background()),
		"fetch":  fetchErr,
		"upload": c.Upload(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("x")),
	} {
		if err == nil || !strings.Contains(err.Error(), "unreachable") {
			t.Errorf("%s: want an unreachable error, got %v", name, err)
			continue
		}
		if len(err.Error()) > 2*maxMessageChars {
			t.Errorf("%s: %d bytes", name, len(err.Error()))
		}
	}
}

func TestFetchCopyErrorCut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "body") }))
	defer srv.Close()
	c := newClient(t, srv, "")
	_, err := c.Fetch(context.Background(), "pkg", "1.0.0", errWriter{errors.New(strings.Repeat("w\x07", 5000))}, 10)
	if err == nil || len(err.Error()) > 2*maxMessageChars || strings.Contains(err.Error(), "\x07") {
		t.Fatalf("got %v", err)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestUploadSendsTheTarballAlone(t *testing.T) {
	var requests atomic.Int32
	type part struct{ name, body string }
	var parts []part
	var method, path, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		method, path, query = r.Method, r.URL.Path, r.URL.RawQuery
		mr, err := r.MultipartReader()
		if err != nil {
			t.Errorf("multipart: %v", err)
			return
		}
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			parts = append(parts, part{p.FormName(), string(b)})
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClient(t, srv, "")
	if err := c.Upload(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("tarball bytes")); err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
	if method != http.MethodPost || path != "/service/rest/v1/components" || query != "repository=npm-hosted" {
		t.Errorf("request = %s %s?%s", method, path, query)
	}
	if len(parts) != 1 || parts[0].name != "npm.asset" || parts[0].body != "tarball bytes" {
		t.Errorf("form parts = %+v, want only npm.asset with the tarball", parts)
	}
}

func TestUploadUsesTheFormatField(t *testing.T) {
	for _, tc := range []struct {
		format     Format
		file, want string
	}{
		{"", "pkg-1.0.0.tgz", "npm.asset"},
		{FormatNPM, "pkg-1.0.0.tgz", "npm.asset"},
		{FormatPyPI, "six-1.16.0-py2.py3-none-any.whl", "pypi.asset"},
	} {
		var field, file, query string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query = r.URL.RawQuery
			mr, err := r.MultipartReader()
			if err != nil {
				t.Errorf("multipart: %v", err)
				return
			}
			if p, err := mr.NextPart(); err == nil {
				field, file = p.FormName(), p.FileName()
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		u, _ := url.Parse(srv.URL)
		c, err := New(Config{URL: u, Repository: "pypi", Format: tc.format, User: testUser, Password: []byte(testPassword)})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Upload(context.Background(), tc.file, strings.NewReader("bytes")); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if field != tc.want || file != tc.file || query != "repository=pypi" {
			t.Errorf("format %q: field %q file %q query %q, want %q %q", tc.format, field, file, query, tc.want, tc.file)
		}
	}
}

func TestClientRefusesAnUnknownFormat(t *testing.T) {
	u, _ := url.Parse("https://nexus.example.internal")
	_, err := New(Config{URL: u, Repository: "r", Format: "maven2"})
	if err == nil || err.Error() != `nexus format "maven2" is neither npm nor pypi` {
		t.Fatalf("got %v", err)
	}
}

func TestCheckRepositoryFormat(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		body     string
		want     string
		wrapsErr bool
	}{
		"pypi hosted": {200, `[{"name":"npm-hosted","format":"npm","type":"hosted"},{"name":"pypi","format":"pypi","type":"hosted"}]`, "", false},
		"npm hosted":  {200, `[{"name":"pypi","format":"npm","type":"hosted"}]`, `nexus repository "pypi" is npm hosted, not pypi hosted`, true},
		"pypi proxy":  {200, `[{"name":"pypi","format":"pypi","type":"proxy"}]`, `nexus repository "pypi" is pypi proxy, not pypi hosted`, true},
		"absent":      {200, `[{"name":"npm-hosted","format":"npm","type":"hosted"}]`, `nexus repository "pypi" not found`, true},
		"500":         {500, "down", "nexus answered 500: down", false},
		"403":         {403, "denied", "nexus answered 403: denied", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		u, _ := url.Parse(srv.URL)
		c, err := New(Config{URL: u, Repository: "pypi", Format: FormatPyPI, User: testUser, Password: []byte(testPassword)})
		if err != nil {
			t.Fatal(err)
		}
		err = c.CheckRepository(context.Background())
		srv.Close()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || err.Error() != tc.want):
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		case errors.Is(err, ErrRepository) != tc.wrapsErr:
			t.Errorf("%s: wraps ErrRepository %v, want %v", name, errors.Is(err, ErrRepository), tc.wrapsErr)
		}
	}
}

func TestCheckRepositoryNPMWrapsErrRepository(t *testing.T) {
	for _, body := range []string{
		`[{"name":"other","format":"npm","type":"hosted"}]`,
		`[{"name":"npm-hosted","format":"pypi","type":"hosted"}]`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		err := newClient(t, srv, "").CheckRepository(context.Background())
		srv.Close()
		if !errors.Is(err, ErrRepository) {
			t.Errorf("%s: %v does not wrap ErrRepository", body, err)
		}
	}
}

func TestNexusErrorsCarryNoPipSecret(t *testing.T) {
	const pipUser, pipPassword = "sealift-pip", "pip-test-password"
	basic := base64.StdEncoding.EncodeToString([]byte(pipUser + ":" + pipPassword))
	leak := "denied for password " + pipPassword + " token " + basic
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, leak+" "+r.Header.Get("Authorization"))
	}))
	defer echo.Close()
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<a href="http://`+pipUser+`:`+pipPassword+`@other.example/`+basic+`/six-1.16.0-py2.py3-none-any.whl">six</a>`)
	}))
	defer page.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	pipClient := func(srv *httptest.Server) *Client {
		u, _ := url.Parse(srv.URL)
		c, err := New(Config{URL: u, Repository: "pypi", Format: FormatPyPI, User: pipUser, Password: []byte(pipPassword)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	calls := map[string]func(*Client) error{
		"check": func(c *Client) error { return c.CheckRepository(context.Background()) },
		"fetch file": func(c *Client) error {
			_, err := c.FetchFile(context.Background(), "six", "six-1.16.0-py2.py3-none-any.whl", io.Discard, 1<<20)
			return err
		},
		"upload": func(c *Client) error {
			return c.Upload(context.Background(), "six-1.16.0-py2.py3-none-any.whl", strings.NewReader("x"))
		},
	}
	for name, call := range calls {
		for label, srv := range map[string]*httptest.Server{"echo": echo, "unreachable": gone, "link": page} {
			err := call(pipClient(srv))
			if err == nil {
				if label == "link" && name != "fetch file" {
					continue
				}
				t.Fatalf("%s/%s: no error", name, label)
			}
			for _, secret := range []string{pipPassword, basic} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("%s/%s: error holds %q: %v", name, label, secret, err)
				}
			}
		}
	}
}

// searchServer answers the asset search with body and records each query.
func searchServer(t *testing.T, body string, queries *[]url.Values) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/service/rest/v1/search/assets" {
			http.NotFound(w, r)
			return
		}
		if queries != nil {
			*queries = append(*queries, r.URL.Query())
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAssetReadsUploaderAndDate(t *testing.T) {
	var queries []url.Values
	srv := searchServer(t, `{"items":[
		{"path":"@types/node/-/node-22.10.1.tgz","uploader":"someone-else","lastModified":"2024-01-01T00:00:00.000+00:00"},
		{"path":"@types/node/-/node-22.10.2.tgz","uploader":"ci-publish","lastModified":"2025-10-03T09:12:44.123+00:00"}
	],"continuationToken":null}`, &queries)
	facts, found, err := newClient(t, srv, "").Asset(context.Background(), "@types/node", "22.10.2")
	if err != nil || !found {
		t.Fatalf("found %v, err %v", found, err)
	}
	if facts.Uploader != "ci-publish" || !facts.LastModified.Equal(time.Date(2025, 10, 3, 9, 12, 44, 123e6, time.UTC)) {
		t.Fatalf("facts = %+v", facts)
	}
	q := queries[0]
	if q.Get("repository") != "npm-hosted" || q.Get("name") != "@types/node" || q.Get("version") != "22.10.2" {
		t.Fatalf("query = %v", q)
	}
}

func TestAssetFileReadsAPypiFileByItsPath(t *testing.T) {
	file := "numpy-2.1.3-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
	var queries []url.Values
	srv := searchServer(t, `{"items":[
		{"path":"packages/numpy/2.1.3/numpy-2.1.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl","uploader":"other"},
		{"path":"packages/numpy/2.1.3/`+file+`","uploader":"jo","lastModified":"2025-09-02T10:00:00Z"}
	]}`, &queries)
	facts, found, err := newClient(t, srv, "").AssetFile(context.Background(), "numpy", file)
	if err != nil || !found || facts.Uploader != "jo" || facts.LastModified.Year() != 2025 {
		t.Fatalf("facts %+v, found %v, err %v", facts, found, err)
	}
	if q := queries[0]; q.Get("repository") != "npm-hosted" || q.Get("name") != "numpy" {
		t.Fatalf("query = %v", q)
	}
}

func TestAssetBoundsAndScrubsTheAnswer(t *testing.T) {
	big := searchServer(t, `{"items":[{"path":"`+strings.Repeat("a", 2<<20)+`"}]}`, nil)
	if _, found, err := newClient(t, big, "").Asset(context.Background(), "left-pad", "1.0.0"); err == nil || found {
		t.Fatalf("a 2 MiB answer: found %v, err %v", found, err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPassword))
	head := "\x1b[31m" + testPassword + " " + basic + " "
	cases := map[string]struct{ uploader, want string }{
		"short": {
			uploader: "jo " + head + "\x07",
			want:     "jo [31m[redacted] [redacted] ",
		},
		"long": {
			uploader: head + strings.Repeat("u", 150),
			want:     ("[31m[redacted] [redacted] " + strings.Repeat("u", 150))[:100],
		},
	}
	for name, tc := range cases {
		body, _ := json.Marshal(map[string]any{"items": []map[string]string{{"path": "left-pad/-/left-pad-1.0.0.tgz", "uploader": tc.uploader, "lastModified": "not a date"}}})
		srv := searchServer(t, string(body), nil)
		facts, found, err := newClient(t, srv, "").Asset(context.Background(), "left-pad", "1.0.0")
		if err != nil || !found {
			t.Fatalf("%s: found %v, err %v", name, found, err)
		}
		if facts.Uploader != tc.want {
			t.Errorf("%s: uploader = %q, want %q", name, facts.Uploader, tc.want)
		}
		if !facts.LastModified.IsZero() {
			t.Errorf("%s: an unreadable date reads as %v", name, facts.LastModified)
		}
	}
}

func TestAssetAnswersNotFoundForAnEmptySearch(t *testing.T) {
	srv := searchServer(t, `{"items":[],"continuationToken":null}`, nil)
	c := newClient(t, srv, "")
	if _, found, err := c.Asset(context.Background(), "left-pad", "1.0.0"); err != nil || found {
		t.Fatalf("npm: found %v, err %v", found, err)
	}
	if _, found, err := c.AssetFile(context.Background(), "idna", "idna-3.10-py3-none-any.whl"); err != nil || found {
		t.Fatalf("pypi: found %v, err %v", found, err)
	}
}

func TestAssetReportsNexusStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, found, err := newClient(t, srv, "").Asset(context.Background(), "left-pad", "1.0.0")
	var e *Error
	if found || !asError(err, &e) || e.Status != http.StatusForbidden {
		t.Fatalf("found %v, err %v", found, err)
	}
}

func TestAssetSearchGivesUpOnATricklingNexus(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		for {
			if _, err := w.Write([]byte(" ")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()
	defer close(stop)
	c := newClient(t, srv, "")
	c.searchTimeout = 200 * time.Millisecond
	start := time.Now()
	_, found, err := c.Asset(context.Background(), "left-pad", "1.0.0")
	if err == nil || found {
		t.Fatalf("found %v, err %v", found, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the search held the caller for %v", d)
	}
}

func TestClientSearchesAssetsWithinThirtySeconds(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if c := newClient(t, srv, ""); c.searchTimeout != 30*time.Second {
		t.Fatalf("searchTimeout = %v", c.searchTimeout)
	}
}

func TestAssetFileMatchesTheWholeFileName(t *testing.T) {
	srv := searchServer(t, `{"items":[
		{"path":"packages/six/1.16.0/xsix-1.16.0-py2.py3-none-any.whl","uploader":"other"}
	]}`, nil)
	if _, found, err := newClient(t, srv, "").AssetFile(context.Background(), "six", "six-1.16.0-py2.py3-none-any.whl"); err != nil || found {
		t.Fatalf("a longer file name ending the same way: found %v, err %v", found, err)
	}
}
