package nexus

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MorganKryze/sealift/internal/importtest"
)

const (
	sixFile = "six-1.16.0-py2.py3-none-any.whl"
	sixBody = "six wheel bytes"
)

func pypiClient(t *testing.T, base *url.URL) *Client {
	t.Helper()
	c, err := New(Config{URL: base, Repository: "pypi", Format: FormatPyPI, User: testUser, Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fetchFile(t *testing.T, c *Client, project, file string, limit int64) (string, bool, error) {
	t.Helper()
	var b bytes.Buffer
	found, err := c.FetchFile(context.Background(), project, file, &b, limit)
	return b.String(), found, err
}

func TestFetchFileFindsTheExactFile(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(n *importtest.PyPINexus)
		found bool
		body  string
	}{
		"page 404": {func(*importtest.PyPINexus) {}, false, ""},
		"other files only": {func(n *importtest.PyPINexus) {
			n.Put("six", "six-1.15.0-py2.py3-none-any.whl", []byte("older"))
		}, false, ""},
		"relative link with a sha256 fragment": {func(n *importtest.PyPINexus) {
			n.Put("six", "six-1.15.0-py2.py3-none-any.whl", []byte("older"))
			n.Put("six", sixFile, []byte(sixBody))
		}, true, sixBody},
		"same-origin absolute link": {func(n *importtest.PyPINexus) {
			n.Put("six", sixFile, []byte(sixBody))
			n.Link(sixFile, n.URL.String()+n.FilePath("six", sixFile)+"#sha256=00")
		}, true, sixBody},
		"last segment only ends with the name": {func(n *importtest.PyPINexus) {
			n.Put("six", "xsix-1.16.0-py2.py3-none-any.whl", []byte("another project"))
		}, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, "pypi")
			tc.setup(n)
			body, found, err := fetchFile(t, pypiClient(t, n.URL), "six", sixFile, 1<<20)
			if err != nil || found != tc.found || body != tc.body {
				t.Fatalf("found %v body %q err %v, want found %v body %q", found, body, err, tc.found, tc.body)
			}
		})
	}
}

func TestFetchFileReadsTheLabPage(t *testing.T) {
	// The anchor as Nexus 3.96.5 served it in the lab, spread over lines.
	page := `<html><body><h1>Links for mypy-extensions</h1>
    <a href="../../packages/mypy-extensions/1.0.0/mypy_extensions-1.0.0-py3-none-any.whl#sha256=4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d"
       rel="internal"
       data-core-metadata="sha256=617d60dffb00826a22f5662114d8111d02fa29ffb1ec67e39d6814084ef75486"
       data-requires-python="&gt;=3.5"
       data-dist-info-metadata="sha256=617d60dffb00826a22f5662114d8111d02fa29ffb1ec67e39d6814084ef75486">
      mypy_extensions-1.0.0-py3-none-any.whl
    </a><br/>
</body></html>`
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/") {
			_, _ = io.WriteString(w, page)
			return
		}
		_, _ = io.WriteString(w, "wheel")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/nexus/")
	body, found, err := fetchFile(t, pypiClient(t, u), "mypy-extensions", "mypy_extensions-1.0.0-py3-none-any.whl", 10)
	if err != nil || !found || body != "wheel" {
		t.Fatalf("found %v body %q err %v", found, body, err)
	}
	want := []string{
		"/nexus/repository/pypi/simple/mypy-extensions/",
		"/nexus/repository/pypi/packages/mypy-extensions/1.0.0/mypy_extensions-1.0.0-py3-none-any.whl",
	}
	if !slices.Equal(paths, want) {
		t.Fatalf("paths %q, want %q", paths, want)
	}
}

func TestFetchFileFollowsOnlyTheRepositoryLink(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	for name, tc := range map[string]struct {
		href func(n *importtest.PyPINexus) string
		want string
	}{
		"another host": {func(n *importtest.PyPINexus) string {
			return "http://other.example:" + n.URL.Port() + "/repository/pypi/packages/six/1.16.0/" + sixFile
		}, "it points to http://other.example:"},
		"another port": {func(*importtest.PyPINexus) string {
			return other.URL + "/repository/pypi/packages/six/1.16.0/" + sixFile
		}, "it points to " + other.URL + ", not http://127.0.0.1:"},
		"another scheme": {func(n *importtest.PyPINexus) string {
			return "https://" + n.URL.Host + "/repository/pypi/packages/six/1.16.0/" + sixFile
		}, "it points to https://127.0.0.1:"},
		"user information": {func(n *importtest.PyPINexus) string {
			return "http://someone@" + n.URL.Host + "/repository/pypi/packages/six/1.16.0/" + sixFile
		}, "it carries user information"},
		"another repository": {func(*importtest.PyPINexus) string {
			return "../../../npm-hosted/packages/six/1.16.0/" + sixFile
		}, "its path is outside /repository/pypi/"},
		"outside every repository": {func(*importtest.PyPINexus) string {
			return "/service/rest/v1/" + sixFile
		}, "its path is outside /repository/pypi/"},
		"escaped dots": {func(*importtest.PyPINexus) string {
			return "../../packages/%2e%2e/%2e%2e/%2e%2e/npm-hosted/" + sixFile
		}, "its path holds a percent escape"},
		"a query": {func(*importtest.PyPINexus) string {
			return "../../packages/six/1.16.0/" + sixFile + "?redirect=1"
		}, "it carries a query"},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, "pypi")
			n.Put("six", sixFile, []byte(sixBody))
			href := tc.href(n)
			n.Link(sixFile, href)
			_, found, err := fetchFile(t, pypiClient(t, n.URL), "six", sixFile, 1<<20)
			wantPrefix := `nexus lists the file at a link that leaves the repository: `
			if found || err == nil || !strings.HasPrefix(err.Error(), wantPrefix) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("found %v err %v, want %q", found, err, tc.want)
			}
			if !strings.Contains(err.Error(), `"`+href+`"`) {
				t.Errorf("the reason does not quote the link: %v", err)
			}
			if reqs := n.Requests(); len(reqs) != 1 || reqs[0] != "GET /repository/pypi/simple/six/" {
				t.Errorf("requests %q, want the page only", reqs)
			}
		})
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("another server saw %d requests", n)
	}
}

func TestFetchFileBounds(t *testing.T) {
	anchor := `<a href="../../packages/six/1.16.0/` + sixFile + `">` + sixFile + "</a>\n"
	for name, tc := range map[string]struct {
		page  string
		limit int64
		want  string
	}{
		"page of 8 MiB": {
			page:  anchor + strings.Repeat(" ", 8388608-len(anchor)),
			limit: 1 << 20,
		},
		"page over 8 MiB": {
			page:  anchor + strings.Repeat(" ", 8388609-len(anchor)),
			limit: 1 << 20,
			want:  "nexus simple page is larger than 8388608 bytes",
		},
		"100000 links": {
			page:  strings.Repeat(`<a href="other.whl">x</a>`, 99999) + anchor,
			limit: 1 << 20,
		},
		"over 100000 links": {
			page:  strings.Repeat(`<a href="other.whl">x</a>`, 100000) + anchor,
			limit: 1 << 20,
			want:  "nexus simple page lists more than 100000 links",
		},
		"body at the limit": {page: anchor, limit: 15},
		"body over the limit": {
			page:  anchor,
			limit: 14,
			want:  "nexus copy is larger than 14 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/") {
					_, _ = io.WriteString(w, tc.page)
					return
				}
				_, _ = io.WriteString(w, sixBody)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			body, found, err := fetchFile(t, pypiClient(t, u), "six", sixFile, tc.limit)
			if tc.want == "" {
				if err != nil || !found || body != sixBody {
					t.Fatalf("found %v body %q err %v", found, body, err)
				}
				return
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFetchFileAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(n *importtest.PyPINexus)
		found bool
		want  string
	}{
		"page answers 500": {func(n *importtest.PyPINexus) {
			n.SetStatus(n.PagePath("six"), 500)
		}, false, "nexus answered 500: status 500 from the fake"},
		"file answers 403": {func(n *importtest.PyPINexus) {
			n.Put("six", sixFile, []byte(sixBody))
			n.SetStatus(n.FilePath("six", sixFile), 403)
		}, false, "nexus answered 403: status 403 from the fake"},
		"file answers 404": {func(n *importtest.PyPINexus) {
			n.Put("six", sixFile, []byte(sixBody))
			n.SetStatus(n.FilePath("six", sixFile), 404)
		}, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, "pypi")
			tc.setup(n)
			_, found, err := fetchFile(t, pypiClient(t, n.URL), "six", sixFile, 1<<20)
			if found != tc.found || (tc.want == "" && err != nil) || (tc.want != "" && (err == nil || err.Error() != tc.want)) {
				t.Fatalf("found %v err %v, want found %v err %q", found, err, tc.found, tc.want)
			}
		})
	}
}

func TestFetchFileRefusesUnusableNames(t *testing.T) {
	n := importtest.NewPyPINexus(t, "pypi")
	c := pypiClient(t, n.URL)
	for _, tc := range []struct{ project, file string }{
		{"../npm-hosted", sixFile},
		{"six/x", sixFile},
		{"six", "a/" + sixFile},
		{"six", "%2e%2e"},
		{"", sixFile},
		{"six", ""},
	} {
		_, _, err := fetchFile(t, c, tc.project, tc.file, 10)
		if err == nil || err.Error() != "project or file name is not usable in a URL path" {
			t.Errorf("%q %q: %v", tc.project, tc.file, err)
		}
	}
	if reqs := n.Requests(); len(reqs) != 0 {
		t.Fatalf("requests %q", reqs)
	}
}

func TestSimpleLinksReadsAnchors(t *testing.T) {
	page := `<html><abbr href="abbr.whl">x</abbr><a data-href="data.whl" href="one.whl">1</a>
<A
   HREF='two.whl#sha256=00'
   rel="internal">2</A>
<a rel=internal href=three.whl>3</a>
<a title="a > b" href="four&amp;more.whl">4</a>
<a name="no-link">5</a>
<area href="area.whl">
<a href="last.whl"`
	got, err := simpleLinks([]byte(page))
	want := []string{"one.whl", "two.whl#sha256=00", "three.whl", "four&more.whl", "last.whl"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("links %q err %v, want %q", got, err, want)
	}
}
