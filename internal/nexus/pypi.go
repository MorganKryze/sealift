package nexus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	// maxSimplePage is the largest simple page the client reads.
	maxSimplePage = 8 << 20
	// maxSimpleLinks is the most anchors a simple page may hold.
	maxSimpleLinks = 100000
)

// FetchFile copies the file a pypi repository's simple index lists for
// project to w. It reports found false when the page or the file is absent,
// and fails when the copy is longer than limit bytes or the link leaves the
// repository.
func (c *Client) FetchFile(ctx context.Context, project, file string, w io.Writer, limit int64) (bool, error) {
	if !pathSegment(project) || !pathSegment(file) {
		return false, errors.New("project or file name is not usable in a URL path")
	}
	page := c.base
	page.Path, page.RawPath, page.RawQuery = c.repositoryPath()+"simple/"+project+"/", "", ""
	links, found, err := c.readPage(ctx, page.String())
	if err != nil || !found {
		return false, err
	}
	href, ok := fileLink(links, file)
	if !ok {
		return false, nil
	}
	// The link is checked before the request: the request carries the
	// credentials, which go to the configured origin only.
	target, err := c.repositoryLink(&page, href)
	if err != nil {
		return false, err
	}
	resp, err := c.do(ctx, http.MethodGet, target.String(), nil, "")
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

// readPage reads a simple page and returns its links. It reports found false
// on a 404.
func (c *Client) readPage(ctx context.Context, page string) ([]string, bool, error) {
	resp, err := c.do(ctx, http.MethodGet, page, nil, "")
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, nil
	case resp.StatusCode != http.StatusOK:
		return nil, false, c.statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSimplePage+1))
	if err != nil {
		return nil, false, fmt.Errorf("nexus unreachable: %s", c.clean(err.Error()))
	}
	if len(body) > maxSimplePage {
		return nil, false, fmt.Errorf("nexus simple page is larger than %d bytes", maxSimplePage)
	}
	links, err := simpleLinks(body)
	if err != nil {
		return nil, false, err
	}
	return links, true, nil
}

// repositoryPath is the path below which the repository's files sit, with
// a trailing slash.
func (c *Client) repositoryPath() string {
	return strings.TrimSuffix(c.base.Path, "/") + "/repository/" + c.repo + "/"
}

// repositoryLink resolves href against the page and refuses it unless it
// stays on the configured scheme, host and port, below the repository's
// path, with no escape, query or user information.
func (c *Client) repositoryLink(page *url.URL, href string) (*url.URL, error) {
	ref, err := url.Parse(href)
	if err != nil {
		return nil, c.linkError(href, "it is not a URL")
	}
	u := page.ResolveReference(ref)
	prefix := c.repositoryPath()
	switch {
	case u.User != nil:
		return nil, c.linkError(href, "it carries user information")
	case u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.Opaque != "":
		return nil, c.linkError(href, fmt.Sprintf("it points to %s, not %s", c.clean(u.Scheme+"://"+u.Host), c.base.Scheme+"://"+c.base.Host))
	case u.RawQuery != "" || u.ForceQuery:
		return nil, c.linkError(href, "it carries a query")
	case strings.Contains(u.EscapedPath(), "%"):
		return nil, c.linkError(href, "its path holds a percent escape")
	case !strings.HasPrefix(u.Path, prefix) || slices.ContainsFunc(strings.Split(u.Path, "/"), isDotSegment):
		return nil, c.linkError(href, "its path is outside "+prefix)
	}
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}

func (c *Client) linkError(href, reason string) error {
	return fmt.Errorf("nexus lists the file at a link that leaves the repository: %s (\"%s\")", reason, c.clean(href))
}

func isDotSegment(s string) bool { return s == "." || s == ".." }

// pathSegment reports whether s can stand as one segment of a URL path.
func pathSegment(s string) bool {
	return plainSegment(s) && !strings.Contains(s, "/")
}

// fileLink returns the first link whose last path segment, fragment and
// query dropped, is file.
func fileLink(links []string, file string) (string, bool) {
	for _, href := range links {
		p, _, _ := strings.Cut(href, "#")
		p, _, _ = strings.Cut(p, "?")
		if p[strings.LastIndexByte(p, '/')+1:] == file {
			return href, true
		}
	}
	return "", false
}

// simpleLinks returns the href of every anchor in page, in order, with &amp;
// decoded. It scans the raw HTML, which on a simple page holds anchors and
// little else, and fails past maxSimpleLinks anchors.
func simpleLinks(page []byte) ([]string, error) {
	var links []string
	for i := 0; i < len(page); {
		j := bytes.IndexByte(page[i:], '<')
		if j < 0 {
			break
		}
		i += j + 1
		if i+1 >= len(page) || page[i]|0x20 != 'a' || !isSpace(page[i+1]) {
			continue
		}
		href, end, found := anchorHref(page, i+1)
		i = end
		if !found {
			continue
		}
		if len(links) == maxSimpleLinks {
			return nil, fmt.Errorf("nexus simple page lists more than %d links", maxSimpleLinks)
		}
		links = append(links, strings.ReplaceAll(href, "&amp;", "&"))
	}
	return links, nil
}

// anchorHref reads the attributes of a tag from page[i:] up to its closing
// '>' and returns the first href, and the offset after the tag.
func anchorHref(page []byte, i int) (href string, end int, found bool) {
	for i < len(page) {
		for i < len(page) && (isSpace(page[i]) || page[i] == '/') {
			i++
		}
		if i >= len(page) {
			break
		}
		if page[i] == '>' {
			return href, i + 1, found
		}
		start := i
		for i < len(page) && !isSpace(page[i]) && page[i] != '=' && page[i] != '>' && page[i] != '/' {
			i++
		}
		name := page[start:i]
		for i < len(page) && isSpace(page[i]) {
			i++
		}
		var value []byte
		if i < len(page) && page[i] == '=' {
			value, i = attributeValue(page, i+1)
		}
		if !found && bytes.EqualFold(name, []byte("href")) {
			href, found = string(value), true
		}
	}
	return href, len(page), found
}

// attributeValue reads a quoted or bare attribute value from page[i:] and
// returns it with the offset after it.
func attributeValue(page []byte, i int) ([]byte, int) {
	for i < len(page) && isSpace(page[i]) {
		i++
	}
	if i < len(page) && (page[i] == '"' || page[i] == '\'') {
		quote := page[i]
		i++
		k := bytes.IndexByte(page[i:], quote)
		if k < 0 {
			return page[i:], len(page)
		}
		return page[i : i+k], i + k + 1
	}
	start := i
	for i < len(page) && !isSpace(page[i]) && page[i] != '>' {
		i++
	}
	return page[start:i], i
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}
