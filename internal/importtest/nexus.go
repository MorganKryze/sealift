package importtest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/MorganKryze/sealift/pip"
)

// PyPINexus is a fake Nexus holding one pypi hosted repository, answering as
// the lab's Nexus 3.96.5 did: a 404 for a project it does not hold, a simple
// page whose anchors link ../../packages/<project>/<version>/<file>#sha256=,
// a 204 for an upload in the pypi.asset field, and a 409 for a file it holds.
type PyPINexus struct {
	URL *url.URL

	t    testing.TB
	repo string

	mu       sync.Mutex
	format   string
	kind     string
	files    map[string][]byte   // by path
	listed   map[string][]string // file names by project, in upload order
	status   map[string]int      // by request path
	links    map[string]string   // href by file name
	omitted  map[string]bool     // file names the page leaves out
	tamper   bool
	user     string // when set, a request without this user and pass answers 401
	pass     string
	uploads  int
	requests []string
}

// NewPyPINexus starts the fake on loopback and stops it when t ends.
func NewPyPINexus(t testing.TB, repo string) *PyPINexus {
	t.Helper()
	n := &PyPINexus{
		t: t, repo: repo, format: "pypi", kind: "hosted",
		files: map[string][]byte{}, listed: map[string][]string{}, status: map[string]int{},
		links: map[string]string{}, omitted: map[string]bool{},
	}
	srv := httptest.NewServer(http.HandlerFunc(n.handle))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	n.URL = u
	return n
}

// PagePath is the path of project's simple page.
func (n *PyPINexus) PagePath(project string) string {
	return "/repository/" + n.repo + "/simple/" + project + "/"
}

// FilePath is the path the page links file to: the version comes from the
// file name, as Nexus files a wheel.
func (n *PyPINexus) FilePath(project, file string) string {
	w, err := pip.ParseWheelName(file)
	if err != nil {
		n.t.Fatalf("FilePath(%q): %v", file, err)
	}
	return "/repository/" + n.repo + "/packages/" + project + "/" + w.Version + "/" + file
}

// Put makes the fake hold file under project, as if uploaded earlier.
func (n *PyPINexus) Put(project, file string, body []byte) {
	path := n.FilePath(project, file)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.store(project, file, path, body)
}

func (n *PyPINexus) store(project, file, path string, body []byte) {
	if _, ok := n.files[path]; !ok {
		n.listed[project] = append(n.listed[project], file)
	}
	n.files[path] = body
}

// Remove makes the fake forget file under project, as an administrator's delete would.
func (n *PyPINexus) Remove(project, file string) {
	path := n.FilePath(project, file)
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.files, path)
	n.listed[project] = slices.DeleteFunc(n.listed[project], func(f string) bool { return f == file })
}

// RequireAuth makes every later request without user and pass in its basic
// authorization answer 401, as Nexus does for another user.
func (n *PyPINexus) RequireAuth(user, pass string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.user, n.pass = user, pass
}

// SetRepository makes the repository list name the repository with another
// format and type.
func (n *PyPINexus) SetRepository(format, kind string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.format, n.kind = format, kind
}

// SetStatus makes every request to path answer status.
func (n *PyPINexus) SetStatus(path string, status int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.status[path] = status
}

// Link makes the page link file to href in place of its own path.
func (n *PyPINexus) Link(file, href string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.links[file] = href
}

// Omit makes the page leave file out, even after an upload.
func (n *PyPINexus) Omit(file string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.omitted[file] = true
}

// Tamper makes the fake serve other bytes than it receives in later uploads.
func (n *PyPINexus) Tamper() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tamper = true
}

// Uploads is the number of uploads the fake accepted.
func (n *PyPINexus) Uploads() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.uploads
}

// Requests lists every request as "<method> <path>", in order.
func (n *PyPINexus) Requests() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.requests)
}

func (n *PyPINexus) handle(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	n.requests = append(n.requests, r.Method+" "+r.URL.Path)
	status := n.status[r.URL.Path]
	wantUser, wantPass := n.user, n.pass
	n.mu.Unlock()
	if user, pass, _ := r.BasicAuth(); wantUser != "" && (user != wantUser || pass != wantPass) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "status %d from the fake", status)
		return
	}
	prefix := "/repository/" + n.repo + "/"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/service/rest/v1/repositories":
		n.mu.Lock()
		body := fmt.Sprintf(`[{"name":"npm-hosted","format":"npm","type":"hosted"},{"name":%q,"format":%q,"type":%q}]`, n.repo, n.format, n.kind)
		n.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	case r.Method == http.MethodPost && r.URL.Path == "/service/rest/v1/components" && r.URL.Query().Get("repository") == n.repo:
		n.upload(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, prefix+"simple/"):
		n.page(w, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix+"simple/"), "/"), r.URL.Path)
	case r.Method == http.MethodGet:
		n.mu.Lock()
		body, ok := n.files[r.URL.Path]
		n.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(body)
	default:
		http.NotFound(w, r)
	}
}

// page writes the simple page in the form Nexus 3.96.5 served in the lab:
// one anchor per file, spread over several lines, with the sha256 fragment.
func (n *PyPINexus) page(w http.ResponseWriter, project, path string) {
	if !strings.HasSuffix(path, "/") || strings.Contains(project, "/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	files := n.listed[project]
	if len(files) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<!DOCTYPE html>\n<html lang=\"en\">\n<head><title>Links for %s</title>\n  <meta name=\"api-version\" value=\"2\"/>\n</head>\n<body><h1>Links for %s</h1>\n", project, project)
	for _, file := range files {
		if n.omitted[file] {
			continue
		}
		version := "0"
		if wn, err := pip.ParseWheelName(file); err == nil {
			version = wn.Version
		}
		sum := sha256.Sum256(n.files["/repository/"+n.repo+"/packages/"+project+"/"+version+"/"+file])
		href, ok := n.links[file]
		if !ok {
			href = "../../packages/" + project + "/" + version + "/" + file + "#sha256=" + hex.EncodeToString(sum[:])
		}
		fmt.Fprintf(&b, "    <a href=\"%s\"\n       rel=\"internal\"\n       data-core-metadata=\"sha256=%s\"\n       data-requires-python=\"&gt;=3.7\"\n       data-dist-info-metadata=\"sha256=%s\">\n      %s\n    </a><br/>\n",
			href, hex.EncodeToString(sum[:]), hex.EncodeToString(sum[:]), file)
	}
	b.WriteString("</body>\n</html>\n")
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

func (n *PyPINexus) upload(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "not a multipart form", http.StatusBadRequest)
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "pypi.asset" {
		http.Error(w, `[{"id":"*","message":"the form holds no pypi.asset field"}]`, http.StatusBadRequest)
		return
	}
	file := part.FileName()
	body, err := io.ReadAll(part)
	if err != nil {
		http.Error(w, "cannot read the upload", http.StatusBadRequest)
		return
	}
	wn, err := pip.ParseWheelName(file)
	if err != nil {
		http.Error(w, `[{"id":"*","message":"not a wheel"}]`, http.StatusBadRequest)
		return
	}
	project := pip.Normalize(wn.Name)
	path := "/repository/" + n.repo + "/packages/" + project + "/" + wn.Version + "/" + file
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.files[path]; ok {
		// The lab recorded this answer cut at 120 characters; the fake keeps that much.
		http.Error(w, fmt.Sprintf("ValidationErrorXO{id='*', message='%s/packages/%s/%s/%s -  cannot be updated", n.repo, project, wn.Version, file), http.StatusConflict)
		return
	}
	if n.tamper {
		body = append(slices.Clone(body), '!')
	}
	n.store(project, file, path, body)
	n.uploads++
	w.WriteHeader(http.StatusNoContent)
}
