package importer

import (
	"crypto/sha512"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/MorganKryze/sealift/internal/nexus"
	"github.com/MorganKryze/sealift/npm"
)

const (
	testPassword = "test-password"
	testRepo     = "npm-hosted"
)

type request struct{ Method, Path, Query, Auth string }

type upload struct {
	Field, File string
	Body        []byte
}

// fakeNexus answers the three endpoints the client uses; every answer can
// be set and every request is recorded.
type fakeNexus struct {
	srv *httptest.Server
	mu  sync.Mutex

	repoStatus int    // 0 means 200
	repoBody   string // empty means a valid hosted npm repository
	tarballs   map[string][]byte
	getStatus  map[string]int // by request path
	getBody    map[string]string
	drop       map[string]bool // GET paths whose connection is cut
	postStatus int             // 0 means 204
	postBody   string
	onGet      func(path string)
	onUpload   func(f *fakeNexus, u upload)

	requests []request
	uploads  []upload
}

func newFakeNexus(t *testing.T) *fakeNexus {
	t.Helper()
	f := &fakeNexus{tarballs: map[string][]byte{}, getStatus: map[string]int{}, getBody: map[string]string{}, drop: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func tarballPath(name, version string) string {
	return npm.TarballURL("/repository/"+testRepo, name, version)
}

func (f *fakeNexus) put(name, version string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tarballs[tarballPath(name, version)] = b
}

func (f *fakeNexus) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, request{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
	f.mu.Unlock()
	switch {
	case r.URL.Path == "/service/rest/v1/repositories":
		if f.repoStatus != 0 {
			w.WriteHeader(f.repoStatus)
			_, _ = io.WriteString(w, "repository answer")
			return
		}
		body := f.repoBody
		if body == "" {
			body = `[{"name":"other","format":"maven2","type":"hosted"},{"name":"` + testRepo + `","format":"npm","type":"hosted"}]`
		}
		_, _ = io.WriteString(w, body)
	case r.URL.Path == "/service/rest/v1/components" && r.Method == http.MethodPost:
		f.handlePost(w, r)
	case r.Method == http.MethodGet:
		if f.onGet != nil {
			f.onGet(r.URL.Path)
		}
		f.mu.Lock()
		cut, status, body := f.drop[r.URL.Path], f.getStatus[r.URL.Path], f.getBody[r.URL.Path]
		tarball, ok := f.tarballs[r.URL.Path]
		f.mu.Unlock()
		switch {
		case cut:
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		case status != 0:
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		case ok:
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeNexus) handlePost(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var u upload
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		u.Field, u.File = part.FormName(), part.FileName()
		u.Body, _ = io.ReadAll(part)
	}
	f.mu.Lock()
	f.uploads = append(f.uploads, u)
	status, body, hook := f.postStatus, f.postBody, f.onUpload
	f.mu.Unlock()
	if status != 0 && status >= 300 {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
		return
	}
	if hook != nil {
		hook(f, u)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeNexus) uploadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

// client returns a real client pointed at the fake.
func (f *fakeNexus) client(t *testing.T) *nexus.Client {
	t.Helper()
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := nexus.New(nexus.Config{URL: u, Repository: testRepo, User: "sealift-import", Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// stage writes content as a checked tarball and returns its package.
func stage(t *testing.T, dir, name, version string, content []byte) Package {
	t.Helper()
	file := npm.PackFileName(name, version)
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(content)
	return Package{Name: name, Version: version, File: file, Path: path, SHA512: sum[:]}
}

// storeUploads makes the fake serve what it receives, under the package's path.
func (f *fakeNexus) storeUploads(pkgs ...Package) {
	byFile := map[string]Package{}
	for _, p := range pkgs {
		byFile[p.File] = p
	}
	f.onUpload = func(f *fakeNexus, u upload) {
		if p, ok := byFile[u.File]; ok {
			f.put(p.Name, p.Version, u.Body)
		}
	}
}
