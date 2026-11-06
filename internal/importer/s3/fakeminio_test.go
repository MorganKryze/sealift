package s3

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAccess = "test-access-id"
	testSecret = "test-minio-secret"
)

// answer is what the fake sends for one kind of call.
type answer struct {
	Status int
	Header map[string]string
	Body   string
	// Echo copies the request's Authorization header into the body.
	Echo bool
}

type recorded struct {
	Method string
	Path   string // as sent on the wire
	Query  url.Values
	Header http.Header
}

// fakeMinio answers ListObjectsV2, HEAD, GET and DELETE and records every request.
type fakeMinio struct {
	*httptest.Server
	mu      sync.Mutex
	reqs    []recorded
	answers map[string]answer
}

func kindOf(r *http.Request) string {
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		return "list"
	case r.Method == http.MethodHead:
		return "head"
	case r.Method == http.MethodGet:
		return "get"
	}
	return "delete"
}

func newFake(t *testing.T, tlsOn bool) *fakeMinio {
	t.Helper()
	f := &fakeMinio{answers: map[string]answer{}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header.Clone()})
		a, ok := f.answers[kindOf(r)]
		f.mu.Unlock()
		if !ok {
			a = answer{Status: http.StatusOK}
		}
		for k, v := range a.Header {
			w.Header().Set(k, v)
		}
		body := a.Body
		if a.Echo {
			body = strings.ReplaceAll(body, "{auth}", r.Header.Get("Authorization"))
		}
		w.WriteHeader(a.Status)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	})
	if tlsOn {
		f.Server = httptest.NewTLSServer(h)
	} else {
		f.Server = httptest.NewServer(h)
	}
	t.Cleanup(f.Close)
	return f
}

func (f *fakeMinio) set(kind string, a answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[kind] = a
}

func (f *fakeMinio) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeMinio) config(t *testing.T) Config {
	t.Helper()
	u, err := url.Parse(f.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		URL: u, AccessKey: []byte(testAccess), SecretKey: []byte(testSecret),
		Now: func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) },
	}
}

func (f *fakeMinio) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(f.config(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// caFile writes the TLS fake's certificate where Config.CAFile can read it.
func (f *fakeMinio) caFile(t *testing.T) string {
	t.Helper()
	cert := f.Certificate()
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(cert.Raw); err != nil {
		t.Fatal(err)
	}
	return path
}
