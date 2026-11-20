package pip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const wheelFile = "demo-1.0-py3-none-any.whl"

// noWaits makes the retries immediate for one test.
func noWaits(t *testing.T) {
	t.Helper()
	delays := retryDelays
	retryDelays = []time.Duration{0, 0}
	t.Cleanup(func() { retryDelays = delays })
}

// fileServer answers each request with answer, given the request's number
// from 1, and counts the requests.
func fileServer(t *testing.T, answer func(n int, w http.ResponseWriter)) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		answer(int(hits.Add(1)), w)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func wheelBytes(n int) []byte { return bytes.Repeat([]byte("w"), n) }

func indexFileFor(url string, body []byte) IndexFile {
	sum := sha256.Sum256(body)
	return IndexFile{Filename: wheelFile, URL: url + "/files/" + wheelFile, Sha256: hex.EncodeToString(sum[:]), Size: int64(len(body))}
}

func serveBody(body []byte) func(int, http.ResponseWriter) {
	return func(_ int, w http.ResponseWriter) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	for _, p := range []string{path, path + ".part"} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is left behind: %v", filepath.Base(p), err)
		}
	}
}

func TestDownloadFileChecksSha256(t *testing.T) {
	noWaits(t)
	body := wheelBytes(100)
	other := bytes.Repeat([]byte("x"), 100)
	srv, hits := fileServer(t, serveBody(other))
	path := filepath.Join(t.TempDir(), wheelFile)

	_, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, body), path)
	if !errors.Is(err, ErrDigest) {
		t.Fatalf("DownloadFile = %v, want ErrDigest", err)
	}
	if !strings.Contains(err.Error(), wheelFile) || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error %q does not name the file and sha256", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("requests = %d, want 1: a digest mismatch gets no retry", n)
	}
	assertNoFile(t, path)
}

func TestDownloadFileWritesTheCheckedFile(t *testing.T) {
	body := wheelBytes(100)
	srv, _ := fileServer(t, serveBody(body))
	path := filepath.Join(t.TempDir(), wheelFile)

	sum, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, body), path)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	want := sha512.Sum512(body)
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("sha512 = %s, want the body's", sum)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, body) {
		t.Errorf("file = %q (%v), want the body", got, err)
	}
	if _, err := os.Stat(path + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf(".part is left behind: %v", err)
	}
}

// countingTransport counts the body bytes the client reads.
type countingTransport struct{ read atomic.Int64 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = countingBody{resp.Body, &c.read}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

func TestDownloadFileRefusesAnotherLength(t *testing.T) {
	noWaits(t)
	recorded := wheelBytes(100)
	tests := []struct {
		name     string
		served   []byte
		want     []string
		wantRead int64
	}{
		{"longer", wheelBytes(64 << 10), []string{"at least 101 bytes", "recorded 100"}, 101},
		{"shorter", wheelBytes(90), []string{"has 90 bytes", "recorded 100"}, 90},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits := fileServer(t, serveBody(tc.served))
			tr := &countingTransport{}
			path := filepath.Join(t.TempDir(), wheelFile)
			_, err := (&Client{HTTP: &http.Client{Transport: tr}}).DownloadFile(context.Background(), indexFileFor(srv.URL, recorded), path)
			if err == nil {
				t.Fatal("DownloadFile accepted a body of another length")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not say %q", err, w)
				}
			}
			if !strings.Contains(err.Error(), wheelFile) {
				t.Errorf("error %q does not name the file", err)
			}
			if n := tr.read.Load(); n != tc.wantRead {
				t.Errorf("read %d bytes, want %d", n, tc.wantRead)
			}
			if n := hits.Load(); n != 1 {
				t.Errorf("requests = %d, want 1: a size mismatch gets no retry", n)
			}
			assertNoFile(t, path)
		})
	}
}

func TestDownloadFileRetriesServerErrors(t *testing.T) {
	noWaits(t)
	body := wheelBytes(100)
	srv, hits := fileServer(t, func(n int, w http.ResponseWriter) {
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		serveBody(body)(n, w)
	})
	path := filepath.Join(t.TempDir(), wheelFile)
	if _, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, body), path); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestDownloadFileGivesUpAfterThreeAttempts(t *testing.T) {
	noWaits(t)
	srv, hits := fileServer(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) })
	path := filepath.Join(t.TempDir(), wheelFile)
	_, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, wheelBytes(100)), path)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("DownloadFile = %v, want a refusal naming status 503", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
	assertNoFile(t, path)
}

func TestDownloadFileDoesNotRetryNotFound(t *testing.T) {
	noWaits(t)
	srv, hits := fileServer(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) })
	path := filepath.Join(t.TempDir(), wheelFile)
	_, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, wheelBytes(100)), path)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("DownloadFile = %v, want ErrNotFound", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestDownloadFileRefusesBadInput(t *testing.T) {
	noWaits(t)
	body := wheelBytes(100)
	srv, hits := fileServer(t, serveBody(body))
	good := indexFileFor(srv.URL, body)
	host := strings.TrimPrefix(srv.URL, "http://")
	tests := []struct {
		name   string
		change func(*IndexFile)
		reason string
	}{
		{"ftp url", func(f *IndexFile) { f.URL = "ftp://" + host + "/files/" + wheelFile }, "is not https"},
		{"http on another host", func(f *IndexFile) { f.URL = "http://files.example.org/files/" + wheelFile }, "is not https"},
		{"user info", func(f *IndexFile) { f.URL = "http://user:pw@" + host + "/files/" + wheelFile }, "credentials"},
		{"no size", func(f *IndexFile) { f.Size = 0 }, "no recorded size"},
		{"size above the bound", func(f *IndexFile) { f.Size = MaxWheelBytes + 1 }, "4294967296-byte bound"},
		{"uppercase sha256", func(f *IndexFile) { f.Sha256 = strings.ToUpper(f.Sha256) }, "no valid sha256"},
		{"short sha256", func(f *IndexFile) { f.Sha256 = f.Sha256[:63] }, "no valid sha256"},
		{"source distribution", func(f *IndexFile) {
			f.Filename = "demo-1.0.tar.gz"
			f.URL = srv.URL + "/files/demo-1.0.tar.gz"
		}, "not a wheel"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := good
			tc.change(&f)
			path := filepath.Join(t.TempDir(), wheelFile)
			_, err := (&Client{}).DownloadFile(context.Background(), f, path)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("DownloadFile = %v, want a refusal saying %q", err, tc.reason)
			}
			if strings.Contains(err.Error(), "pw@") || strings.Contains(err.Error(), "files.example.org") {
				t.Errorf("error %q quotes the url", err)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("requests = %d, want 0", n)
			}
			assertNoFile(t, path)
		})
	}
}

// shortStall sets the stall timeout for one test.
func shortStall(t *testing.T, d time.Duration) {
	t.Helper()
	stall := stallTimeout
	stallTimeout = d
	t.Cleanup(func() { stallTimeout = stall })
}

// A body that takes longer than the stall timeout in total, while a byte
// arrives well within it each time, is a slow download, not a stalled one.
func TestDownloadFileOutlivesTheStallTimeoutWhileBytesArrive(t *testing.T) {
	noWaits(t)
	shortStall(t, 200*time.Millisecond)
	body := wheelBytes(30)
	srv, hits := fileServer(t, func(_ int, w http.ResponseWriter) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		for _, b := range body {
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			_, _ = w.Write([]byte{b})
		}
	})
	path := filepath.Join(t.TempDir(), wheelFile)
	start := time.Now()
	if _, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, body), path); err != nil {
		t.Fatalf("DownloadFile = %v, want the slow body accepted", err)
	}
	if took := time.Since(start); took < 2*stallTimeout {
		t.Fatalf("the body took %s, under twice the %s stall timeout, so this test proves nothing", took, stallTimeout)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestDownloadFileStallsOut(t *testing.T) {
	noWaits(t)
	shortStall(t, 20*time.Millisecond)
	release := make(chan struct{})
	srv, _ := fileServer(t, func(_ int, w http.ResponseWriter) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	})
	// Registered after the server's Close, so it runs first and frees the
	// handlers Close waits for.
	t.Cleanup(func() { close(release) })
	path := filepath.Join(t.TempDir(), wheelFile)
	_, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, wheelBytes(100)), path)
	if err == nil || !strings.Contains(err.Error(), "stalled") || !strings.Contains(err.Error(), wheelFile) {
		t.Fatalf("DownloadFile = %v, want a stall naming the file", err)
	}
	assertNoFile(t, path)
}

func TestDownloadFileErrorsNameTheFileNotTheURL(t *testing.T) {
	noWaits(t)
	tests := []struct {
		name   string
		answer func(int, http.ResponseWriter)
	}{
		{"server error", func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }},
		{"dropped connection", func(_ int, w http.ResponseWriter) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits := fileServer(t, tc.answer)
			f := indexFileFor(srv.URL, wheelBytes(100))
			f.URL += "?token=secret-value"
			_, err := (&Client{}).DownloadFile(context.Background(), f, filepath.Join(t.TempDir(), wheelFile))
			if err == nil {
				t.Fatal("DownloadFile succeeded")
			}
			if !strings.Contains(err.Error(), wheelFile) {
				t.Errorf("error %q does not name the file", err)
			}
			if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), srv.URL) {
				t.Errorf("error %q quotes the url", err)
			}
			if n := hits.Load(); n != 3 {
				t.Errorf("requests = %d, want 3", n)
			}
		})
	}
}

func TestDownloadFileIgnoresIndexVariables(t *testing.T) {
	decoy, decoyHits := fileServer(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) })
	for _, name := range []string{"PIP_INDEX_URL", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"} {
		t.Setenv(name, decoy.URL+"/simple/")
	}
	body := wheelBytes(100)
	srv, hits := fileServer(t, serveBody(body))
	if _, err := (&Client{}).DownloadFile(context.Background(), indexFileFor(srv.URL, body), filepath.Join(t.TempDir(), wheelFile)); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if n := decoyHits.Load(); n != 0 {
		t.Errorf("the decoy index got %d requests, want 0", n)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("the recorded url got %d requests, want 1", n)
	}
}
