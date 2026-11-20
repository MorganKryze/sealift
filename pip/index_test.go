package pip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func wheel(file string) IndexFile {
	return IndexFile{Filename: file, URL: "http://x/" + file, Sha256: sha}
}

func TestChooseWheel(t *testing.T) {
	tests := []struct {
		name  string
		files []IndexFile
		want  string
		block Blocking
	}{
		{"compiled over generic", []IndexFile{
			wheel("a-1-py3-none-any.whl"),
			wheel("a-1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"),
		}, "a-1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", ""},
		{"newer glibc refused", []IndexFile{
			wheel("a-1-cp311-cp311-manylinux_2_31_x86_64.whl"),
			wheel("a-1-py3-none-any.whl"),
		}, "a-1-py3-none-any.whl", ""},
		{"only a newer glibc", []IndexFile{
			wheel("a-1-cp311-cp311-manylinux_2_31_x86_64.whl"),
		}, "", OtherPlatforms},
		{"requires-python skips a file", []IndexFile{
			{Filename: "a-1-cp311-cp311-manylinux_2_28_x86_64.whl", URL: "http://x/a", Sha256: sha, RequiresPython: ">=3.12"},
			wheel("a-1-py3-none-any.whl"),
		}, "a-1-py3-none-any.whl", ""},
		{"requires-python that fits", []IndexFile{
			{Filename: "a-1-py3-none-any.whl", URL: "http://x/a", Sha256: sha, RequiresPython: ">=3.8,<4"},
		}, "a-1-py3-none-any.whl", ""},
		{"unparseable requires-python", []IndexFile{
			{Filename: "a-1-py3-none-any.whl", URL: "http://x/a", Sha256: sha, RequiresPython: "banana"},
		}, "", OtherPlatforms},
		{"tie goes to the higher build", []IndexFile{
			wheel("a-1-1-py3-none-any.whl"),
			wheel("a-1-2-py3-none-any.whl"),
			wheel("a-1-10-py3-none-any.whl"),
		}, "a-1-10-py3-none-any.whl", ""},
		{"tie goes to the name", []IndexFile{
			wheel("b-1-py3-none-any.whl"),
			wheel("a-1-py3-none-any.whl"),
		}, "a-1-py3-none-any.whl", ""},
		{"abi3 over generic", []IndexFile{
			wheel("a-1-py3-none-any.whl"),
			wheel("a-1-cp38-abi3-manylinux_2_17_x86_64.whl"),
		}, "a-1-cp38-abi3-manylinux_2_17_x86_64.whl", ""},
		{"sdists only", []IndexFile{
			wheel("a-1.tar.gz"), wheel("a-1.zip"),
		}, "", SourceOnly},
		{"other platforms only", []IndexFile{
			wheel("a-1-cp312-cp312-win_amd64.whl"),
			wheel("a-1-cp312-cp312-manylinux_2_17_x86_64.whl"),
			wheel("a-1.tar.gz"),
		}, "", OtherPlatforms},
		{"windows only", []IndexFile{wheel("a-1-py3-none-win_amd64.whl")}, "", OtherPlatforms},
		{"no files", nil, "", NoFiles},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, block := ChooseWheel(tc.files, host)
			if got.Filename != tc.want || block != tc.block {
				t.Fatalf("got %q, %q; want %q, %q", got.Filename, block, tc.want, tc.block)
			}
		})
	}
}

func TestChooseWheelRefusesRequiresPythonClauses(t *testing.T) {
	tests := []struct {
		spec string
		fits bool
	}{
		{"", true},
		{">=3.11", true},
		{">= 3.8, != 3.9.*", true},
		{">=3.11.3", false},
		{">3.11.2", false},
		{"<=3.11.2", true},
		{"<3.11", false},
		{"==3.11.*", true},
		{"==3.12.*", false},
		{"!=3.11.*", false},
		{"==3.11.2", true},
		{"==3.11", false},
		{"~=3.8", true},
		{"~=3.11.1", true},
		{"~=3.11.3", false},
		{"~=3", false},
		{">=3,<4", true},
		{">=3.x", false},
		{"3.11", false},
		{">=3.11,", false},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			f := IndexFile{Filename: "a-1-py3-none-any.whl", URL: "http://x/a", Sha256: sha, RequiresPython: tc.spec}
			got, _ := ChooseWheel([]IndexFile{f}, host)
			if (got.Filename != "") != tc.fits {
				t.Fatalf("requires-python %q: chosen = %v, want %v", tc.spec, got.Filename != "", tc.fits)
			}
		})
	}
}

const jsonType = "application/vnd.pypi.simple.v1+json"

func serve(t *testing.T, status int, ctype, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != jsonType {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &Client{Index: srv.URL + "/simple/", HTTP: srv.Client()}
}

func page(files string) string {
	return `{"meta":{"api-version":"1.0"},"name":"demo","files":[` + files + `]}`
}

func TestIndexFilesReadsYanked(t *testing.T) {
	body := page(fmt.Sprintf(`
	  {"filename":"demo-1.0-py3-none-any.whl","url":"../../files/a.whl","hashes":{"sha256":%q},"yanked":false},
	  {"filename":"demo-1.0.tar.gz","url":"../../files/b.tar.gz","hashes":{"sha256":%q},"yanked":true},
	  {"filename":"demo-1.0-cp311-cp311-win_amd64.whl","url":"../../files/c.whl","hashes":{"sha256":%q},"yanked":"broke on 3.11","size":42,"requires-python":">=3.8","upload-time":"2024-05-06T07:08:09.123456Z"},
	  {"filename":"demo-1.0-cp312-cp312-win_amd64.whl","url":"../../files/d.whl","hashes":{"sha256":%q}}`, sha, sha, sha, sha))
	c := serve(t, 200, jsonType, body)
	files, err := c.Files(context.Background(), "Demo", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("got %d files", len(files))
	}
	if files[0].Yanked || files[0].YankedReason != "" {
		t.Errorf("false read as %+v", files[0])
	}
	if !files[1].Yanked || files[1].YankedReason != "" {
		t.Errorf("true read as %+v", files[1])
	}
	f := files[2]
	if !f.Yanked || f.YankedReason != "broke on 3.11" || f.Size != 42 || f.RequiresPython != ">=3.8" || f.UploadTime.Year() != 2024 {
		t.Errorf("reason read as %+v", f)
	}
	if files[3].Yanked || !files[3].UploadTime.IsZero() {
		t.Errorf("plain file read as %+v", files[3])
	}
	if !strings.HasPrefix(files[0].URL, "http://127.0.0.1:") || !strings.HasSuffix(files[0].URL, "/files/a.whl") {
		t.Errorf("url not resolved against the page: %s", files[0].URL)
	}
}

func TestIndexFilesKeepsTheVersion(t *testing.T) {
	body := page(fmt.Sprintf(`
	  {"filename":"demo-1.0.0-py3-none-any.whl","url":"http://h/1","hashes":{"sha256":%q}},
	  {"filename":"demo-1.0.0.tar.gz","url":"http://h/2","hashes":{"sha256":%q}},
	  {"filename":"Demo_Pkg-1.0.0.zip","url":"http://h/3","hashes":{"sha256":%q}},
	  {"filename":"demo-1.1-py3-none-any.whl","url":"http://h/4","hashes":{"sha256":%q}},
	  {"filename":"demo-1.1.tar.gz","url":"http://h/5","hashes":{"sha256":%q}},
	  {"filename":"other-1.0-py3-none-any.whl","url":"http://h/6","hashes":{"sha256":%q}},
	  {"filename":"demo-1.0.egg","url":"http://h/7","hashes":{"sha256":%q}}`, sha, sha, sha, sha, sha, sha, sha))
	c := serve(t, 200, jsonType, body)
	files, err := c.Files(context.Background(), "demo", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Filename)
	}
	want := "demo-1.0.0-py3-none-any.whl demo-1.0.0.tar.gz"
	if strings.Join(names, " ") != want {
		t.Fatalf("files = %v, want %s", names, want)
	}
}

func TestIndexFilesRefuses(t *testing.T) {
	good := fmt.Sprintf(`{"filename":"demo-1.0.tar.gz","url":"http://h/1","hashes":{"sha256":%q}}`, sha)
	tests := []struct {
		name   string
		status int
		ctype  string
		body   string
		reason string
	}{
		{"html answer", 200, "text/html", "<html></html>", "not the JSON simple API"},
		{"api version 2", 200, jsonType, `{"meta":{"api-version":"2.0"},"files":[` + good + `]}`, "api-version"},
		{"no api version", 200, jsonType, `{"files":[` + good + `]}`, "api-version"},
		{"not json", 200, jsonType, `{"meta":`, "not valid JSON"},
		{"file url", 200, jsonType, page(fmt.Sprintf(`{"filename":"demo-1.0.tar.gz","url":"file:///etc/passwd","hashes":{"sha256":%q}}`, sha)), "http or https"},
		{"url with credentials", 200, jsonType, page(fmt.Sprintf(`{"filename":"demo-1.0.tar.gz","url":"http://u:p@h/1","hashes":{"sha256":%q}}`, sha)), "credentials"},
		{"missing sha256", 200, jsonType, page(`{"filename":"demo-1.0.tar.gz","url":"http://h/1","hashes":{"md5":"abc"}}`), "sha256"},
		{"short sha256", 200, jsonType, page(`{"filename":"demo-1.0.tar.gz","url":"http://h/1","hashes":{"sha256":"abc"}}`), "sha256"},
		{"missing url", 200, jsonType, page(fmt.Sprintf(`{"filename":"demo-1.0.tar.gz","hashes":{"sha256":%q}}`, sha)), "no url"},
		{"server error", 500, jsonType, "{}", "status 500"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, tc.status, tc.ctype, tc.body)
			_, err := c.Files(context.Background(), "demo", "1.0")
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want %q", err, tc.reason)
			}
			if errors.Is(err, ErrNotFound) {
				t.Fatal("a refusal must not read as not found")
			}
		})
	}
}

func TestIndexFilesNotFound(t *testing.T) {
	c := serve(t, 404, "text/html", "nope")
	_, err := c.Files(context.Background(), "demo", "1.0")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestIndexFilesRefusesBadArguments(t *testing.T) {
	c := serve(t, 200, jsonType, page(""))
	for _, tc := range []struct{ name, version, reason string }{
		{"../x", "1.0", "project name"},
		{"demo", "latest", "version"},
	} {
		if _, err := c.Files(context.Background(), tc.name, tc.version); err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("Files(%q, %q) err = %v, want %q", tc.name, tc.version, err, tc.reason)
		}
	}
}

func TestIndexFilesBoundsThePage(t *testing.T) {
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", jsonType)
		chunk := []byte(strings.Repeat(" ", 1<<20))
		for i := 0; i < 64; i++ {
			n, err := w.Write(chunk)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	c := &Client{Index: srv.URL + "/simple/", HTTP: srv.Client()}
	_, err := c.Files(context.Background(), "demo", "1.0")
	if err == nil || !strings.Contains(err.Error(), "32 MiB") {
		t.Fatalf("err = %v, want the 32 MiB bound named", err)
	}
	// The server writes ahead of the client through socket buffers, so allow
	// slack; an unbounded read would drain all 64 MiB.
	if got := sent.Load(); got > 48<<20 {
		t.Fatalf("server sent %d bytes, the client kept reading past the bound", got)
	}
}
