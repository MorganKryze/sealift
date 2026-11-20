package piptest

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/pip"
)

func TestFakeIndexServesWheelMetadata(t *testing.T) {
	ix := NewIndex(t)
	up := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	f := ix.Add(Dist{
		Name: "Demo_Pkg", Version: "1.2", Tag: "py3-none-any",
		Requires: []string{"idna>=3", "certifi"}, RequiresPython: ">=3.8",
		Uploaded: up, Payload: map[string][]byte{"demo_pkg-1.2.data/scripts/demo": []byte("#!/bin/sh\n")},
	})
	ix.Add(Dist{Name: "demo-pkg", Version: "1.2", Yanked: "-"})
	ix.Add(Dist{Name: "demo-pkg", Version: "1.3", Tag: "py3-none-any", Yanked: "broken"})

	if f.Filename != "demo_pkg-1.2-py3-none-any.whl" {
		t.Fatalf("filename = %s", f.Filename)
	}
	c := &pip.Client{Index: ix.URL}
	files, err := c.Files(context.Background(), "demo-pkg", "1.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want the wheel and the sdist", len(files))
	}
	var got pip.IndexFile
	for _, g := range files {
		if g.Filename == f.Filename {
			got = g
		}
	}
	if got != f {
		t.Fatalf("page says %+v, Add returned %+v", got, f)
	}
	for _, g := range files {
		if strings.HasSuffix(g.Filename, ".tar.gz") && (!g.Yanked || g.YankedReason != "") {
			t.Errorf("yanked without a reason read as %+v", g)
		}
	}
	other, err := c.Files(context.Background(), "demo-pkg", "1.3")
	if err != nil || len(other) != 1 || !other[0].Yanked || other[0].YankedReason != "broken" {
		t.Fatalf("1.3 = %+v, %v", other, err)
	}

	resp, err := http.Get(got.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if int64(len(data)) != got.Size {
		t.Errorf("served %d bytes, page says %d", len(data), got.Size)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]string{}
	for _, e := range zr.File {
		rc, _ := e.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		read[e.Name] = string(b)
	}
	meta := read["demo_pkg-1.2.dist-info/METADATA"]
	for _, want := range []string{"Name: Demo_Pkg", "Version: 1.2", "Requires-Dist: idna>=3", "Requires-Dist: certifi", "Requires-Python: >=3.8"} {
		if !strings.Contains(meta, want) {
			t.Errorf("METADATA lacks %q:\n%s", want, meta)
		}
	}
	if !strings.Contains(read["demo_pkg-1.2.dist-info/WHEEL"], "Tag: py3-none-any") {
		t.Errorf("WHEEL = %q", read["demo_pkg-1.2.dist-info/WHEEL"])
	}
	record := read["demo_pkg-1.2.dist-info/RECORD"]
	if !strings.Contains(record, "demo_pkg-1.2.data/scripts/demo,sha256=") || !strings.Contains(record, "demo_pkg-1.2.dist-info/RECORD,,") {
		t.Errorf("RECORD = %q", record)
	}
	if read["demo_pkg-1.2.data/scripts/demo"] != "#!/bin/sh\n" {
		t.Error("payload entry missing")
	}
	if ix.Requests("/simple/demo-pkg/") != 2 {
		t.Errorf("page requests = %d", ix.Requests("/simple/demo-pkg/"))
	}
	if ix.Requests("/files/"+f.Filename) != 1 {
		t.Errorf("file requests = %d", ix.Requests("/files/"+f.Filename))
	}
}

func TestFakeIndexAnswersNotFound(t *testing.T) {
	ix := NewIndex(t)
	_, err := (&pip.Client{Index: ix.URL}).Files(context.Background(), "nothing", "1.0")
	if !errors.Is(err, pip.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
