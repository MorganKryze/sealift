package jobs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/store"
)

func TestCheckPinsNamesEveryBlockedPin(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "docopt", Version: "0.6.2"})
	ix.Add(piptest.Dist{Name: "pywin32", Version: "306", Tag: "cp311-cp311-win_amd64"})
	ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget,
		reqFile("requirements.txt", "docopt==0.6.2\nrequests==2.32.3\n"),
		reqFile("requirements-win.txt", "pywin32==306\n"))
	uv := &fakeUv{lock: "x==1\n", set: resolved("docopt", "0.6.2", "pywin32", "306", "requests", "2.32.3")}
	a.Uv = uv

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want check-pins to refuse docopt and pywin32")
	}
	status, _ := readStatus(t, st, a)
	if want := []string{"validate:done", "prepare-tools:done", "check-pins:failed"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	if n := len(uv.Calls()); n != 0 {
		t.Errorf("uv ran %d times, want 0", n)
	}
	msg := status.Steps[2].Error
	for _, want := range []string{
		"docopt==0.6.2 (requirements.txt): source distribution only",
		"pywin32==306 (requirements-win.txt): wheels for other platforms only",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("check-pins error = %q, want %q", msg, want)
		}
	}
	if strings.Contains(msg, "requests") {
		t.Errorf("check-pins error = %q, names requests, which has a wheel", msg)
	}

	res, _ := readPipResult(t, st, a)
	want := []PipBlocking{
		{Name: "docopt", Version: "0.6.2", Kind: "source-only", Detail: "source distribution only"},
		{Name: "pywin32", Version: "306", Kind: "other-platforms", Detail: "wheels for other platforms only"},
	}
	if !slices.Equal(res.Blocking, want) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, want)
	}
	if res.Packages == nil || len(res.Packages) != 0 {
		t.Errorf("packages = %#v, want an empty list: nothing was resolved", res.Packages)
	}
}

func TestCheckPinsRefusesHashMismatch(t *testing.T) {
	ix := piptest.NewIndex(t)
	generic := ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
	native := ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "cp311-cp311-manylinux_2_17_x86_64"})
	other := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		hashes   []string
		wantFile string // the recorded wheel; empty when check-pins refuses
	}{
		{"hashes listing no wheel", []string{other}, ""},
		{"hashes listing the preferred wheel", []string{native.Sha256}, native.Filename},
		{"hashes listing only a less preferred wheel", []string{generic.Sha256, other}, generic.Filename},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := "requests==2.32.3"
			for _, h := range c.hashes {
				line += " --hash=sha256:" + h
			}
			a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", line+"\n"))
			uv := &fakeUv{lock: "requests==2.32.3\n", set: resolved("requests", "2.32.3")}
			a.Uv = uv

			err := a.Run(context.Background(), func(Event) {})
			status, _ := readStatus(t, st, a)
			res, _ := readPipResult(t, st, a)
			if c.wantFile != "" {
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				if len(res.Packages) != 1 || res.Packages[0].Wheel == nil || res.Packages[0].Wheel.File != c.wantFile {
					t.Errorf("packages = %+v, want %s recorded", res.Packages, c.wantFile)
				}
				return
			}
			if err == nil || len(status.Steps) != 3 || status.Steps[2].Name != "check-pins" {
				t.Fatalf("Run = %v, steps %v, want check-pins failed", err, stepNames(status.Steps))
			}
			for _, want := range []string{"requests==2.32.3 (requirements.txt)", "requirements.txt", native.Filename} {
				if !strings.Contains(status.Steps[2].Error, want) {
					t.Errorf("check-pins error = %q, want %q", status.Steps[2].Error, want)
				}
			}
			if len(res.Blocking) != 1 || res.Blocking[0].Kind != "hash-mismatch" || res.Blocking[0].Name != "requests" {
				t.Errorf("blocking = %+v, want requests as a hash mismatch", res.Blocking)
			}
			if n := len(uv.Calls()); n != 0 {
				t.Errorf("uv ran %d times, want 0", n)
			}
		})
	}
}

// The outputs below come from uv, run against a fake index.
func TestBlockingFromUvOutput(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   PipBlocking
		ok     bool
	}{
		{
			name: "a source-only package",
			output: "error: No solution found when resolving dependencies\n" +
				"  cause: Because docopt==0.6.2 has no usable wheels and you require docopt==0.6.2, we can conclude that your requirements are unsatisfiable.\n\n" +
				"hint: Wheels are required for `docopt` because building from source is disabled for all packages (i.e., with `--no-build`)\n",
			want: PipBlocking{Name: "docopt", Version: "0.6.2", Kind: "source-only", Detail: "source distribution only"},
			ok:   true,
		},
		{
			name: "a transitive package with wheels for another platform",
			output: "error: No solution found when resolving dependencies\n" +
				"  cause: Because pywin32==306 has no wheels with a matching platform tag (e.g., `manylinux_2_28_x86_64`) and all versions of omega depend on pywin32==306, we can conclude that all versions of omega cannot be used.\n" +
				"         And because you require omega==1.0.0, we can conclude that your requirements are unsatisfiable.\n\n" +
				"hint: Wheels are available for `pywin32` (v306) on the following platform: `win_amd64`\n",
			want: PipBlocking{Name: "pywin32", Version: "306", Kind: "other-platforms", Detail: "wheels for other platforms only"},
			ok:   true,
		},
		{
			name: "a package with wheels for another interpreter",
			output: "error: No solution found when resolving dependencies\n" +
				"  cause: Because numpy==2.0.0 has no wheels with a matching Python implementation tag (e.g., `cp311`) and all versions of kappa depend on numpy==2.0.0, we can conclude that all versions of kappa cannot be used.\n" +
				"         And because you require kappa==1.0.0, we can conclude that your requirements are unsatisfiable.\n\n" +
				"hint: You require CPython 3.11 (`cp311`), but we only found wheels for `numpy` (v2.0.0) with the following Python implementation tag: `cp312`\n",
			want: PipBlocking{Name: "numpy", Version: "2.0.0", Kind: "other-platforms", Detail: "wheels for other platforms only"},
			ok:   true,
		},
		{
			name: "a conflict between pins",
			output: "error: No solution found when resolving dependencies\n" +
				"  cause: Because mypy==1.11.2 depends on mypy-extensions>=1.1.0 and you require mypy-extensions==1.0.0, we can conclude that your requirements are unsatisfiable.\n",
		},
		{name: "no output", output: ""},
		{
			name:   "a name that is no package name",
			output: "  cause: Because ../x==1.0 has no usable wheels and you require it.\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := blockingFromUv(c.output)
			if ok != c.ok || got != c.want {
				t.Errorf("blockingFromUv = %+v, %v; want %+v, %v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestPipAnalysisRecordsTheBlockingPackageUvNames(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "omega==1.0.0\n"))
	output := "error: No solution found when resolving dependencies\n" +
		"  cause: Because eps==1.0.0 has no usable wheels and all versions of omega depend on eps==1.0.0, we can conclude that all versions of omega cannot be used.\n"
	a.Uv = &fakeUv{output: output, err: errors.New("uv pip compile: No solution found when resolving dependencies: exit status 1")}

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want the resolve failure")
	}
	status, _ := readStatus(t, st, a)
	if want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:failed"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	res, _ := readPipResult(t, st, a)
	want := []PipBlocking{{Name: "eps", Version: "1.0.0", Kind: "source-only", Detail: "source distribution only"}}
	if !slices.Equal(res.Blocking, want) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, want)
	}
}

// uv resolves against every file the index lists, so a transitive package
// can reach the set with no wheel the target installs. The analysis must
// fail on it, never finish with a package that has no wheel.
func TestChooseWheelsNamesEveryBlockedPackage(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
	ix.Add(piptest.Dist{Name: "eps", Version: "1.0.0"})
	ix.Add(piptest.Dist{Name: "zeta", Version: "2.0.0", Tag: "cp311-cp311-win_amd64"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "omega==1.0.0\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("eps", "1.0.0", "omega", "1.0.0", "theta", "3.0.0", "zeta", "2.0.0")}

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want choose-wheels to refuse eps, theta and zeta")
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Failed {
		t.Errorf("state = %q, want failed", status.State)
	}
	want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:done", "choose-wheels:failed"}
	if !slices.Equal(stepNames(status.Steps), want) {
		t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	msg := status.Steps[4].Error
	for _, want := range []string{
		"3 packages have no wheel the target can install",
		"eps==1.0.0: source distribution only",
		"theta==3.0.0: no files on the index",
		"zeta==2.0.0: wheels for other platforms only",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("choose-wheels error = %q, want %q", msg, want)
		}
	}
	res, _ := readPipResult(t, st, a)
	wantBlocking := []PipBlocking{
		{Name: "eps", Version: "1.0.0", Kind: "source-only", Detail: "source distribution only"},
		{Name: "theta", Version: "3.0.0", Kind: "no-files", Detail: "no files on the index"},
		{Name: "zeta", Version: "2.0.0", Kind: "other-platforms", Detail: "wheels for other platforms only"},
	}
	if !slices.Equal(res.Blocking, wantBlocking) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, wantBlocking)
	}
	if res.Packages == nil || len(res.Packages) != 0 {
		t.Errorf("packages = %#v, want an empty list: nothing was scanned", res.Packages)
	}
}

func TestPipAnalysisRecordsOneWheelPerPackage(t *testing.T) {
	ix := piptest.NewIndex(t)
	// The generic wheel comes first on the page, so taking the first file
	// that fits would record it.
	ix.Add(piptest.Dist{Name: "numpy", Version: "2.1.0", Tag: "py3-none-any"})
	native := ix.Add(piptest.Dist{Name: "numpy", Version: "2.1.0", Tag: "cp311-cp311-manylinux_2_17_x86_64"})
	ix.Add(piptest.Dist{Name: "numpy", Version: "2.1.0", Tag: "cp312-cp312-manylinux_2_17_x86_64"})
	ix.Add(piptest.Dist{Name: "numpy", Version: "2.1.0"})
	certifi := ix.Add(piptest.Dist{Name: "certifi", Version: "2024.8.30", Tag: "py3-none-any"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "numpy==2.1.0\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("certifi", "2024.8.30", "numpy", "2.1.0")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	want := map[string]PipWheel{
		"certifi": {File: certifi.Filename, URL: certifi.URL, Sha256: certifi.Sha256, Size: certifi.Size},
		"numpy":   {File: native.Filename, URL: native.URL, Sha256: native.Sha256, Size: native.Size},
	}
	if len(res.Packages) != 2 {
		t.Fatalf("packages = %+v, want certifi and numpy", res.Packages)
	}
	for _, p := range res.Packages {
		if p.Wheel == nil || *p.Wheel != want[p.Name] {
			t.Errorf("%s wheel = %+v, want %+v", p.Name, p.Wheel, want[p.Name])
		}
	}
	if !strings.HasPrefix(native.URL, "http://127.0.0.1") || !strings.HasSuffix(native.URL, "/files/"+native.Filename) {
		t.Errorf("wheel URL = %q, want the index's absolute file URL", native.URL)
	}
	if len(res.Blocking) != 0 {
		t.Errorf("blocking = %+v, want none", res.Blocking)
	}
}

func TestYankedPinWarnsWithReason(t *testing.T) {
	cases := []struct {
		name   string
		yanked string
		want   string
	}{
		{"with a reason", "broken connection pool", "redis==5.0.8 is yanked on the index: broken connection pool"},
		{"with no reason", "-", "redis==5.0.8 is yanked on the index: no reason given"},
		{"with control characters in the reason", "bad\u202e\x1b[31m pool", "redis==5.0.8 is yanked on the index: bad[31m pool"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			ix.Add(piptest.Dist{Name: "redis", Version: "5.0.8", Tag: "py3-none-any", Yanked: c.yanked})
			a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "redis==5.0.8\n"))
			a.Uv = &fakeUv{lock: "redis==5.0.8\n", set: resolved("redis", "5.0.8")}

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, _ := readPipResult(t, st, a)
			if !slices.Equal(res.Warnings, []string{c.want}) {
				t.Errorf("warnings = %q, want %q", res.Warnings, c.want)
			}
		})
	}
}

func TestYoungPinWarns(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		uploaded time.Time
		want     []string
	}{
		{"a pin uploaded yesterday", now.Add(-24 * time.Hour), []string{
			"delta==2.0.0 was uploaded on " + now.Add(-24*time.Hour).Format(time.DateOnly) + ", within the 14-day minimum release age",
		}},
		{"a pin uploaded a month ago", now.Add(-30 * 24 * time.Hour), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			ix.Add(piptest.Dist{Name: "delta", Version: "2.0.0", Tag: "py3-none-any", Uploaded: c.uploaded})
			a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "delta==2.0.0\n"))
			a.Uv = &fakeUv{lock: "delta==2.0.0\n", set: resolved("delta", "2.0.0")}

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, _ := readPipResult(t, st, a)
			if !slices.Equal(res.Warnings, c.want) {
				t.Errorf("warnings = %q, want %q", res.Warnings, c.want)
			}
		})
	}
}

func TestChooseWheelsFetchesNoFile(t *testing.T) {
	ix := piptest.NewIndex(t)
	files := []string{
		ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"}).Filename,
		ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3"}).Filename,
		ix.Add(piptest.Dist{Name: "idna", Version: "3.10", Tag: "py3-none-any"}).Filename,
		ix.Add(piptest.Dist{Name: "idna", Version: "3.10"}).Filename,
	}
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("idna", "3.10", "requests", "2.32.3")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if status, _ := readStatus(t, st, a); status.State != store.Done {
		t.Fatalf("state = %q, want done", status.State)
	}
	for _, f := range files {
		if n := ix.Requests("/files/" + f); n != 0 {
			t.Errorf("%s was fetched %d times, want 0", f, n)
		}
	}
	for _, page := range []string{"/simple/requests/", "/simple/idna/"} {
		if n := ix.Requests(page); n != 1 {
			t.Errorf("%s was read %d times, want once", page, n)
		}
	}
}

func TestCheckPinsReportsWhatTheIndexAnswers(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		wantErr string
		blocked bool
	}{
		{"a project the index does not know", http.StatusNotFound, "requests==2.32.3 (requirements.txt): no files on the index", true},
		{"an index error", http.StatusInternalServerError, "read the index page of requests==2.32.3: pip: the index answered status 500", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(c.status) }))
			t.Cleanup(srv.Close)
			a, st := newPipAnalysis(t, srv.URL+"/simple/", store.DefaultPipTarget, reqFile("requirements.txt", "requests==2.32.3\n"))
			uv := &fakeUv{}
			a.Uv = uv

			if err := a.Run(context.Background(), func(Event) {}); err == nil {
				t.Fatal("Run succeeded, want check-pins to fail")
			}
			status, _ := readStatus(t, st, a)
			if len(status.Steps) != 3 || !strings.Contains(status.Steps[2].Error, c.wantErr) {
				t.Errorf("steps = %+v, want check-pins failing with %q", status.Steps, c.wantErr)
			}
			if n := len(uv.Calls()); n != 0 {
				t.Errorf("uv ran %d times, want 0", n)
			}
			_, err := os.Stat(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "pip-result.json"))
			if c.blocked != (err == nil) {
				t.Errorf("pip-result.json present = %v, want %v", err == nil, c.blocked)
			}
		})
	}
}
