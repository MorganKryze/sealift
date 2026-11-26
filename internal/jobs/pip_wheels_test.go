package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/store"
)

func TestCheckPinsRecordsEveryBlockedPinAndGoesOn(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "docopt", Version: "0.6.2"})
	ix.Add(piptest.Dist{Name: "pywin32", Version: "306", Tag: "cp311-cp311-win_amd64"})
	requests := ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget,
		reqFile("requirements.txt", "docopt==0.6.2\nrequests==2.32.3\n"),
		reqFile("requirements-win.txt", "# windows only\npywin32==306\n"))
	uv := &fakeUv{lock: "requests==2.32.3\n", set: resolved("requests", "2.32.3")}
	a.Uv = uv
	trivy := &cannedTrivy{report: pipTrivyReport()}
	a.Trivy = trivy

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Done {
		t.Errorf("state = %q, want done", status.State)
	}
	want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:done", "choose-wheels:done", "scan:done"}
	if !slices.Equal(stepNames(status.Steps), want) {
		t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	calls := uv.Calls()
	if len(calls) != 1 {
		t.Fatalf("uv ran %d times, want once", len(calls))
	}
	if in := string(calls[0].Requirements); !strings.Contains(in, "requests==2.32.3") || strings.Contains(in, "docopt") || strings.Contains(in, "pywin32") {
		t.Errorf("uv read %q, want requests alone: the blocked lines stay out", in)
	}
	log := pipLog(t, a)
	for _, want := range []string{
		"docopt==0.6.2 (requirements.txt): source distribution only",
		"pywin32==306 (requirements-win.txt): wheels for other platforms only",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log = %q, want %q", log, want)
		}
	}

	res, _ := readPipResult(t, st, a)
	wantBlocking := []PipBlocking{
		{Name: "docopt", Version: "0.6.2", Kind: "source-only", Detail: "source distribution only",
			PinnedAt: []PipPlace{{File: "requirements.txt", Line: 1}}},
		{Name: "pywin32", Version: "306", Kind: "other-platforms", Detail: "wheels for other platforms only",
			PinnedAt: []PipPlace{{File: "requirements-win.txt", Line: 2}}},
	}
	if !reflect.DeepEqual(res.Blocking, wantBlocking) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, wantBlocking)
	}
	if got := packageNames(res.Packages); !slices.Equal(got, []string{"docopt", "pywin32", "requests"}) {
		t.Fatalf("packages = %v, want docopt, pywin32 and requests", got)
	}
	for _, p := range res.Packages {
		switch {
		case p.Name == "requests" && (p.Wheel == nil || p.Wheel.File != requests.Filename):
			t.Errorf("requests wheel = %+v, want %s", p.Wheel, requests.Filename)
		case p.Name != "requests" && p.Wheel != nil:
			t.Errorf("%s wheel = %+v, want none: the target cannot install it", p.Name, p.Wheel)
		}
	}
	if got, want := scannedPurls(t, trivy), []string{"pkg:pypi/docopt@0.6.2", "pkg:pypi/pywin32@306", "pkg:pypi/requests@2.32.3"}; !slices.Equal(got, want) {
		t.Errorf("scanned purls = %v, want %v", got, want)
	}
}

func TestCheckPinsRecordsAHashMismatchAndGoesOn(t *testing.T) {
	ix := piptest.NewIndex(t)
	generic := ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
	native := ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "cp311-cp311-manylinux_2_17_x86_64"})
	other := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		hashes   []string
		wantFile string // the recorded wheel; empty when check-pins blocks the pin
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
			uv := &fakeUv{lock: "x==1\n"}
			if c.wantFile != "" {
				uv.set = resolved("requests", "2.32.3")
			}
			a.Uv = uv

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			status, _ := readStatus(t, st, a)
			if status.State != store.Done {
				t.Errorf("state = %q, want done", status.State)
			}
			res, _ := readPipResult(t, st, a)
			if len(res.Packages) != 1 || res.Packages[0].Name != "requests" {
				t.Fatalf("packages = %+v, want requests", res.Packages)
			}
			if c.wantFile != "" {
				if w := res.Packages[0].Wheel; w == nil || w.File != c.wantFile {
					t.Errorf("wheel = %+v, want %s recorded", w, c.wantFile)
				}
				if len(res.Blocking) != 0 {
					t.Errorf("blocking = %+v, want none", res.Blocking)
				}
				return
			}
			if w := res.Packages[0].Wheel; w != nil {
				t.Errorf("wheel = %+v, want none: no wheel matches the hashes", w)
			}
			log := pipLog(t, a)
			for _, want := range []string{"requests==2.32.3 (requirements.txt)", "the --hash options in requirements.txt", native.Filename} {
				if !strings.Contains(log, want) {
					t.Errorf("log = %q, want %q", log, want)
				}
			}
			if len(res.Blocking) != 1 || res.Blocking[0].Kind != "hash-mismatch" || res.Blocking[0].Name != "requests" {
				t.Errorf("blocking = %+v, want requests as a hash mismatch", res.Blocking)
			}
			if calls := uv.Calls(); len(calls) != 1 || strings.Contains(string(calls[0].Requirements), "requests") {
				t.Errorf("uv calls = %+v, want one, with the blocked line left out", calls)
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
			if ok != c.ok || !reflect.DeepEqual(got, c.want) {
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
	if !reflect.DeepEqual(res.Blocking, want) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, want)
	}
}

// uv gives no set when it stops on a package with no wheel, so nothing can
// be scanned: the analysis fails, and its result lists every package known
// to block, the pins check-pins found included, and no package.
func TestResolverBlockingStillFailsTheAnalysis(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
	ix.Add(piptest.Dist{Name: "docopt", Version: "0.6.2"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "docopt==0.6.2\nomega==1.0.0\n"))
	output := "error: No solution found when resolving dependencies\n" +
		"  cause: Because eps==1.0.0 has no usable wheels and all versions of omega depend on eps==1.0.0, we can conclude that all versions of omega cannot be used.\n"
	a.Uv = &fakeUv{output: output, err: errors.New("uv pip compile: No solution found when resolving dependencies: exit status 1")}

	if err := a.Run(context.Background(), func(Event) {}); err == nil {
		t.Fatal("Run succeeded, want the resolve failure")
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Failed {
		t.Errorf("state = %q, want failed", status.State)
	}
	if want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:failed"}; !slices.Equal(stepNames(status.Steps), want) {
		t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	if log := pipLog(t, a); !strings.Contains(log, "eps==1.0.0: source distribution only") {
		t.Errorf("log = %q, want it to name eps", log)
	}
	res, _ := readPipResult(t, st, a)
	want := []PipBlocking{
		{Name: "docopt", Version: "0.6.2", Kind: "source-only", Detail: "source distribution only",
			PinnedAt: []PipPlace{{File: "requirements.txt", Line: 1}}},
		{Name: "eps", Version: "1.0.0", Kind: "source-only", Detail: "source distribution only"},
	}
	if !reflect.DeepEqual(res.Blocking, want) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, want)
	}
	if res.Packages == nil || len(res.Packages) != 0 {
		t.Errorf("packages = %#v, want an empty list: nothing was scanned", res.Packages)
	}
}

// uv never sees a constraint's --hash options, so choose-wheels is the only
// step that holds a constraint reaching the set to them.
func TestChooseWheelsHoldsAConstraintToItsHashes(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
	generic := ix.Add(piptest.Dist{Name: "eps", Version: "1.0.0", Tag: "py3-none-any"})
	native := ix.Add(piptest.Dist{Name: "eps", Version: "1.0.0", Tag: "cp311-cp311-manylinux_2_17_x86_64"})
	other := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		hashes   []string
		wantFile string // the recorded wheel; empty when choose-wheels blocks eps
	}{
		{"hashes listing no wheel", []string{other}, ""},
		{"hashes listing only a less preferred wheel", []string{generic.Sha256, other}, generic.Filename},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := "eps==1.0.0"
			for _, h := range c.hashes {
				line += " --hash=sha256:" + h
			}
			a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget,
				reqFile("requirements.txt", "omega==1.0.0\n-c constraints.txt\n"),
				reqFile("constraints.txt", line+"\n"))
			a.Uv = &fakeUv{lock: "x==1\n", set: resolved("eps", "1.0.0", "omega", "1.0.0")}

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, _ := readPipResult(t, st, a)
			i := slices.IndexFunc(res.Packages, func(p PipPackage) bool { return p.Name == "eps" })
			if i < 0 {
				t.Fatalf("packages = %+v, want eps", res.Packages)
			}
			if c.wantFile != "" {
				if res.Packages[i].Wheel == nil || res.Packages[i].Wheel.File != c.wantFile {
					t.Errorf("packages = %+v, want eps recorded as %s", res.Packages, c.wantFile)
				}
				return
			}
			if w := res.Packages[i].Wheel; w != nil {
				t.Errorf("eps wheel = %+v, want none: no wheel matches the hashes", w)
			}
			log := pipLog(t, a)
			for _, want := range []string{"eps==1.0.0 (constraints.txt)", "the --hash options in constraints.txt", native.Filename} {
				if !strings.Contains(log, want) {
					t.Errorf("log = %q, want %q", log, want)
				}
			}
			if len(res.Blocking) != 1 || res.Blocking[0].Kind != "hash-mismatch" || res.Blocking[0].Name != "eps" ||
				!reflect.DeepEqual(res.Blocking[0].PinnedAt, []PipPlace{{File: "constraints.txt", Line: 1}}) {
				t.Errorf("blocking = %+v, want eps as a hash mismatch pinned at constraints.txt line 1", res.Blocking)
			}
		})
	}
}

// uv resolves against every file the index lists, so a transitive package
// can reach the set with no wheel the target installs. It stays in the set
// without a wheel and in blocking, and the analysis goes on.
func TestChooseWheelsKeepsABlockedPackageWithoutAWheel(t *testing.T) {
	ix := piptest.NewIndex(t)
	omega := ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
	ix.Add(piptest.Dist{Name: "eps", Version: "1.0.0", Uploaded: released})
	ix.Add(piptest.Dist{Name: "zeta", Version: "2.0.0", Tag: "cp311-cp311-win_amd64", Uploaded: released})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "omega==1.0.0\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("eps", "1.0.0", "omega", "1.0.0", "theta", "3.0.0", "zeta", "2.0.0")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	status, _ := readStatus(t, st, a)
	if status.State != store.Done {
		t.Errorf("state = %q, want done", status.State)
	}
	want := []string{"validate:done", "prepare-tools:done", "check-pins:done", "resolve:done", "choose-wheels:done", "scan:done"}
	if !slices.Equal(stepNames(status.Steps), want) {
		t.Fatalf("steps = %v, want %v", stepNames(status.Steps), want)
	}
	log := pipLog(t, a)
	for _, want := range []string{
		"eps==1.0.0: source distribution only",
		"theta==3.0.0: no files on the index",
		"zeta==2.0.0: wheels for other platforms only",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log = %q, want %q", log, want)
		}
	}
	res, _ := readPipResult(t, st, a)
	wantBlocking := []PipBlocking{
		{Name: "eps", Version: "1.0.0", Kind: "source-only", Detail: "source distribution only"},
		{Name: "theta", Version: "3.0.0", Kind: "no-files", Detail: "no files on the index"},
		{Name: "zeta", Version: "2.0.0", Kind: "other-platforms", Detail: "wheels for other platforms only"},
	}
	if !reflect.DeepEqual(res.Blocking, wantBlocking) {
		t.Errorf("blocking = %+v, want %+v", res.Blocking, wantBlocking)
	}
	if got := packageNames(res.Packages); !slices.Equal(got, []string{"eps", "omega", "theta", "zeta"}) {
		t.Fatalf("packages = %v, want every package of the set", got)
	}
	for _, p := range res.Packages {
		switch {
		case p.Name == "omega" && (p.Wheel == nil || p.Wheel.File != omega.Filename):
			t.Errorf("omega wheel = %+v, want %s", p.Wheel, omega.Filename)
		case p.Name != "omega" && p.Wheel != nil:
			t.Errorf("%s wheel = %+v, want none", p.Name, p.Wheel)
		}
	}
}

// A constraint limits a package only when something requires it, and a
// marker can leave a requirement out for the target: neither is installed,
// so neither needs a wheel.
func TestCheckPinsSkipsPinsTheTargetDoesNotInstall(t *testing.T) {
	cases := []struct {
		name  string
		files []store.RequirementsFile
	}{
		{"a constraint nothing requires", []store.RequirementsFile{
			reqFile("requirements.txt", "requests==2.32.3\n-c constraints.txt\n"),
			reqFile("constraints.txt", "pywin32==306\n"),
		}},
		{"a requirement marked for another platform", []store.RequirementsFile{
			reqFile("requirements.txt", "requests==2.32.3\npywin32==306 ; sys_platform == \"win32\"\n"),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
			ix.Add(piptest.Dist{Name: "pywin32", Version: "306", Tag: "cp311-cp311-win_amd64"})
			a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, c.files...)
			a.Uv = &fakeUv{lock: "requests==2.32.3\n", set: resolved("requests", "2.32.3")}

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if status, _ := readStatus(t, st, a); status.State != store.Done {
				t.Errorf("state = %q, want done", status.State)
			}
			if n := ix.Requests("/simple/pywin32/"); n != 0 {
				t.Errorf("the pywin32 page was read %d times, want 0: the target never installs it", n)
			}
		})
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
	certifi := ix.Add(piptest.Dist{Name: "certifi", Version: "2024.8.30", Tag: "py3-none-any", Uploaded: released})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "numpy==2.1.0\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("certifi", "2024.8.30", "numpy", "2.1.0")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, _ := readPipResult(t, st, a)
	want := map[string]PipWheel{
		"certifi": {File: certifi.Filename, URL: certifi.URL, Sha256: certifi.Sha256, Size: certifi.Size, UploadedAt: &released},
		"numpy":   {File: native.Filename, URL: native.URL, Sha256: native.Sha256, Size: native.Size},
	}
	if len(res.Packages) != 2 {
		t.Fatalf("packages = %+v, want certifi and numpy", res.Packages)
	}
	for _, p := range res.Packages {
		if p.Wheel == nil || !reflect.DeepEqual(*p.Wheel, want[p.Name]) {
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

func TestPipAnalysisMarksAYankedReleaseWithACleanReason(t *testing.T) {
	cases := []struct {
		name   string
		yanked string
		want   string
	}{
		{"with a reason", "broken connection pool", "broken connection pool"},
		{"with no reason", "-", ""},
		{"with only a line feed as the reason", "\n", ""},
		{"with only a tab as the reason", "\t", ""},
		{"with control characters in the reason", "bad\u202e\x1b[31m pool", "bad[31m pool"},
		{"with a line separator in the reason", "first line\u2028second line", "first line second line"},
		{"with no-break spaces in the reason", "see\u00a0issue\u202f12\u3000now", "see\u00a0issue\u202f12\u3000now"},
		{"with a URL carrying credentials in the reason", "moved to http://alice:s3cret@host/", "moved to http://host/"},
		{"with a reason of 300 characters", strings.Repeat("x", 300), strings.Repeat("x", 200)},
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
			if len(res.Packages) != 1 || res.Packages[0].Yanked == nil {
				t.Fatalf("packages = %+v, want redis marked yanked", res.Packages)
			}
			got := res.Packages[0].Yanked.Reason
			if got != c.want {
				t.Errorf("yanked reason = %q, want %q", got, c.want)
			}
			if got != "" {
				if err := archive.CheckReason(got); err != nil {
					t.Errorf("archive.CheckReason(%q) = %v, want the import to accept it", got, err)
				}
			}
		})
	}
}

// The mark on the package replaces the sentence a yanked release used to
// add to the warnings, and a release the index keeps carries no mark.
func TestPipAnalysisWritesNoYankedWarning(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "redis", Version: "5.0.8", Tag: "py3-none-any", Yanked: "broken connection pool"})
	ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "redis==5.0.8\nrequests==2.32.3\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("redis", "5.0.8", "requests", "2.32.3")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %q, want none", res.Warnings)
	}
	if len(res.Packages) != 2 || res.Packages[0].Yanked == nil || res.Packages[1].Yanked != nil {
		t.Fatalf("packages = %+v, want redis marked yanked and requests not", res.Packages)
	}
	if n := strings.Count(string(raw), `"yanked"`); n != 1 {
		t.Errorf("pip-result.json = %s, holds %d yanked keys, want 1", raw, n)
	}
}

func TestPipAnalysisRecordsTheWheelUploadTime(t *testing.T) {
	ix := piptest.NewIndex(t)
	ix.Add(piptest.Dist{Name: "delta", Version: "2.0.0", Tag: "py3-none-any", Uploaded: released})
	ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, reqFile("requirements.txt", "delta==2.0.0\nomega==1.0.0\n"))
	a.Uv = &fakeUv{lock: "x==1\n", set: resolved("delta", "2.0.0", "omega", "1.0.0")}

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	res, raw := readPipResult(t, st, a)
	if len(res.Packages) != 2 || res.Packages[0].Wheel == nil || res.Packages[1].Wheel == nil {
		t.Fatalf("packages = %+v, want delta and omega with a wheel each", res.Packages)
	}
	if got := res.Packages[0].Wheel.UploadedAt; got == nil || !got.Equal(released) || got.Location() != time.UTC {
		t.Errorf("delta uploadedAt = %v, want %v in UTC", got, released)
	}
	if got := res.Packages[1].Wheel.UploadedAt; got != nil {
		t.Errorf("omega uploadedAt = %v, want absent: the index gives none", got)
	}
	if n := strings.Count(string(raw), `"uploadedAt"`); n != 1 {
		t.Errorf("pip-result.json = %s, holds %d uploadedAt keys, want 1", raw, n)
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

// uv resolves a package no pin fixes among the files uploaded before the
// minimum release age, so a wheel added to an old release afterwards must
// not be the one recorded. A pin, from either kind of file, stays exempt.
func TestChooseWheelsHoldsUnpinnedPackagesToTheReleaseAge(t *testing.T) {
	now := time.Now().UTC()
	old, young := now.Add(-60*24*time.Hour), now.Add(-time.Hour)
	youngWarning := "eps==1.0.0 was uploaded on " + young.Format(time.DateOnly) + ", within the 14-day minimum release age"
	cases := []struct {
		name        string
		constraint  string // constraints.txt, empty for none
		dists       []piptest.Dist
		wantFile    string // the recorded wheel; empty when choose-wheels blocks eps
		wantWarning []string
		wantBlock   PipBlocking
	}{
		{
			name: "a wheel added to an old release",
			dists: []piptest.Dist{
				{Name: "eps", Version: "1.0.0", Tag: "py3-none-any", Uploaded: old},
				{Name: "eps", Version: "1.0.0", Tag: "cp311-cp311-manylinux_2_17_x86_64", Uploaded: young},
			},
			wantFile: "eps-1.0.0-py3-none-any.whl",
		},
		{
			name: "a wheel with no upload date",
			dists: []piptest.Dist{
				{Name: "eps", Version: "1.0.0", Tag: "py3-none-any", Uploaded: old},
				{Name: "eps", Version: "1.0.0", Tag: "cp311-cp311-manylinux_2_17_x86_64"},
			},
			wantFile: "eps-1.0.0-py3-none-any.whl",
		},
		{
			name: "an old source distribution beside young wheels",
			dists: []piptest.Dist{
				{Name: "eps", Version: "1.0.0", Uploaded: old},
				{Name: "eps", Version: "1.0.0", Tag: "py3-none-any"},
				{Name: "eps", Version: "1.0.0", Tag: "cp311-cp311-manylinux_2_17_x86_64", Uploaded: young},
			},
			wantBlock: PipBlocking{Name: "eps", Version: "1.0.0", Kind: "source-only",
				Detail: "source distribution only, counting only the files uploaded more than 14 days ago"},
		},
		{
			name: "young files only",
			dists: []piptest.Dist{
				{Name: "eps", Version: "1.0.0", Tag: "py3-none-any", Uploaded: young},
			},
			wantBlock: PipBlocking{Name: "eps", Version: "1.0.0", Kind: "no-files",
				Detail: "no files on the index, counting only the files uploaded more than 14 days ago"},
		},
		{
			name:       "a constraint keeps its young wheel and warns",
			constraint: "eps==1.0.0\n",
			dists: []piptest.Dist{
				{Name: "eps", Version: "1.0.0", Tag: "py3-none-any", Uploaded: old},
				{Name: "eps", Version: "1.0.0", Tag: "cp311-cp311-manylinux_2_17_x86_64", Uploaded: young},
			},
			wantFile:    "eps-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
			wantWarning: []string{youngWarning},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := piptest.NewIndex(t)
			ix.Add(piptest.Dist{Name: "omega", Version: "1.0.0", Tag: "py3-none-any"})
			for _, d := range c.dists {
				ix.Add(d)
			}
			files := []store.RequirementsFile{reqFile("requirements.txt", "omega==1.0.0\n")}
			if c.constraint != "" {
				files = []store.RequirementsFile{
					reqFile("requirements.txt", "omega==1.0.0\n-c constraints.txt\n"),
					reqFile("constraints.txt", c.constraint),
				}
			}
			a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget, files...)
			a.Uv = &fakeUv{lock: "x==1\n", set: resolved("eps", "1.0.0", "omega", "1.0.0")}

			if err := a.Run(context.Background(), func(Event) {}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			res, _ := readPipResult(t, st, a)
			i := slices.IndexFunc(res.Packages, func(p PipPackage) bool { return p.Name == "eps" })
			if i < 0 {
				t.Fatalf("packages = %+v, want eps", res.Packages)
			}
			if c.wantFile != "" {
				if res.Packages[i].Wheel == nil || res.Packages[i].Wheel.File != c.wantFile {
					t.Errorf("packages = %+v, want eps recorded as %s", res.Packages, c.wantFile)
				}
				if !slices.Equal(res.Warnings, c.wantWarning) {
					t.Errorf("warnings = %q, want %q", res.Warnings, c.wantWarning)
				}
				return
			}
			if w := res.Packages[i].Wheel; w != nil {
				t.Errorf("eps wheel = %+v, want none", w)
			}
			if log := pipLog(t, a); !strings.Contains(log, "eps==1.0.0: "+c.wantBlock.Detail) {
				t.Errorf("log = %q, want %q", log, c.wantBlock.Detail)
			}
			if !reflect.DeepEqual(res.Blocking, []PipBlocking{c.wantBlock}) {
				t.Errorf("blocking = %+v, want %+v", res.Blocking, c.wantBlock)
			}
		})
	}
}

func TestChooseWheelsFetchesNoFile(t *testing.T) {
	ix := piptest.NewIndex(t)
	files := []string{
		ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3", Tag: "py3-none-any"}).Filename,
		ix.Add(piptest.Dist{Name: "requests", Version: "2.32.3"}).Filename,
		ix.Add(piptest.Dist{Name: "idna", Version: "3.10", Tag: "py3-none-any", Uploaded: released}).Filename,
		ix.Add(piptest.Dist{Name: "idna", Version: "3.10", Uploaded: released}).Filename,
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
		want    string // in the log for a blocked pin, in the step's error otherwise
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

			err := a.Run(context.Background(), func(Event) {})
			status, _ := readStatus(t, st, a)
			_, serr := os.Stat(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "pip-result.json"))
			if c.blocked {
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				if log := pipLog(t, a); !strings.Contains(log, c.want) {
					t.Errorf("log = %q, want %q", log, c.want)
				}
				if serr != nil {
					t.Errorf("pip-result.json: %v, want it written", serr)
				}
				return
			}
			if err == nil {
				t.Fatal("Run succeeded, want check-pins to fail")
			}
			if len(status.Steps) != 3 || !strings.Contains(status.Steps[2].Error, c.want) {
				t.Errorf("steps = %+v, want check-pins failing with %q", status.Steps, c.want)
			}
			if n := len(uv.Calls()); n != 0 {
				t.Errorf("uv ran %d times, want 0", n)
			}
			if serr == nil {
				t.Error("pip-result.json written, want none: the index never answered")
			}
		})
	}
}

// packageNames lists the names of pkgs in order.
func packageNames(pkgs []PipPackage) []string {
	names := make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i] = p.Name
	}
	return names
}

// scannedPurls lists the package URLs of the SBOM trivy scanned last.
func scannedPurls(t *testing.T, trivy *cannedTrivy) []string {
	t.Helper()
	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(trivy.sbom, &doc); err != nil {
		t.Fatalf("decode the scanned SBOM: %v", err)
	}
	purls := make([]string, len(doc.Components))
	for i, c := range doc.Components {
		purls[i] = c.PURL
	}
	return purls
}
