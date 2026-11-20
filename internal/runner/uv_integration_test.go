//go:build integration

package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/pip"
)

// TestUvResolvesAgainstALocalIndex runs the real uv against a fake index on
// loopback. The target's Python version decides the markers, and the
// interpreter found on PATH only starts uv.
func TestUvResolvesAgainstALocalIndex(t *testing.T) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv not found on PATH; skipping uv integration test")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH; skipping uv integration test")
	}

	start := time.Now().UTC().Truncate(time.Second)
	old := start.Add(-60 * 24 * time.Hour)
	yesterday := start.Add(-24 * time.Hour)
	ix := piptest.NewIndex(t)
	for _, d := range []piptest.Dist{
		{Name: "alpha", Version: "1.0.0", Requires: []string{`beta==2.0.0; python_full_version < "3.11.3"`}},
		{Name: "beta", Version: "2.0.0"},
		{Name: "beta", Version: "3.0.0"},
		{Name: "devtool", Version: "1.0.0"},
		{Name: "zeta", Version: "1.0.0", Requires: []string{"gamma>=1.0"}},
		{Name: "gamma", Version: "1.0.0"},
		{Name: "gamma", Version: "1.1.0", Uploaded: yesterday},
		{Name: "delta", Version: "2.0.0", Uploaded: yesterday},
		{Name: "omega", Version: "1.0.0", Requires: []string{"eps==1.0.0"}},
	} {
		d.Tag = "py3-none-any"
		if d.Uploaded.IsZero() {
			d.Uploaded = old
		}
		ix.Add(d)
	}
	ix.Add(piptest.Dist{Name: "eps", Version: "1.0.0", Uploaded: old})

	files := func(t *testing.T, contents ...string) pip.Set {
		t.Helper()
		var fs []pip.File
		for i, c := range contents {
			name := "requirements.txt"
			if i > 0 {
				name = "requirements-dev.txt"
			}
			fs = append(fs, pip.File{Name: name, Data: []byte(c)})
		}
		set, problems := pip.ParseFiles(fs)
		if len(problems) > 0 {
			t.Fatalf("ParseFiles: %+v", problems)
		}
		return set
	}
	compile := func(t *testing.T, set pip.Set, python311 string) (CompileResult, error) {
		t.Helper()
		target := store.DefaultPipTarget
		target.Python = python311
		var exempt []string
		for _, p := range slices.Concat(set.Requirements, set.Constraints) {
			exempt = append(exempt, p.Key)
		}
		in := CompileInput{
			Bin: uv, Dir: t.TempDir(),
			Requirements: set.RequirementsIn(), Constraints: set.ConstraintsTxt(),
			Target: target, Index: ix.URL,
			ExcludeNewer: start.Add(-14 * 24 * time.Hour), Exempt: exempt, ExemptUntil: start,
		}
		return NewUvCLI(python, t.TempDir(), nil).Compile(context.Background(), in)
	}
	names := func(res CompileResult) map[string]string {
		got := map[string]string{}
		for _, r := range res.Set {
			got[r.Name] = r.Version
		}
		return got
	}

	t.Run("a marker true at 3.11.2", func(t *testing.T) {
		res, err := compile(t, files(t, "alpha==1.0.0\n"), "3.11.2")
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, res.Output)
		}
		if got := names(res); got["beta"] != "2.0.0" {
			t.Errorf("set = %v, want beta 2.0.0 for Python 3.11.2", got)
		}
	})
	t.Run("the same marker false at 3.11.3", func(t *testing.T) {
		res, err := compile(t, files(t, "alpha==1.0.0\n"), "3.11.3")
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, res.Output)
		}
		if got := names(res); len(got) != 1 || got["alpha"] != "1.0.0" {
			t.Errorf("set = %v, want alpha alone for Python 3.11.3", got)
		}
	})
	t.Run("files resolved together", func(t *testing.T) {
		res, err := compile(t, files(t, "alpha==1.0.0\n", "devtool==1.0.0\n"), "3.11.2")
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, res.Output)
		}
		want := []Resolved{{"alpha", "1.0.0"}, {"beta", "2.0.0"}, {"devtool", "1.0.0"}}
		if !slices.Equal(res.Set, want) {
			t.Errorf("set = %+v, want %+v", res.Set, want)
		}
	})
	t.Run("a conflict across two files", func(t *testing.T) {
		res, err := compile(t, files(t, "alpha==1.0.0\n", "beta==3.0.0\n"), "3.11.2")
		if err == nil {
			t.Fatalf("Compile succeeded with %+v, want a conflict", res.Set)
		}
		cause := uvFailure(res.Output)
		for _, want := range []string{"alpha==1.0.0", "beta==3.0.0", "beta", "unsatisfiable"} {
			if !strings.Contains(cause, want) || !strings.Contains(err.Error(), want) {
				t.Errorf("cause = %q, error = %q, want both to name %q", cause, err, want)
			}
		}
	})
	t.Run("a young release waits", func(t *testing.T) {
		res, err := compile(t, files(t, "zeta==1.0.0\n"), "3.11.2")
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, res.Output)
		}
		if got := names(res); got["gamma"] != "1.0.0" {
			t.Errorf("set = %v, want gamma 1.0.0: 1.1.0 is a day old", got)
		}
	})
	t.Run("a young pin resolves", func(t *testing.T) {
		res, err := compile(t, files(t, "delta==2.0.0\n"), "3.11.2")
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, res.Output)
		}
		if got := names(res); got["delta"] != "2.0.0" {
			t.Errorf("set = %v, want the pinned delta 2.0.0", got)
		}
	})
	t.Run("a source-only package fails and is never fetched", func(t *testing.T) {
		res, err := compile(t, files(t, "omega==1.0.0\n"), "3.11.2")
		if err == nil {
			t.Fatalf("Compile succeeded with %+v, want eps refused", res.Set)
		}
		if cause := uvFailure(res.Output); !strings.Contains(cause, "eps==1.0.0 has no usable wheels") {
			t.Errorf("cause = %q, want eps named with no usable wheels", cause)
		}
		if n := ix.Requests("/files/eps-1.0.0.tar.gz"); n != 0 {
			t.Errorf("the sdist was requested %d times, want 0", n)
		}
	})
	t.Run("index variables reach no decoy", func(t *testing.T) {
		var decoyHits atomic.Int64
		decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			decoyHits.Add(1)
			http.NotFound(w, r)
		}))
		t.Cleanup(decoy.Close)
		for _, name := range []string{"UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_INDEX", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"} {
			t.Setenv(name, decoy.URL+"/simple/")
		}
		res, err := compile(t, files(t, "alpha==1.0.0\n"), "3.11.2")
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, res.Output)
		}
		if n := decoyHits.Load(); n != 0 {
			t.Errorf("the decoy index got %d requests, want 0", n)
		}
	})
}
