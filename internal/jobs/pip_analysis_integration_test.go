//go:build integration

package jobs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/piptest"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
)

// A pin whose marker is false on the target leaves its package to the
// resolver, held to the release age, when another pin needs it. The real uv
// resolves against a fake index on loopback.
func TestPipAnalysisWithUvHoldsAFalseMarkerPinsPackageToTheAge(t *testing.T) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv not found on PATH; skipping uv integration test")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH; skipping uv integration test")
	}

	now := time.Now().UTC()
	ix := piptest.NewIndex(t)
	for _, d := range []piptest.Dist{
		{Name: "zeta", Version: "1.0.0", Requires: []string{"gamma>=1.0"}, Uploaded: now.Add(-60 * 24 * time.Hour)},
		{Name: "gamma", Version: "1.0.0", Uploaded: now.Add(-60 * 24 * time.Hour)},
		{Name: "gamma", Version: "1.1.0", Uploaded: now.Add(-24 * time.Hour)},
	} {
		d.Tag = "py3-none-any"
		ix.Add(d)
	}
	a, st := newPipAnalysis(t, ix.URL, store.DefaultPipTarget,
		reqFile("requirements.txt", "zeta==1.0.0\ngamma==1.0.0 ; python_version < \"3.8\"\n"))
	// EnsureUv finds the target's uv installed and runs the one on PATH.
	bin := filepath.Join(st.Root(), "tools", "uv", store.DefaultPipTarget.UvVer, "uv")
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(uv, bin); err != nil {
		t.Fatal(err)
	}
	a.Uv = runner.NewUvCLI(python, filepath.Join(st.Root(), "cache", "uv"), nil)

	if err := a.Run(context.Background(), func(Event) {}); err != nil {
		status, _ := readStatus(t, st, a)
		t.Fatalf("Run: %v; steps %+v", err, status.Steps)
	}
	lock, err := os.ReadFile(filepath.Join(strings.TrimSuffix(a.Dir, ".tmp"), "project", "requirements.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lock), "gamma==1.0.0") || !strings.Contains(string(lock), "zeta==1.0.0") {
		t.Errorf("requirements.lock = %q, want zeta 1.0.0 and gamma 1.0.0: gamma 1.1.0 is a day old", lock)
	}
}
