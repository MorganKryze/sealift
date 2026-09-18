package jobs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MorganKryze/sealift/npm"
	"github.com/MorganKryze/sealift/rank"
)

// stepValidate is step 1: it reads the project's package.json, rejects
// anything the proof of concept does not support, and copies the manifest
// into the analysis directory. A validation problem blocks the start: Run
// returns without going further.
func (r *run) stepValidate() (npm.Manifest, error) {
	var manifest npm.Manifest
	err := r.runStep("validate", func() error {
		raw, ferr := os.ReadFile(filepath.Join(r.a.Project.Dir, "package.json"))
		if ferr != nil {
			return fmt.Errorf("read package.json: %w", ferr)
		}
		m, perr := npm.ParseManifest(bytes.NewReader(raw))
		if perr != nil {
			return fmt.Errorf("parse package.json: %w", perr)
		}
		if problems := m.Validate(); len(problems) > 0 {
			for _, p := range problems {
				r.log(formatProblem(p))
			}
			return fmt.Errorf("%d problem(s) in package.json, see the log", len(problems))
		}
		if werr := os.WriteFile(filepath.Join(r.a.Dir, "package.json"), raw, 0o664); werr != nil {
			return fmt.Errorf("copy package.json: %w", werr)
		}
		manifest = m
		return nil
	})
	return manifest, err
}

func formatProblem(p npm.Problem) string {
	if p.Name == "" {
		return fmt.Sprintf("%s: %s", p.Field, p.Reason)
	}
	return fmt.Sprintf("%s.%s = %q: %s", p.Field, p.Name, p.Value, p.Reason)
}

// stepPrepareTools is step 2: it installs the project's pnpm version if
// missing and refreshes the Trivy database. A pnpm download failure stops
// the job; a database update failure on a stale database only warns.
func (r *run) stepPrepareTools() (trivyVersion string, dbDate time.Time, err error) {
	err = r.runStep("prepare-tools", func() error {
		if _, perr := r.a.Tools.EnsurePnpm(r.ctx, r.a.Settings.Target.PnpmVer); perr != nil {
			return fmt.Errorf("install pnpm %s: %w", r.a.Settings.Target.PnpmVer, perr)
		}
		if state, serr := r.a.Tools.TrivyState(r.ctx); serr == nil {
			trivyVersion, dbDate = state.Active, state.DBDate
		}
		if _, uerr := r.a.Trivy.UpdateDB(r.ctx); uerr != nil {
			r.result.Warnings = append(r.result.Warnings, fmt.Sprintf(
				"could not refresh the vulnerability database: %v; using the database from %s", uerr, dbDateLabel(dbDate)))
			r.log(fmt.Sprintf("trivy database update failed: %v", uerr))
			return nil
		}
		if state, serr := r.a.Tools.TrivyState(r.ctx); serr == nil {
			trivyVersion, dbDate = state.Active, state.DBDate
		}
		return nil
	})
	return trivyVersion, dbDate, err
}

// dbDateLabel formats t for a warning message, or names it unknown when
// the caller has no date yet (a fresh volume, or a Trivy state lookup that
// itself failed).
func dbDateLabel(t time.Time) string {
	if t.IsZero() {
		return "an unknown date"
	}
	return t.Format(time.DateOnly)
}

// stepResolveProject is step 3: it resolves the manifest as given, with no
// version overrides, and writes project/pnpm-lock.yaml. A resolution
// failure stops the job and shows pnpm's output.
func (r *run) stepResolveProject(manifest npm.Manifest) ([]npm.LockPackage, error) {
	var pkgs []npm.LockPackage
	err := r.runStep("resolve-project", func() error {
		lockRaw, output, rerr := r.a.resolve(r.ctx, buildFullManifest(manifest, nil))
		if rerr != nil {
			r.log("pnpm: " + output)
			return fmt.Errorf("resolve project: %w", rerr)
		}
		if werr := os.MkdirAll(filepath.Join(r.a.Dir, "project"), 0o770); werr != nil {
			return werr
		}
		if werr := os.WriteFile(filepath.Join(r.a.Dir, "project", "pnpm-lock.yaml"), lockRaw, 0o664); werr != nil {
			return werr
		}
		parsed, perr := npm.ParseLockfile(bytes.NewReader(lockRaw))
		if perr != nil {
			return fmt.Errorf("parse project lockfile: %w", perr)
		}
		pkgs = platformOf(r.a.Settings.Target).Filter(parsed)
		return nil
	})
	return pkgs, err
}

// stepScanProject is step 4: it scans the project's filtered packages and
// records the "before" vector. A scan failure stops the job.
func (r *run) stepScanProject(pkgs []npm.LockPackage) (rank.Index, error) {
	var index rank.Index
	err := r.runStep("scan-project", func() error {
		findings, serr := r.a.scanPackages(r.ctx, pkgs, filepath.Join(r.a.Dir, "project.trivy.json"))
		if serr != nil {
			return fmt.Errorf("scan project: %w", serr)
		}
		index = rank.NewIndex(findings)
		r.result.Before = Vector(rank.VectorOf(index.Set(keysOf(pkgs))))
		return nil
	})
	return index, err
}
