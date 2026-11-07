package service

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/s3"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

const bucketAlice = "user-alice"

// attemptRig is a handler set over the fakes, with one import of a bundle recorded as the start would.
type attemptRig struct {
	h     *Handlers
	minio *fakeMinio
	nexus *fakeNexus
	imp   imports.Import
	b     testBundle
}

func newAttemptRig(t *testing.T) *attemptRig {
	t.Helper()
	nx, ca := newFakeNexus(t, leftPad)
	m := newFakeMinio()
	b := buildBundle(t, leftPad)
	m.putData(archiveKey, b.archive)
	m.putData(manifestKey, b.manifest)
	h := New(Config{MinIO: m, Settings: nx.settings(t, ca), NewPublisher: newPublisher, ImportVersion: "0.3.0"})
	imp := imports.Import{
		ID: "20261106T101500Z-3f9a0c1d", User: "alice",
		Archive:  imports.Object{Key: archiveKey, ETag: m.etagOf(archiveKey), Size: int64(len(b.archive))},
		Manifest: imports.Object{Key: manifestKey, ETag: m.etagOf(manifestKey)},
	}
	m.calls = nil
	return &attemptRig{h: h, minio: m, nexus: nx, imp: imp, b: b}
}

func (a *attemptRig) run(t *testing.T) (importer.Report, *imports.Removal, string) {
	t.Helper()
	dir := t.TempDir()
	rep, remove := a.h.RunAttempt(context.Background(), a.imp, dir, importer.Progress{})
	var rem *imports.Removal
	if remove != nil {
		rem = remove(context.Background())
	}
	return rep, rem, dir
}

func TestAttemptReadsEachObjectOnce(t *testing.T) {
	a := newAttemptRig(t)
	rep, rem, dir := a.run(t)
	if rep.Outcome != importer.OutcomeComplete || rep.Counts.Published != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if rem == nil || !rem.Removed {
		t.Errorf("removal = %+v, want both objects removed", rem)
	}
	gets := map[string]string{}
	for _, c := range a.minio.recorded() {
		if c.Op != "get" {
			continue
		}
		if _, dup := gets[c.Key]; dup {
			t.Errorf("%s read twice", c.Key)
		}
		gets[c.Key] = c.ETag
	}
	if len(gets) != 2 || gets[manifestKey] != a.imp.Manifest.ETag || gets[archiveKey] != a.imp.Archive.ETag {
		t.Errorf("reads = %v, want the manifest and the archive, each with its recorded ETag", gets)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the work directory still holds %d entries", len(entries))
	}
	if rep.Archive.File != "packages_npm.tar.gz" {
		t.Errorf("archive file = %q", rep.Archive.File)
	}
}

func TestAttemptCutStreamIsIncomplete(t *testing.T) {
	boom := errors.New("connection reset by peer")
	tests := []struct {
		name  string
		setup func(a *attemptRig)
		want  string
	}{
		{"the body ends early", func(a *attemptRig) { a.minio.cut[dataKey(bucketAlice, archiveKey)] = len(a.b.archive) / 2 }, "cut short"},
		{"the body fails", func(a *attemptRig) {
			k := dataKey(bucketAlice, archiveKey)
			a.minio.cut[k] = len(a.b.archive) / 2
			a.minio.readErr[k] = boom
		}, "connection reset"},
		{"the manifest ends early", func(a *attemptRig) { a.minio.cut[dataKey(bucketAlice, manifestKey)] = len(a.b.manifest) / 2 }, "cut short"},
		{"MinIO fails the read", func(a *attemptRig) {
			a.minio.failWith = &s3.Error{Status: 500, Code: "InternalError", Message: "disk on fire"}
		}, "disk on fire"},
		{"the archive is gone", func(a *attemptRig) { delete(a.minio.buckets[bucketAlice], archiveKey) }, "no longer in MinIO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAttemptRig(t)
			tt.setup(a)
			rep, _, _ := a.run(t)
			if rep.Outcome != importer.OutcomeIncomplete {
				t.Fatalf("outcome %q (%s), want incomplete and never refused", rep.Outcome, rep.Reason)
			}
			if !strings.Contains(rep.Reason+failReasons(rep), tt.want) {
				t.Errorf("reason %q and packages %+v do not say %q", rep.Reason, rep.Packages, tt.want)
			}
			if strings.Contains(strings.ToLower(rep.Reason), "refus") {
				t.Errorf("reason %q reads like a refusal", rep.Reason)
			}
			if a.nexus.uploadCount() != 0 {
				t.Error("a cut archive was uploaded")
			}
			// Once the manifest is read, every listed package fails with the reason.
			if len(rep.Packages) > 0 {
				for _, p := range rep.Packages {
					if p.State != importer.Failed || p.Reason == "" {
						t.Errorf("package %+v, want failed with a reason", p)
					}
				}
			}
		})
	}
}

func failReasons(rep importer.Report) string {
	var out []string
	for _, p := range rep.Packages {
		out = append(out, p.Reason)
	}
	return strings.Join(out, "; ")
}

func TestAttemptChangedObjectIsRefused(t *testing.T) {
	for name, key := range map[string]string{"archive": archiveKey, "manifest": manifestKey} {
		t.Run(name, func(t *testing.T) {
			a := newAttemptRig(t)
			a.minio.change(key)
			rep, _, _ := a.run(t)
			want := "the " + name + " changed in MinIO; start a new import"
			if rep.Outcome != importer.OutcomeRefused || rep.Reason != want {
				t.Errorf("outcome %q, reason %q; want refused with %q", rep.Outcome, rep.Reason, want)
			}
			if a.nexus.uploadCount() != 0 {
				t.Error("a changed archive was uploaded")
			}
			if rep.ArchiveChecked == nil || *rep.ArchiveChecked {
				t.Errorf("archiveChecked %v, want false: no object was read", rep.ArchiveChecked)
			}
		})
	}
}

func TestAttemptWithoutWorkingDirectoryIsUnchecked(t *testing.T) {
	a := newAttemptRig(t)
	dir := t.TempDir() + "/missing"
	rep, remove := a.h.RunAttempt(context.Background(), a.imp, dir, importer.Progress{})
	if remove != nil {
		t.Error("an attempt with no working directory returned a removal")
	}
	if rep.Outcome != importer.OutcomeRefused || !strings.Contains(rep.Reason, "no working directory") {
		t.Errorf("outcome %q, reason %q; want refused for the working directory", rep.Outcome, rep.Reason)
	}
	if rep.ArchiveChecked == nil || *rep.ArchiveChecked {
		t.Errorf("archiveChecked %v, want false: no object was read", rep.ArchiveChecked)
	}
	if a.nexus.uploadCount() != 0 {
		t.Error("an unchecked archive was uploaded")
	}
}

func TestAttemptRefusesAnETagThatIsNotTheOneAsked(t *testing.T) {
	a := newAttemptRig(t)
	a.minio.serveETag[dataKey(bucketAlice, archiveKey)] = `"another"`
	rep, _, _ := a.run(t)
	if rep.Outcome != importer.OutcomeRefused || !strings.Contains(rep.Reason, "changed in MinIO") {
		t.Errorf("outcome %q, reason %q; want refused as changed", rep.Outcome, rep.Reason)
	}
}

func TestAttemptInterruptedIsNotARefusal(t *testing.T) {
	a := newAttemptRig(t)
	a.minio.stall[dataKey(bucketAlice, archiveKey)] = len(a.b.archive) / 2
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan importer.Report, 1)
	go func() {
		rep, _ := a.h.RunAttempt(ctx, a.imp, t.TempDir(), importer.Progress{})
		done <- rep
	}()
	// The body stalls until its context ends; cancel once the read is blocked.
	select {
	case <-a.minio.stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("the read never started")
	}
	cancel()
	select {
	case rep := <-done:
		if rep.Outcome != importer.OutcomeIncomplete {
			t.Errorf("outcome %q (%s), want incomplete", rep.Outcome, rep.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the attempt did not stop")
	}
}

func TestMinioSource(t *testing.T) {
	old := idleReadTimeout
	idleReadTimeout = 20 * time.Millisecond
	t.Cleanup(func() { idleReadTimeout = old })

	read := func(open func(context.Context) (io.ReadCloser, error)) ([]byte, error) {
		rc, err := open(context.Background())
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	t.Run("a whole body reads clean", func(t *testing.T) {
		a := newAttemptRig(t)
		src := minioSource(a.minio, bucketAlice, a.imp)
		got, err := read(src.Archive)
		if err != nil || len(got) != len(a.b.archive) {
			t.Errorf("read %d bytes, %v; want %d", len(got), err, len(a.b.archive))
		}
		if src.Name != "packages_npm.tar.gz" {
			t.Errorf("name = %q", src.Name)
		}
	})
	t.Run("a stalled body is a source failure", func(t *testing.T) {
		a := newAttemptRig(t)
		a.minio.stall[dataKey(bucketAlice, archiveKey)] = 10
		_, err := read(minioSource(a.minio, bucketAlice, a.imp).Archive)
		if !errors.Is(err, importer.ErrSource) || !strings.Contains(err.Error(), "no data") {
			t.Errorf("err = %v, want ErrSource naming the idle wait", err)
		}
	})
	t.Run("a failing body is a source failure", func(t *testing.T) {
		a := newAttemptRig(t)
		a.minio.readErr[dataKey(bucketAlice, archiveKey)] = io.ErrUnexpectedEOF
		a.minio.cut[dataKey(bucketAlice, archiveKey)] = 10
		_, err := read(minioSource(a.minio, bucketAlice, a.imp).Archive)
		if !errors.Is(err, importer.ErrSource) {
			t.Errorf("err = %v, want ErrSource", err)
		}
	})
	t.Run("a changed object is a refusal", func(t *testing.T) {
		a := newAttemptRig(t)
		a.minio.change(archiveKey)
		_, err := read(minioSource(a.minio, bucketAlice, a.imp).Archive)
		var ref *archive.Refusal
		if !errors.As(err, &ref) || errors.Is(err, importer.ErrSource) {
			t.Errorf("err = %v, want a *archive.Refusal", err)
		}
	})
	t.Run("a missing object is a source failure", func(t *testing.T) {
		a := newAttemptRig(t)
		delete(a.minio.buckets[bucketAlice], manifestKey)
		_, err := read(minioSource(a.minio, bucketAlice, a.imp).Manifest)
		if !errors.Is(err, importer.ErrSource) {
			t.Errorf("err = %v, want ErrSource", err)
		}
	})
	t.Run("an interrupt stays an interrupt", func(t *testing.T) {
		a := newAttemptRig(t)
		a.minio.stall[dataKey(bucketAlice, archiveKey)] = 10
		ctx, cancel := context.WithCancel(context.Background())
		rc, err := minioSource(a.minio, bucketAlice, a.imp).Archive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		cancel()
		_, err = io.ReadAll(rc)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want the context's error", err)
		}
	})
}
