package importer

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/importtest"
	"github.com/MorganKryze/sealift/internal/nexus"
)

const pipRepo = "pypi"

func pypiClient(t *testing.T, n *importtest.PyPINexus) *nexus.Client {
	t.Helper()
	c, err := nexus.New(nexus.Config{URL: n.URL, Repository: pipRepo, Format: nexus.FormatPyPI, User: "sealift-import", Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// stageWheel writes w as a checked wheel and returns its package.
func stageWheel(t *testing.T, dir string, w importtest.WheelFile) Package {
	t.Helper()
	path := filepath.Join(dir, w.File)
	if err := os.WriteFile(path, w.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(w.Body)
	return Package{Name: w.Name, Version: w.Version, File: w.File, Path: path, SHA512: sum[:]}
}

func sha512Hex(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

func TestPublishWheels(t *testing.T) {
	six := importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any")
	other := importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any", importtest.Entry{Name: "six/extra.py", Body: []byte("x = 1\n")})
	for name, tc := range map[string]struct {
		setup   func(t *testing.T, n *importtest.PyPINexus, pkg *Package)
		cancel  bool
		state   State
		kind    Kind
		reason  []string
		uploads int
	}{
		"published": {
			setup: func(*testing.T, *importtest.PyPINexus, *Package) {},
			state: Published, uploads: 1,
		},
		"present on the same bytes": {
			setup: func(_ *testing.T, n *importtest.PyPINexus, _ *Package) { n.Put("six", six.File, six.Body) },
			state: Present,
		},
		"conflict on other bytes": {
			setup: func(_ *testing.T, n *importtest.PyPINexus, _ *Package) { n.Put("six", six.File, other.Body) },
			state: Failed, kind: KindConflict,
			reason: []string{"nexus holds this file with other bytes: shipped sha512 " + sha512Hex(six.Body) + ", nexus sha512 " + sha512Hex(other.Body)},
		},
		"500 on upload": {
			setup: func(_ *testing.T, n *importtest.PyPINexus, _ *Package) {
				n.SetStatus("/service/rest/v1/components", http.StatusInternalServerError)
			},
			state: Failed, kind: KindNexus,
			reason: []string{"upload failed: nexus answered 500: status 500 from the fake"},
		},
		"page omits the file after the upload": {
			setup: func(_ *testing.T, n *importtest.PyPINexus, _ *Package) { n.Omit(six.File) },
			state: Failed, kind: KindNexus, uploads: 1,
			reason: []string{"nexus accepted the upload but does not list the file"},
		},
		"other bytes after the upload": {
			setup: func(_ *testing.T, n *importtest.PyPINexus, _ *Package) { n.Tamper() },
			state: Failed, kind: KindNexus, uploads: 1,
			reason: []string{"nexus serves other bytes after the upload: shipped sha512 " + sha512Hex(six.Body) + ", nexus sha512 " + sha512Hex(append(slices.Clone(six.Body), '!'))},
		},
		"file changed after the checks": {
			setup: func(t *testing.T, _ *importtest.PyPINexus, pkg *Package) {
				if err := os.WriteFile(pkg.Path, other.Body, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			state: Failed, kind: KindLocal,
			reason: []string{"the file changed after the checks: shipped sha512 " + sha512Hex(six.Body) + ", nexus sha512 " + sha512Hex(other.Body)},
		},
		"cancelled": {
			setup:  func(*testing.T, *importtest.PyPINexus, *Package) {},
			cancel: true,
			state:  Failed, kind: KindInterrupted,
			reason: []string{"interrupted"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, pipRepo)
			pkg := stageWheel(t, t.TempDir(), six)
			tc.setup(t, n, &pkg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			var ended []int
			res := PublishWheels(ctx, pypiClient(t, n), []Package{pkg}, t.TempDir(), func(i int, _ Result) { ended = append(ended, i) })
			r := res[0]
			if r.State != tc.state || r.Kind != tc.kind || r.Name != "six" || r.Version != "1.16.0" || r.File != six.File {
				t.Fatalf("got %+v, want state %s kind %q", r, tc.state, tc.kind)
			}
			for _, want := range tc.reason {
				if r.Reason != want {
					t.Errorf("reason %q, want %q", r.Reason, want)
				}
			}
			if len(tc.reason) == 0 && r.Reason != "" {
				t.Errorf("reason %q, want none", r.Reason)
			}
			if got := n.Uploads(); got != tc.uploads {
				t.Errorf("%d uploads, want %d", got, tc.uploads)
			}
			if !slices.Equal(ended, []int{0}) {
				t.Errorf("ended %v, want [0]", ended)
			}
		})
	}
}

func TestPublishWheelsReadsBackTheShippedBytes(t *testing.T) {
	n := importtest.NewPyPINexus(t, pipRepo)
	w := importtest.Wheel(t, "MarkupSafe", "2.1.5", "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64")
	pkg := stageWheel(t, t.TempDir(), w)
	res := PublishWheels(context.Background(), pypiClient(t, n), []Package{pkg}, t.TempDir(), nil)
	if res[0].State != Published {
		t.Fatalf("got %+v", res[0])
	}
	want := []string{
		"GET /service/rest/v1/repositories",
		"GET /repository/pypi/simple/markupsafe/",
		"POST /service/rest/v1/components",
		"GET /repository/pypi/simple/markupsafe/",
		"GET " + n.FilePath("markupsafe", w.File),
	}
	if got := n.Requests(); !slices.Equal(got, want) {
		t.Fatalf("requests %q, want %q", got, want)
	}
}

func TestPublishWheelsStopsWhenRepositoryCheckFails(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(n *importtest.PyPINexus)
		want  string
	}{
		"npm hosted": {func(n *importtest.PyPINexus) { n.SetRepository("npm", "hosted") }, `repository check failed: nexus repository "pypi" is npm hosted, not pypi hosted`},
		"401":        {func(n *importtest.PyPINexus) { n.SetStatus("/service/rest/v1/repositories", 401) }, "repository check failed: nexus answered 401: status 401 from the fake"},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, pipRepo)
			tc.setup(n)
			dir := t.TempDir()
			wheels := []Package{
				stageWheel(t, dir, importtest.Wheel(t, "six", "1.16.0", "py2.py3-none-any")),
				stageWheel(t, dir, importtest.Wheel(t, "idna", "3.6", "py3-none-any")),
			}
			for _, r := range PublishWheels(context.Background(), pypiClient(t, n), wheels, t.TempDir(), nil) {
				if r.State != Failed || r.Kind != KindNexus || r.Reason != tc.want {
					t.Errorf("%s: %+v, want %q", r.Name, r, tc.want)
				}
			}
			if got := n.Requests(); len(got) != 1 {
				t.Errorf("requests %q, want the repository list only", got)
			}
		})
	}
}

func TestPublishWheelsFailsAMismatchAndGoesOn(t *testing.T) {
	dir := t.TempDir()
	newer := importtest.Wheel(t, "six", "1.17.0", "py2.py3-none-any")
	idna := importtest.Wheel(t, "idna", "3.6", "py3-none-any")
	for name, tc := range map[string]struct {
		wheel importtest.WheelFile
		want  string
	}{
		"metadata names another version": {
			importtest.WheelFile{Name: "six", Version: "1.16.0", File: "six-1.16.0-py2.py3-none-any.whl", Body: newer.Body},
			`the wheel's METADATA says "six" "1.17.0", the manifest says six 1.16.0`,
		},
		"file name names another project": {
			importtest.WheelFile{Name: "six", Version: "1.17.0", File: "five-1.17.0-py2.py3-none-any.whl", Body: newer.Body},
			`the wheel's file name says "five" "1.17.0", the manifest says six 1.17.0`,
		},
		"not a wheel": {
			importtest.WheelFile{Name: "six", Version: "1.16.0", File: "six-1.16.0-py2.py3-none-any.whl", Body: []byte("not a zip")},
			"the wheel is not a valid package: the wheel is not a zip archive",
		},
		"file name is not a wheel name": {
			importtest.WheelFile{Name: "six", Version: "1.17.0", File: "six-1.17.0.tar.gz", Body: newer.Body},
			"the wheel's file name is not a wheel name: pip: file is not a wheel",
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := importtest.NewPyPINexus(t, pipRepo)
			bad := stageWheel(t, t.TempDir(), tc.wheel)
			good := stageWheel(t, dir, idna)
			res := PublishWheels(context.Background(), pypiClient(t, n), []Package{bad, good}, t.TempDir(), nil)
			if r := res[0]; r.State != Failed || r.Kind != KindMismatch || r.Reason != tc.want {
				t.Errorf("mismatch: %+v, want %q", r, tc.want)
			}
			if r := res[1]; r.State != Published {
				t.Errorf("next wheel: %+v", r)
			}
			for _, req := range n.Requests() {
				if strings.Contains(req, "six") || strings.Contains(req, "five") {
					t.Errorf("a request reached nexus for the mismatched wheel: %s", req)
				}
			}
			if got := n.Uploads(); got != 1 {
				t.Errorf("%d uploads, want 1", got)
			}
		})
	}
}

func TestPublishWheelsStopsBetweenWheels(t *testing.T) {
	dir := t.TempDir()
	wheels := []Package{
		stageWheel(t, dir, importtest.Wheel(t, "aaa", "1.0", "py3-none-any")),
		stageWheel(t, dir, importtest.Wheel(t, "bbb", "1.0", "py3-none-any")),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	pub := stubPublisher{fetch: func(context.Context) (bool, error) {
		calls++
		cancel()
		return false, context.Canceled
	}}
	res := PublishWheels(ctx, pub, wheels, t.TempDir(), nil)
	if calls != 1 {
		t.Errorf("%d reads reached the publisher, want 1", calls)
	}
	for i, r := range res {
		if r.State != Failed || r.Kind != KindInterrupted || r.Reason != "interrupted" {
			t.Errorf("wheel %d: %+v", i, r)
		}
	}
}
