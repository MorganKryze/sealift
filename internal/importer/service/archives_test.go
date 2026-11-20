package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/s3"
	"github.com/MorganKryze/sealift/internal/importer/token"
)

const base = "packages/npm/"

// minioRig is a service for alice over the given fake; the token "t" names her.
func minioRig(t *testing.T, f *fakeMinio, links ...string) rig {
	t.Helper()
	var objs Objects
	if f != nil {
		objs = f
	}
	return newRigConfig(t, Config{
		Verifier:         fakeVerifier{claims: map[string]token.Claims{"t": named("alice"), "b": named("bob")}},
		MinIO:            objs,
		UnencryptedLinks: links,
	})
}

func listOf(t *testing.T, rec *httptest.ResponseRecorder) ArchiveList {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var l ArchiveList
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return l
}

func byKey(l ArchiveList) map[string]Archive {
	m := map[string]Archive{}
	for _, a := range l.Archives {
		m[a.Key] = a
	}
	return m
}

func reasonOf(a Archive) string {
	if a.Reason == nil {
		return ""
	}
	return *a.Reason
}

func TestListArchivesWithoutMinIO(t *testing.T) {
	r := minioRig(t, nil)
	l := listOf(t, r.get("/api/archives", "t"))
	if l.MinioConfigured || len(l.Archives) != 0 || l.Bucket != "user-alice" || l.Folder != base {
		t.Errorf("got %+v", l)
	}
	if !strings.Contains(r.get("/api/archives", "t").Body.String(), `"archives":[]`) {
		t.Error("archives must be an empty array, not null")
	}
}

func TestMeSaysWhetherMinIOIsConfigured(t *testing.T) {
	for name, f := range map[string]*fakeMinio{"configured": newFakeMinio(), "absent": nil} {
		t.Run(name, func(t *testing.T) {
			rec := minioRig(t, f).get("/api/me", "t")
			var me Me
			if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || me.MinioConfigured != (f != nil) {
				t.Fatalf("body %q: %+v, %v", rec.Body, me, err)
			}
		})
	}
}

func TestMeNamesTheTrustedKey(t *testing.T) {
	want := archive.PublicKeySHA256(testPub)
	r := newRigConfig(t, Config{
		Verifier: fakeVerifier{claims: map[string]token.Claims{"t": named("alice")}},
		Settings: importer.Settings{PublicKey: testPub, PublicKeySHA256: want},
	})
	rec := r.get("/api/me", "t")
	var me Me
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %q: %v", rec.Code, rec.Body, err)
	}
	if me.PublicKeySha256 != want {
		t.Errorf("publicKeySha256 = %q, want %q", me.PublicKeySha256, want)
	}
}

func TestListArchives(t *testing.T) {
	f := newFakeMinio()
	f.put("user-alice", base+"export.tar.gz", 2048)
	f.put("user-alice", base+"manifest.json", 10)
	f.put("user-alice", base+"manifest.json.sig", 300)
	r := minioRig(t, f)
	l := listOf(t, r.get("/api/archives", "t"))
	if !l.MinioConfigured || l.BucketMissing || l.Truncated || l.Bucket != "user-alice" || l.Folder != base {
		t.Errorf("got %+v", l)
	}
	if len(l.Archives) != 1 {
		t.Fatalf("archives = %+v", l.Archives)
	}
	a := l.Archives[0]
	if a.Key != base+"export.tar.gz" || a.Size != 2048 || !a.Modified.Equal(epoch) || !a.Importable || a.Reason != nil {
		t.Errorf("got %+v", a)
	}
	for _, c := range f.recorded() {
		if c.Op != "list" && (c.Op != "get" || c.Key != base+"manifest.json") {
			t.Errorf("a list called %s on %q: a list reads the listing and manifests only", c.Op, c.Key)
		}
	}
}

func TestListPairsByFolder(t *testing.T) {
	f := newFakeMinio()
	b := "user-alice"
	f.put(b, base+"root.tar.gz", 1)
	f.put(b, base+"manifest.json", 1)
	f.put(b, base+"manifest.json.sig", 1)
	f.put(b, base+"sub/own.tar.gz", 1)
	f.put(b, base+"sub/manifest.json", 1)
	f.put(b, base+"sub/manifest.json.sig", 1)
	f.put(b, base+"two/a.tar.gz", 1)
	f.put(b, base+"two/b.tar.gz", 1)
	f.put(b, base+"two/manifest.json", 1)
	f.put(b, base+"two/manifest.json.sig", 1)
	f.put(b, base+"bare/lonely.tar.gz", 1)
	f.put(b, base+"deep/er/down.tar.gz", 1)
	f.put(b, base+"deep/er/manifest.json", 1)
	f.put(b, base+"deep/er/manifest.json.sig", 1)
	f.put(b, base+"sub/.keep", 0)
	f.put(b, base+".keep", 0)
	got := byKey(listOf(t, minioRig(t, f).get("/api/archives", "t")))

	want := map[string]struct {
		ok     bool
		reason string
	}{
		base + "root.tar.gz":        {true, ""},
		base + "sub/own.tar.gz":     {true, ""},
		base + "two/a.tar.gz":       {false, "the folder holds more than one archive"},
		base + "two/b.tar.gz":       {false, "the folder holds more than one archive"},
		base + "bare/lonely.tar.gz": {false, "no manifest.json in its folder"},
	}
	if len(got) != len(want) {
		t.Errorf("listed %d archives, want %d: %+v", len(got), len(want), got)
	}
	for key, w := range want {
		a, ok := got[key]
		if !ok {
			t.Errorf("%s is not listed", key)
			continue
		}
		if a.Importable != w.ok || reasonOf(a) != w.reason {
			t.Errorf("%s: importable %v reason %q, want %v %q", key, a.Importable, reasonOf(a), w.ok, w.reason)
		}
	}
}

func TestListNeedsTheSignature(t *testing.T) {
	const noSignature = "no manifest.json.sig in its folder"
	f := newFakeMinio()
	b := "user-alice"
	// Each folder holds one archive and lacks one thing.
	f.put(b, base+"unsigned/a.tar.gz", 1)
	f.put(b, base+"unsigned/manifest.json", 1)
	f.put(b, base+"signed/a.tar.gz", 1)
	f.put(b, base+"signed/manifest.json", 1)
	f.put(b, base+"signed/manifest.json.sig", 1)
	// The signature of another folder does not count, nor does a lookalike.
	f.put(b, base+"elsewhere/a.tar.gz", 1)
	f.put(b, base+"elsewhere/manifest.json", 1)
	f.put(b, base+"signed/elsewhere.sig", 1)
	f.put(b, base+"lookalike/a.tar.gz", 1)
	f.put(b, base+"lookalike/manifest.json", 1)
	f.put(b, base+"lookalike/manifest.json.sig.bak", 1)
	f.put(b, base+"lookalike/Manifest.json.sig", 1)
	// The reasons that come before it keep their place.
	f.put(b, base+"neither/a.tar.gz", 1)
	f.put(b, base+"several/a.tar.gz", 1)
	f.put(b, base+"several/b.tar.gz", 1)
	f.put(b, base+"several/manifest.json", 1)
	f.put(b, base+"bad//name.tar.gz", 1)
	f.put(b, base+"bad/manifest.json", 1)
	f.put(b, base+"sigonly/a.tar.gz", 1)
	f.put(b, base+"sigonly/manifest.json.sig", 1)
	got := byKey(listOf(t, minioRig(t, f).get("/api/archives", "t")))

	want := map[string]string{
		base + "unsigned/a.tar.gz":  noSignature,
		base + "signed/a.tar.gz":    "",
		base + "elsewhere/a.tar.gz": noSignature,
		base + "lookalike/a.tar.gz": noSignature,
		base + "neither/a.tar.gz":   "no manifest.json in its folder",
		base + "several/a.tar.gz":   "the folder holds more than one archive",
		base + "several/b.tar.gz":   "the folder holds more than one archive",
		base + "bad//name.tar.gz":   "its name cannot be imported",
		base + "sigonly/a.tar.gz":   "no manifest.json in its folder",
	}
	for key, reason := range want {
		a, ok := got[key]
		if !ok {
			t.Errorf("%s is not listed", key)
			continue
		}
		if a.Importable != (reason == "") || reasonOf(a) != reason {
			t.Errorf("%s: importable %v reason %q, want reason %q", key, a.Importable, reasonOf(a), reason)
		}
	}
}

func TestArchiveKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string // a fragment of the reason; "" means accepted
	}{
		{"root archive", base + "a.tar.gz", ""},
		{"one folder down", base + "d/a.tar.gz", ""},
		{"outside the folder", "other/a.tar.gz", "start with packages/npm/"},
		{"another prefix", "packages/pypi/a.tar.gz", "start with packages/npm/"},
		{"leading slash", "/" + base + "a.tar.gz", "start with packages/npm/"},
		{"wrong suffix", base + "a.zip", ".tar.gz"},
		{"two folders down", base + "d/e/a.tar.gz", "one folder"},
		{"empty segment", base + "d//a.tar.gz", "empty"},
		{"empty name", base + ".tar.gz", ""},
		{"dot segment", base + "./a.tar.gz", "."},
		{"dot dot segment", base + "../a.tar.gz", ".."},
		{"dot dot folder", base + "../../a.tar.gz", ".."},
		{"control character", base + "a\x00b.tar.gz", "control"},
		{"newline", base + "a\nb.tar.gz", "control"},
		{"not UTF-8", base + "a\xffb.tar.gz", "UTF-8"},
		{"over 1024 bytes", base + strings.Repeat("a", 1024) + ".tar.gz", "1024"},
		{"encoded dot dot", base + "%2e%2e/a.tar.gz", ".."},
		{"encoded dot dot in capitals", base + "%2E%2E/a.tar.gz", ".."},
		{"double dots hidden in an encoded slash", base + "a%2f..%2fb.tar.gz", ".."},
		{"encoded slash into a third folder", base + "a%2fb%2fc.tar.gz", "one folder"},
		{"a percent sign in a name", base + "100%.tar.gz", ""},
		{"an escape that does not decode", base + "%zz/a.tar.gz", ""},
		{"exactly 1024 bytes", base + strings.Repeat("a", 1024-len(base)-len(".tar.gz")) + ".tar.gz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ArchiveKey(tt.key)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("ArchiveKey = %v, want nil", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("ArchiveKey = %v, want a reason containing %q", err, tt.want)
			}
			if err != nil && utf8.RuneCountInString(err.Error()) > 300 {
				t.Errorf("the reason is %d characters, want at most 300", utf8.RuneCountInString(err.Error()))
			}
			if err != nil && strings.ContainsAny(err.Error(), "\x00\n") {
				t.Errorf("the reason repeats a control character: %q", err)
			}
		})
	}
}

func TestListMarksNamesItCannotImport(t *testing.T) {
	f := newFakeMinio()
	f.put("user-alice", base+"d//a.tar.gz", 1)
	f.put("user-alice", base+"d/manifest.json", 1)
	f.put("user-alice", base+"d/manifest.json.sig", 1)
	f.put("user-alice", base+"x\x07y.tar.gz", 1)
	f.put("user-alice", base+"manifest.json", 1)
	f.put("user-alice", base+"manifest.json.sig", 1)
	l := listOf(t, minioRig(t, f).get("/api/archives", "t"))
	if len(l.Archives) != 2 {
		t.Fatalf("archives = %+v", l.Archives)
	}
	for _, a := range l.Archives {
		if a.Importable || reasonOf(a) != "its name cannot be imported" {
			t.Errorf("%q: importable %v reason %q", a.Key, a.Importable, reasonOf(a))
		}
		if strings.ContainsRune(a.Key, '\x07') {
			t.Errorf("the key %q keeps a control character", a.Key)
		}
	}
}

func TestListStaysInTheUsersFolder(t *testing.T) {
	f := newFakeMinio()
	f.put("user-alice", base+"mine.tar.gz", 1)
	f.put("user-alice", base+"manifest.json", 1)
	f.put("user-alice", base+"manifest.json.sig", 1)
	f.put("user-alice", "elsewhere/other.tar.gz", 1)
	f.put("user-bob", base+"his.tar.gz", 1)
	f.put("user-bob", base+"manifest.json", 1)
	f.put("user-bob", base+"manifest.json.sig", 1)
	r := minioRig(t, f)

	// A query parameter or a header must not move the bucket.
	rec := r.get("/api/archives?bucket=user-bob&user=bob&prefix=elsewhere/", "t", "X-Auth-Request-Preferred-Username", "bob")
	l := listOf(t, rec)
	if l.Bucket != "user-alice" || len(l.Archives) != 1 || l.Archives[0].Key != base+"mine.tar.gz" {
		t.Errorf("got %+v", l)
	}
	if strings.Contains(rec.Body.String(), "his.tar.gz") || strings.Contains(rec.Body.String(), "other.tar.gz") {
		t.Errorf("the answer shows what alice does not own: %s", rec.Body)
	}
	calls := f.recorded()
	if len(calls) != 3 || calls[0].Op != "list" || calls[0].Prefix != base || calls[1].Op != "list" || calls[1].Prefix != "packages/pip/" {
		t.Fatalf("calls = %+v, want a list of each folder and a read of alice's manifest", calls)
	}
	for _, c := range calls {
		if c.Bucket != "user-alice" || c.Op == "list" && c.Max != MaxListed || c.Op == "get" && c.Key != base+"manifest.json" {
			t.Errorf("call %+v", c)
		}
	}

	f.calls = nil
	if l := listOf(t, r.get("/api/archives", "b")); l.Bucket != "user-bob" || len(l.Archives) != 1 || l.Archives[0].Key != base+"his.tar.gz" {
		t.Errorf("bob got %+v", l)
	}
	for _, c := range f.recorded() {
		if c.Bucket != "user-bob" {
			t.Errorf("bob's call touched %s", c.Bucket)
		}
	}
}

func TestListRefusedTokenCallsNoMinIO(t *testing.T) {
	f := newFakeMinio()
	rec := minioRig(t, f).get("/api/archives", "forged")
	if rec.Code != http.StatusUnauthorized || len(f.recorded()) != 0 {
		t.Errorf("status %d, %d MinIO calls", rec.Code, len(f.recorded()))
	}
}

func TestListNoBucket(t *testing.T) {
	f := newFakeMinio()
	l := listOf(t, minioRig(t, f).get("/api/archives", "t"))
	if !l.BucketMissing || len(l.Archives) != 0 || l.Message == nil || !strings.Contains(*l.Message, "user-alice") {
		t.Errorf("got %+v", l)
	}
}

func TestListMinIOFailure502(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"unreachable", errors.New("dial tcp 10.0.0.9:9000: connect: connection refused"), "connection refused"},
		{"forbidden", &s3.Error{Status: 403, Code: "AccessDenied", Message: "Access Denied."}, "AccessDenied"},
		{"long text with control characters", &s3.Error{Status: 500, Code: "InternalError", Message: "boom\x00\n" + strings.Repeat("x", 600)}, "InternalError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeMinio()
			f.failWith = tt.err
			r := minioRig(t, f)
			rec := r.get("/api/archives", "t")
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", rec.Code)
			}
			d := detailOf(problemOf(t, rec))
			if !strings.Contains(d, tt.want) {
				t.Errorf("detail %q does not contain %q", d, tt.want)
			}
			if utf8.RuneCountInString(d) > 300 || strings.ContainsAny(d, "\x00\n") {
				t.Errorf("detail is %d characters or holds a control character: %q", utf8.RuneCountInString(d), d)
			}
			if strings.Contains(r.logs.String(), "test-minio-secret") || strings.Contains(d, "test-minio-secret") {
				t.Error("a secret reached the log or the answer")
			}
		})
	}
}

func TestListSaysWhenTruncated(t *testing.T) {
	f := newFakeMinio()
	for i := 0; i < MaxListed+1; i++ {
		f.put("user-alice", base+"d"+strings.Repeat("0", 5)+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676))+"/x.tar.gz", 1)
	}
	r := minioRig(t, f)
	l := listOf(t, r.get("/api/archives", "t"))
	if !l.Truncated {
		t.Error("Truncated = false with more objects than MaxListed")
	}
	if c := f.recorded(); len(c) != 2 || c[0].Max != MaxListed || c[1].Max != MaxListed {
		t.Errorf("calls = %+v, want one list of %d per folder", c, MaxListed)
	}

	small := newFakeMinio()
	small.put("user-alice", base+"a.tar.gz", 1)
	if l := listOf(t, minioRig(t, small).get("/api/archives", "t")); l.Truncated {
		t.Error("Truncated = true for a short folder")
	}
}

func TestListMarksUnencrypted(t *testing.T) {
	f := newFakeMinio()
	f.put("user-alice", base+"a.tar.gz", 1)
	if l := listOf(t, minioRig(t, f, "minio", "keySet").get("/api/archives", "t")); strings.Join(l.Unencrypted, ",") != "minio,keySet" {
		t.Errorf("Unencrypted = %v", l.Unencrypted)
	}
	rec := minioRig(t, f).get("/api/archives", "t")
	if l := listOf(t, rec); l.Unencrypted == nil || len(l.Unencrypted) != 0 || !strings.Contains(rec.Body.String(), `"unencrypted":[]`) {
		t.Errorf("Unencrypted = %v, want an empty array", l.Unencrypted)
	}
}

func TestBadParameterAnswersAProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	badParameter(rec, httptest.NewRequest(http.MethodGet, "/api/archives?n=secret-value", nil), errors.New(`invalid value "secret-value"`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret-value") {
		t.Errorf("the answer repeats the input: %s", rec.Body)
	}
	problemOf(t, rec)
}

const pipBase = "packages/pip/"

var (
	npmManifest = []byte(`{"formatVersion": 2}`)
	pipManifest = []byte(`{"formatVersion": 3, "ecosystem": "pip"}`)
)

func TestArchiveKeyFolders(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string // a fragment of the reason; "" means accepted
	}{
		{"npm root archive", base + "a.tar.gz", ""},
		{"npm one folder down", base + "d/a.tar.gz", ""},
		{"pip root archive", pipBase + "a.tar.gz", ""},
		{"pip one folder down", pipBase + "d/a.tar.gz", ""},
		{"another folder of packages", "packages/other/x.tar.gz", "start with packages/npm/ or packages/pip/"},
		{"pip empty segment", pipBase + "/x.tar.gz", "empty"},
		{"pip two folders down", pipBase + "d/e/a.tar.gz", "one folder below packages/pip/"},
		{"pip key that decodes under npm", pipBase + "..%2fnpm%2fx.tar.gz", ".."},
		{"npm key that decodes under pip", base + "..%2Fpip%2Fx.tar.gz", ".."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ArchiveKey(tt.key)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("ArchiveKey = %v, want nil", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("ArchiveKey = %v, want a reason containing %q", err, tt.want)
			}
		})
	}
	for key, want := range map[string]archive.Ecosystem{base + "a.tar.gz": archive.NPM, pipBase + "d/a.tar.gz": archive.Pip, "packages/other/a.tar.gz": ""} {
		if got, ok := FolderOf(key); got != want || ok != (want != "") {
			t.Errorf("FolderOf(%q) = %q, %v; want %q", key, got, ok, want)
		}
	}
}

func ecosystemOf(a Archive) string {
	if a.Ecosystem == nil {
		return ""
	}
	return string(*a.Ecosystem)
}

func TestListsBothFolders(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		name := "per prefix"
		if ignore {
			name = "prefix ignored"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeMinio()
			f.ignorePrefix = ignore
			b := "user-alice"
			for _, k := range []string{base + "a/x.tar.gz", base + "a/manifest.json", base + "a/manifest.json.sig",
				pipBase + "b/y.tar.gz", pipBase + "b/manifest.json", pipBase + "b/manifest.json.sig",
				// The pip folder c lacks a signature; the npm folder c has one, which must not count.
				pipBase + "c/z.tar.gz", pipBase + "c/manifest.json", base + "c/manifest.json.sig",
				// Outside both folders, one folder down from the bucket's root.
				"packages/other/o.tar.gz", "stray/s.tar.gz", "stray/manifest.json", "stray/manifest.json.sig"} {
				f.put(b, k, 1)
			}
			l := listOf(t, minioRig(t, f).get("/api/archives", "t"))
			if l.Folder != base || l.Folders == nil || strings.Join(*l.Folders, ",") != base+","+pipBase {
				t.Errorf("folder %q, folders %v", l.Folder, l.Folders)
			}
			want := map[string][2]string{
				base + "a/x.tar.gz":    {"npm", ""},
				pipBase + "b/y.tar.gz": {"pip", ""},
				pipBase + "c/z.tar.gz": {"pip", "no manifest.json.sig in its folder"},
			}
			if len(l.Archives) != len(want) {
				t.Errorf("listed %d archives, want %d: %+v", len(l.Archives), len(want), l.Archives)
			}
			for key, a := range byKey(l) {
				w, ok := want[key]
				if !ok {
					t.Errorf("%s is listed", key)
					continue
				}
				if ecosystemOf(a) != w[0] || reasonOf(a) != w[1] || a.Importable != (w[1] == "") {
					t.Errorf("%s: ecosystem %q importable %v reason %q, want %q %q", key, ecosystemOf(a), a.Importable, reasonOf(a), w[0], w[1])
				}
			}
			var prefixes []string
			for _, c := range f.recorded() {
				if c.Op == "list" {
					prefixes = append(prefixes, c.Prefix)
					if c.Bucket != b || c.Max != MaxListed {
						t.Errorf("list call %+v", c)
					}
				}
			}
			if strings.Join(prefixes, ",") != base+","+pipBase {
				t.Errorf("listed prefixes %v, want npm then pip", prefixes)
			}
		})
	}
}

func TestListMarksAnArchiveInTheWrongFolder(t *testing.T) {
	const (
		npmHere = "its manifest is an npm archive's: keep the three files under packages/npm/"
		pipHere = "its manifest is a pip archive's: keep the three files under packages/pip/"
	)
	seed := func(f *fakeMinio, folder string, manifest []byte) {
		f.put(bucketAlice, folder+"x.tar.gz", 1)
		f.putData(folder+"manifest.json", manifest)
		f.put(bucketAlice, folder+"manifest.json.sig", 1)
	}
	t.Run("marks", func(t *testing.T) {
		f := newFakeMinio()
		seed(f, pipBase+"npm-inside/", npmManifest)
		seed(f, base+"pip-inside/", pipManifest)
		seed(f, pipBase+"right/", pipManifest)
		seed(f, base+"right/", npmManifest)
		seed(f, pipBase+"garbled/", []byte("not a manifest"))
		seed(f, pipBase+"unreadable/", npmManifest)
		f.readErr[dataKey(bucketAlice, pipBase+"unreadable/manifest.json")] = errors.New("connection reset")
		// Past archive.MaxManifestSize, 16 MiB: never read.
		f.put(bucketAlice, pipBase+"huge/x.tar.gz", 1)
		f.put(bucketAlice, pipBase+"huge/manifest.json", 16<<20+1)
		f.put(bucketAlice, pipBase+"huge/manifest.json.sig", 1)
		r := minioRig(t, f)
		want := map[string]string{
			pipBase + "npm-inside/x.tar.gz": npmHere,
			base + "pip-inside/x.tar.gz":    pipHere,
			pipBase + "right/x.tar.gz":      "",
			base + "right/x.tar.gz":         "",
			pipBase + "garbled/x.tar.gz":    "",
			pipBase + "unreadable/x.tar.gz": "",
			pipBase + "huge/x.tar.gz":       "",
		}
		for round := 1; round <= 2; round++ {
			got := byKey(listOf(t, r.get("/api/archives", "t")))
			for key, reason := range want {
				if a := got[key]; a.Importable != (reason == "") || reasonOf(a) != reason {
					t.Errorf("list %d, %s: importable %v reason %q, want %q", round, key, a.Importable, reasonOf(a), reason)
				}
			}
		}
		for _, folder := range []string{pipBase + "npm-inside/", base + "pip-inside/", pipBase + "right/", base + "right/", pipBase + "garbled/"} {
			if n := f.gets(folder + "manifest.json"); n != 1 {
				t.Errorf("%smanifest.json read %d times over two lists, want 1", folder, n)
			}
		}
		if n := f.gets(pipBase + "huge/manifest.json"); n != 0 {
			t.Errorf("a manifest over 16 MiB was read %d times", n)
		}
		for _, c := range f.recorded() {
			if c.Op == "get" && c.ETag == "" {
				t.Errorf("a manifest read without its listed ETag: %+v", c)
			}
		}
	})
	t.Run("at most 50 new manifests a list", func(t *testing.T) {
		f := newFakeMinio()
		for i := 0; i < 51; i++ {
			seed(f, pipBase+"f"+strings.Repeat("0", 2-len(strconv.Itoa(i)))+strconv.Itoa(i)+"/", npmManifest)
		}
		r := minioRig(t, f)
		count := func(l ArchiveList) (marked int, last Archive) {
			for _, a := range l.Archives {
				if reasonOf(a) == npmHere {
					marked++
				}
			}
			return marked, l.Archives[len(l.Archives)-1]
		}
		marked, last := count(listOf(t, r.get("/api/archives", "t")))
		if marked != 50 || !last.Importable || last.Key != pipBase+"f50/x.tar.gz" {
			t.Errorf("first list: %d marked, last %+v; want 50 marked and f50 left importable", marked, last)
		}
		if marked, _ := count(listOf(t, r.get("/api/archives", "t"))); marked != 51 {
			t.Errorf("second list: %d marked, want 51", marked)
		}
		gets := 0
		for _, c := range f.recorded() {
			if c.Op == "get" {
				gets++
			}
		}
		if gets != 51 {
			t.Errorf("%d manifest reads over two lists, want 51", gets)
		}
	})
}

func TestListMarksEachUsersOwnManifest(t *testing.T) {
	// The fake derives an ETag from the key, so both manifests share one,
	// as two objects may on a real MinIO.
	f := newFakeMinio()
	folder := pipBase + "x/"
	f.put(bucketAlice, folder+"x.tar.gz", 1)
	f.putData(folder+"manifest.json", npmManifest)
	f.put(bucketAlice, folder+"manifest.json.sig", 1)
	f.put("user-bob", folder+"x.tar.gz", 1)
	f.putDataIn("user-bob", folder+"manifest.json", pipManifest)
	f.put("user-bob", folder+"manifest.json.sig", 1)
	r := minioRig(t, f)
	if a := byKey(listOf(t, r.get("/api/archives", "t")))[folder+"x.tar.gz"]; a.Importable {
		t.Fatalf("alice's npm manifest under %s left the row importable", pipBase)
	}
	if a := byKey(listOf(t, r.get("/api/archives", "b")))[folder+"x.tar.gz"]; !a.Importable || reasonOf(a) != "" {
		t.Errorf("bob's pip archive: importable %v reason %q, want importable", a.Importable, reasonOf(a))
	}
	bobReads := 0
	for _, c := range f.recorded() {
		if c.Op == "get" && c.Bucket == "user-bob" {
			bobReads++
		}
	}
	if bobReads != 1 {
		t.Errorf("bob's list read %d of his manifests, want 1", bobReads)
	}
}

func TestMarkCacheHoldsAtMost4096(t *testing.T) {
	var h Handlers
	for i := 0; i < 4096; i++ {
		h.remember(strconv.Itoa(i), archive.NPM)
	}
	if eco, ok := h.recall("0"); !ok || eco != archive.NPM || len(h.marks) != 4096 {
		t.Fatalf("after 4096 marks: %q %v, %d kept", eco, ok, len(h.marks))
	}
	h.remember("one more", archive.Pip)
	if _, ok := h.recall("0"); ok || len(h.marks) != 1 {
		t.Errorf("the 4097th mark kept %d marks, want the cache emptied first", len(h.marks))
	}
	if eco, ok := h.recall("one more"); !ok || eco != archive.Pip {
		t.Errorf("the 4097th mark is %q %v", eco, ok)
	}
}

func TestListKeepsOneFolderWhenTheOtherFails(t *testing.T) {
	denied := &s3.Error{Status: 403, Code: "AccessDenied", Message: "Access Denied.\x00" + strings.Repeat("x", 600)}
	for _, tc := range []struct {
		failing, listed, listedKey string
	}{
		{pipBase, base, base + "a/x.tar.gz"},
		{base, pipBase, pipBase + "a/x.tar.gz"},
	} {
		t.Run(tc.failing, func(t *testing.T) {
			f := newFakeMinio()
			for _, k := range []string{base + "a/x.tar.gz", pipBase + "a/x.tar.gz"} {
				f.put(bucketAlice, k, 1)
			}
			f.failList[tc.failing] = denied
			r := minioRig(t, f)
			l := listOf(t, r.get("/api/archives", "t"))
			if len(l.Archives) != 1 || l.Archives[0].Key != tc.listedKey {
				t.Errorf("archives %+v, want %s alone", l.Archives, tc.listedKey)
			}
			if l.Message == nil || !strings.HasPrefix(*l.Message, "MinIO could not list "+tc.failing+": ") || !strings.Contains(*l.Message, "AccessDenied") {
				t.Fatalf("message %v, want one that names %s and MinIO's reason", l.Message, tc.failing)
			}
			if utf8.RuneCountInString(*l.Message) > 300 || strings.ContainsRune(*l.Message, 0) {
				t.Errorf("message is %d characters or holds a control character", utf8.RuneCountInString(*l.Message))
			}
			if l.BucketMissing {
				t.Error("bucketMissing set for a folder that failed")
			}
		})
	}
	t.Run("both", func(t *testing.T) {
		f := newFakeMinio()
		f.put(bucketAlice, base+"a/x.tar.gz", 1)
		f.failList[base], f.failList[pipBase] = denied, denied
		rec := minioRig(t, f).get("/api/archives", "t")
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", rec.Code)
		}
		if d := detailOf(problemOf(t, rec)); !strings.Contains(d, "AccessDenied") {
			t.Errorf("detail %q", d)
		}
	})
}
