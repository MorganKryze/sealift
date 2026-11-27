package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
	r := keyRig(t, f)

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
	if len(calls) != 4 || calls[0].Op != "list" || calls[0].Prefix != base || calls[1].Op != "list" || calls[1].Prefix != "packages/pip/" {
		t.Fatalf("calls = %+v, want a list of each folder and a read of alice's manifest and signature", calls)
	}
	for _, c := range calls {
		if c.Bucket != "user-alice" || c.Op == "list" && c.Max != MaxListed || c.Op == "get" && c.Key != base+"manifest.json" && c.Key != base+"manifest.json.sig" {
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
		{"pip folder with an encoded slash", "packages/pip%2Fx.tar.gz", "start with packages/npm/ or packages/pip/"},
		{"npm folder with an encoded slash", "packages%2Fnpm/x.tar.gz", "start with packages/npm/ or packages/pip/"},
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

const (
	reasonWrongNPM = "its manifest is an npm archive's: keep the three files under packages/npm/"
	reasonWrongPip = "its manifest is a pip archive's: keep the three files under packages/pip/"
	sealedAt       = "2026-11-25T09:00:00Z"
)

var otherPub, otherPriv = func() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}()

// keyRig is a service for alice and bob over objects that trusts testPub.
func keyRig(t *testing.T, objs Objects) rig {
	t.Helper()
	return newRigConfig(t, Config{
		Verifier: fakeVerifier{claims: map[string]token.Claims{"t": named("alice"), "b": named("bob")}},
		MinIO:    objs,
		Settings: importer.Settings{PublicKey: testPub, PublicKeySHA256: archive.PublicKeySHA256(testPub)},
	})
}

// manifestOf is an npm manifest of n packages for an archive of 2048 bytes,
// with a review that names project when project is not empty.
func manifestOf(t *testing.T, project string, n int) []byte {
	t.Helper()
	pkgs := make([]map[string]any, n)
	for i := range pkgs {
		name := "pkg-" + strconv.Itoa(i)
		sum := sha512.Sum512([]byte(name))
		pkgs[i] = map[string]any{
			"name": name, "version": "1.0.0", "file": name + "-1.0.0.tgz",
			"originalIntegrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
			"shippedSha512":     hex.EncodeToString(sum[:]), "publishConfigStripped": false,
		}
	}
	doc := map[string]any{
		"formatVersion": 2, "toolVersion": "0.8.0", "analysisId": "20261125T085500Z", "createdAt": sealedAt,
		"target":   map[string]any{"os": "linux", "cpu": "x64", "libc": "glibc", "node": "22.17.1", "pnpmVer": "10.34.5"},
		"archive":  map[string]any{"sha256": strings.Repeat("ab", 32), "size": 2048},
		"packages": pkgs,
	}
	if project != "" {
		doc["review"] = map[string]any{"project": project, "cves": map[string]any{"before": []int{0, 1, 0, 0, 0}}}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seedFolder puts an archive of size bytes and manifest in folder, with
// sig as manifest.json.sig when it is not nil.
func seedFolder(f *fakeMinio, bucket, folder string, size int64, manifest, sig []byte) {
	f.put(bucket, folder+"x.tar.gz", size)
	f.putDataIn(bucket, folder+manifestName, manifest)
	if sig != nil {
		f.putDataIn(bucket, folder+signatureName, sig)
	}
}

// sigNaming is a signature file of manifest made by priv that names the key
// sha256 named.
func sigNaming(t *testing.T, priv ed25519.PrivateKey, manifest []byte, named string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"algorithm": "ed25519", "publicKeySha256": named, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signatureOf(a Archive) ArchiveSignature {
	if a.Signature == nil {
		return ""
	}
	return *a.Signature
}

func TestListChecksASignatureOncePerManifestAndSignatureAsStored(t *testing.T) {
	f := newFakeMinio()
	folder := base + "web-portal/"
	m := manifestOf(t, "web-portal", 3)
	seedFolder(f, bucketAlice, folder, 2048, m, signManifest(t, testPriv, m))
	r := keyRig(t, f)
	for round := 1; round <= 3; round++ {
		a := byKey(listOf(t, r.get("/api/archives", "t")))[folder+"x.tar.gz"]
		if signatureOf(a) != ArchiveSignatureVerified || !a.Importable {
			t.Fatalf("list %d: signature %q importable %v reason %q, want verified", round, signatureOf(a), a.Importable, reasonOf(a))
		}
	}
	if n, s := f.gets(folder+manifestName), f.gets(folder+signatureName); n != 1 || s != 1 {
		t.Errorf("three lists read the manifest %d times and the signature %d times, want once each", n, s)
	}
	for _, c := range f.recorded() {
		if c.Op == "get" && c.ETag != f.etagOf(c.Key) {
			t.Errorf("a read without the listed ETag: %+v", c)
		}
	}
	f.change(folder + manifestName)
	listOf(t, r.get("/api/archives", "t"))
	if n := f.gets(folder + manifestName); n != 2 {
		t.Errorf("a replaced manifest was read %d times in all, want 2", n)
	}
}

func TestListReadsAManifestAgainOnceItsSignatureChanges(t *testing.T) {
	f := newFakeMinio()
	folder := base + "web-portal/"
	m := manifestOf(t, "web-portal", 3)
	seedFolder(f, bucketAlice, folder, 2048, m, signManifest(t, testPriv, m))
	r := keyRig(t, f)
	listOf(t, r.get("/api/archives", "t"))
	// Another key signs the same manifest: only the signature file changes.
	f.putData(folder+signatureName, signManifest(t, otherPriv, m))
	f.change(folder + signatureName)
	a := byKey(listOf(t, r.get("/api/archives", "t")))[folder+"x.tar.gz"]
	if n := f.gets(folder + manifestName); n != 2 {
		t.Errorf("the manifest was read %d times, want again once its signature changed", n)
	}
	if signatureOf(a) != ArchiveSignatureUnknownKey || a.Importable || a.Crossing != nil {
		t.Errorf("signature %q importable %v crossing %+v, want the new signature's refusal", signatureOf(a), a.Importable, a.Crossing)
	}
}

func TestListNeverAnswersOneBucketFromAnothersCache(t *testing.T) {
	// The fake derives an ETag from the key, so both users' files share
	// their ETags, as two objects may on a real MinIO.
	f := newFakeMinio()
	folder := base + "x/"
	mine := manifestOf(t, "alice-app", 2)
	seedFolder(f, bucketAlice, folder, 2048, mine, signManifest(t, testPriv, mine))
	theirs := manifestOf(t, "bob-app", 2)
	seedFolder(f, "user-bob", folder, 2048, theirs, signManifest(t, otherPriv, theirs))
	r := keyRig(t, f)
	if a := byKey(listOf(t, r.get("/api/archives", "t")))[folder+"x.tar.gz"]; signatureOf(a) != ArchiveSignatureVerified {
		t.Fatalf("alice's archive: signature %q, want verified", signatureOf(a))
	}
	b := byKey(listOf(t, r.get("/api/archives", "b")))[folder+"x.tar.gz"]
	if signatureOf(b) != ArchiveSignatureUnknownKey || b.Importable || b.Crossing != nil {
		t.Errorf("bob's archive: signature %q importable %v crossing %+v, want his own refusal", signatureOf(b), b.Importable, b.Crossing)
	}
	bobReads := 0
	for _, c := range f.recorded() {
		if c.Op == "get" && c.Bucket == "user-bob" {
			bobReads++
		}
	}
	if bobReads != 2 {
		t.Errorf("bob's list read %d of his files, want his manifest and his signature", bobReads)
	}
}

func TestListVerifiesASignatureBeforeNamingTheCrossing(t *testing.T) {
	f := newFakeMinio()
	trusted := archive.PublicKeySHA256(testPub)
	signed := manifestOf(t, "web-portal", 3)
	seedFolder(f, bucketAlice, base+"signed/", 2048, signed, signManifest(t, testPriv, signed))
	old := manifestOf(t, "", 2)
	seedFolder(f, bucketAlice, base+"old/", 2048, old, signManifest(t, testPriv, old))
	forged := manifestOf(t, "forged-name", 3)
	// Another key signs it, and the file names the trusted key.
	seedFolder(f, bucketAlice, base+"forged/", 2048, forged, sigNaming(t, otherPriv, forged, trusted))
	foreign := manifestOf(t, "foreign-name", 3)
	seedFolder(f, bucketAlice, base+"foreign/", 2048, foreign, signManifest(t, otherPriv, foreign))
	got := byKey(listOf(t, keyRig(t, f).get("/api/archives", "t")))

	a := got[base+"signed/x.tar.gz"]
	if a.Crossing == nil || a.Crossing.Project == nil || *a.Crossing.Project != "web-portal" || a.Crossing.SealedAt != sealedAt || a.Crossing.Packages != 3 {
		t.Errorf("a verified archive's crossing %+v, want web-portal sealed %s with 3 packages", a.Crossing, sealedAt)
	}
	if a.DeclaredSize == nil || *a.DeclaredSize != 2048 || a.Crossing != nil && a.Crossing.Review != nil {
		t.Errorf("a verified archive's declared size %v, crossing review %+v", a.DeclaredSize, a.Crossing)
	}
	if o := got[base+"old/x.tar.gz"]; o.Crossing == nil || o.Crossing.Project != nil || signatureOf(o) != ArchiveSignatureVerified {
		t.Errorf("a verified manifest with no review: crossing %+v, signature %q; want a crossing with no project", o.Crossing, signatureOf(o))
	}
	for _, key := range []string{base + "forged/x.tar.gz", base + "foreign/x.tar.gz"} {
		if a := got[key]; a.Crossing != nil || a.DeclaredSize != nil || a.Importable {
			t.Errorf("%s: crossing %+v, declared size %v, importable %v; an unverified manifest names nothing", key, a.Crossing, a.DeclaredSize, a.Importable)
		}
	}
}

func TestListRefusesEachKindWithItsWords(t *testing.T) {
	f := newFakeMinio()
	good := manifestOf(t, "web-portal", 3)
	seedFolder(f, bucketAlice, base+"unsigned/", 2048, good, nil)
	seedFolder(f, bucketAlice, base+"unknown-key/", 2048, good, signManifest(t, otherPriv, good))
	seedFolder(f, bucketAlice, base+"mismatch/", 2048, good, sigNaming(t, otherPriv, good, archive.PublicKeySHA256(testPub)))
	garbled := []byte(`{"formatVersion": 2, "packages": "none"}`)
	seedFolder(f, bucketAlice, base+"garbled/", 2048, garbled, signManifest(t, testPriv, garbled))
	seedFolder(f, bucketAlice, base+"bad-signature/", 2048, good, []byte(`{"algorithm": "rsa"}`))
	seedFolder(f, bucketAlice, base+"pip-inside/", 2048, pipManifest, signManifest(t, testPriv, pipManifest))
	seedFolder(f, bucketAlice, pipBase+"npm-inside/", 2048, good, signManifest(t, testPriv, good))
	seedFolder(f, bucketAlice, base+"size-differs/", 2049, good, signManifest(t, testPriv, good))
	// Past archive.MaxManifestSize, 16 MiB: refused unread.
	f.put(bucketAlice, base+"huge/x.tar.gz", 2048)
	f.put(bucketAlice, base+"huge/manifest.json", 16<<20+1)
	f.putData(base+"huge/manifest.json.sig", signManifest(t, testPriv, good))
	want := map[string]struct {
		signature ArchiveSignature
		reason    string
	}{
		base + "unsigned/x.tar.gz":      {ArchiveSignatureUnsigned, "no manifest.json.sig in its folder"},
		base + "unknown-key/x.tar.gz":   {ArchiveSignatureUnknownKey, "signed with a key this side does not trust"},
		base + "mismatch/x.tar.gz":      {ArchiveSignatureMismatch, "its signature does not match its manifest"},
		base + "garbled/x.tar.gz":       {ArchiveSignatureVerified, "its manifest cannot be read"},
		base + "huge/x.tar.gz":          {ArchiveSignatureUnreadable, "its manifest cannot be read"},
		base + "bad-signature/x.tar.gz": {ArchiveSignatureUnreadable, "its manifest.json.sig cannot be read"},
		base + "pip-inside/x.tar.gz":    {ArchiveSignatureVerified, reasonWrongPip},
		pipBase + "npm-inside/x.tar.gz": {ArchiveSignatureVerified, reasonWrongNPM},
		base + "size-differs/x.tar.gz":  {ArchiveSignatureVerified, "the archive does not match its manifest"},
	}
	r := keyRig(t, f)
	for round := 1; round <= 2; round++ {
		got := byKey(listOf(t, r.get("/api/archives", "t")))
		for key, w := range want {
			a := got[key]
			if a.Importable || reasonOf(a) != w.reason || signatureOf(a) != w.signature {
				t.Errorf("list %d, %s: importable %v signature %q reason %q, want %q %q", round, key, a.Importable, signatureOf(a), reasonOf(a), w.signature, w.reason)
			}
		}
		if a := got[base+"size-differs/x.tar.gz"]; a.DeclaredSize == nil || *a.DeclaredSize != 2048 || a.Crossing == nil {
			t.Errorf("an archive whose size differs: declared %v crossing %+v, want both from its verified manifest", a.DeclaredSize, a.Crossing)
		}
	}
	if n := f.gets(base + "huge/manifest.json"); n != 0 {
		t.Errorf("a manifest over 16 MiB was read %d times", n)
	}
}

func TestListNamesAnUnknownKeyOnlyWhenItsFingerprintIs64Hex(t *testing.T) {
	other := archive.PublicKeySHA256(otherPub)
	f := newFakeMinio()
	m := manifestOf(t, "web-portal", 1)
	named := map[string]string{"hex": other, "short": other[:63], "upper": strings.ToUpper(other), "control": other[:63] + "\x1b"}
	for folder, key := range named {
		seedFolder(f, bucketAlice, base+folder+"/", 2048, m, sigNaming(t, otherPriv, m, key))
	}
	got := byKey(listOf(t, keyRig(t, f).get("/api/archives", "t")))
	for folder := range named {
		a := got[base+folder+"/x.tar.gz"]
		if folder == "hex" {
			if a.SignerKeySha256 == nil || *a.SignerKeySha256 != other || signatureOf(a) != ArchiveSignatureUnknownKey {
				t.Errorf("%s: signer %v signature %q, want %s", folder, a.SignerKeySha256, signatureOf(a), other)
			}
			continue
		}
		if a.SignerKeySha256 != nil || signatureOf(a) != ArchiveSignatureUnreadable || a.Importable {
			t.Errorf("%s: signer %v signature %q importable %v, want no signer and an unreadable signature", folder, a.SignerKeySha256, signatureOf(a), a.Importable)
		}
	}
}

func TestListListsEachFilesSizeAndUploadTime(t *testing.T) {
	f := newFakeMinio()
	folder := base + "web-portal/"
	m := manifestOf(t, "web-portal", 1)
	sig := signManifest(t, testPriv, m)
	seedFolder(f, bucketAlice, folder, 2048, m, sig)
	times := map[string]time.Time{"x.tar.gz": epoch, manifestName: epoch.Add(time.Minute), signatureName: epoch.Add(2 * time.Minute)}
	for name, at := range times {
		o := f.buckets[bucketAlice][folder+name]
		o.LastModified = at
		f.buckets[bucketAlice][folder+name] = o
	}
	a := byKey(listOf(t, keyRig(t, f).get("/api/archives", "t")))[folder+"x.tar.gz"]
	if a.Files == nil || len(*a.Files) != 3 {
		t.Fatalf("files %v, want the archive, its manifest and its signature", a.Files)
	}
	want := []ArchiveFile{{Name: "x.tar.gz", Size: 2048, Modified: epoch}, {Name: manifestName, Size: int64(len(m)), Modified: epoch.Add(time.Minute)}, {Name: signatureName, Size: int64(len(sig)), Modified: epoch.Add(2 * time.Minute)}}
	for i, w := range want {
		if g := (*a.Files)[i]; g.Name != w.Name || g.Size != w.Size || !g.Modified.Equal(w.Modified) {
			t.Errorf("file %d: %+v, want %+v", i, g, w)
		}
	}
	unsigned := newFakeMinio()
	seedFolder(unsigned, bucketAlice, folder, 2048, m, nil)
	if a := byKey(listOf(t, keyRig(t, unsigned).get("/api/archives", "t")))[folder+"x.tar.gz"]; a.Files == nil || len(*a.Files) != 2 {
		t.Errorf("an unsigned folder lists files %v, want the archive and its manifest", a.Files)
	}
}

// countingMinio counts the reads it opens and the bytes they serve.
type countingMinio struct {
	*fakeMinio
	mu     sync.Mutex
	reads  int
	served int64
}

func (c *countingMinio) Get(ctx context.Context, bucket, key, etag string) (io.ReadCloser, s3.Object, error) {
	body, o, err := c.fakeMinio.Get(ctx, bucket, key, etag)
	if err != nil {
		return nil, o, err
	}
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return countedBody{body, c}, o, nil
}

type countedBody struct {
	io.ReadCloser
	c *countingMinio
}

func (b countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.c.mu.Lock()
	b.c.served += int64(n)
	b.c.mu.Unlock()
	return n, err
}

func TestListReadsAtMost50ManifestsAnd64MiBInOneList(t *testing.T) {
	folderAt := func(i int) string { return base + "f" + strconv.Itoa(100+i) + "/" }
	t.Run("60 manifests of 4 MiB", func(t *testing.T) {
		c := &countingMinio{fakeMinio: newFakeMinio()}
		for i := 0; i < 60; i++ {
			c.put(bucketAlice, folderAt(i)+"x.tar.gz", 2048)
			c.put(bucketAlice, folderAt(i)+manifestName, 4<<20)
			c.put(bucketAlice, folderAt(i)+signatureName, 200)
		}
		r := keyRig(t, c)
		l := listOf(t, r.get("/api/archives", "t"))
		if c.served > 64<<20 {
			t.Errorf("one list read %d bytes, want at most 64 MiB", c.served)
		}
		if c.reads > 2*50 {
			t.Errorf("one list opened %d reads, want at most 50 manifests and their signatures", c.reads)
		}
		notChecked := 0
		for _, a := range l.Archives {
			if signatureOf(a) == ArchiveSignatureNotChecked {
				notChecked++
				if !a.Importable || a.Crossing != nil {
					t.Errorf("%s: not checked, yet importable %v crossing %+v", a.Key, a.Importable, a.Crossing)
				}
			}
		}
		if notChecked == 0 || notChecked == 60 {
			t.Errorf("%d of 60 archives not checked, want those past the bound only", notChecked)
		}
		before := c.served
		listOf(t, r.get("/api/archives", "t"))
		if c.served-before > 64<<20 || c.served == before {
			t.Errorf("the second list read %d bytes, want the next ones within 64 MiB", c.served-before)
		}
	})
	t.Run("60 small manifests", func(t *testing.T) {
		c := &countingMinio{fakeMinio: newFakeMinio()}
		for i := 0; i < 60; i++ {
			m := manifestOf(t, "p"+strconv.Itoa(i), 1)
			seedFolder(c.fakeMinio, bucketAlice, folderAt(i), 2048, m, signManifest(t, testPriv, m))
		}
		r := keyRig(t, c)
		count := func() (verified int) {
			for _, a := range listOf(t, r.get("/api/archives", "t")).Archives {
				if signatureOf(a) == ArchiveSignatureVerified {
					verified++
				}
			}
			return verified
		}
		if n := count(); n != 50 || c.gets(folderAt(50)+manifestName) != 0 {
			t.Errorf("first list verified %d, want 50 and the rest left for later", n)
		}
		if n := count(); n != 60 {
			t.Errorf("second list verified %d, want 60", n)
		}
	})
}

func TestCheckCacheHoldsAtMost4096(t *testing.T) {
	var h Handlers
	for i := 0; i < 4096; i++ {
		h.remember(strconv.Itoa(i), folderCheck{eco: archive.NPM})
	}
	if c, ok := h.recall("0"); !ok || c.eco != archive.NPM || len(h.marks) != 4096 {
		t.Fatalf("after 4096 checks: %+v %v, %d kept", c, ok, len(h.marks))
	}
	h.remember("one more", folderCheck{eco: archive.Pip})
	if _, ok := h.recall("0"); ok || len(h.marks) != 1 {
		t.Errorf("the 4097th check kept %d, want the cache emptied first", len(h.marks))
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

func TestListRefusesASignatureOverItsBoundUnreadAndUncounted(t *testing.T) {
	f := newFakeMinio()
	big := base + "a-big/"
	m := manifestOf(t, "big", 1)
	f.put(bucketAlice, big+"x.tar.gz", 2048)
	f.putData(big+manifestName, m)
	f.put(bucketAlice, big+signatureName, archive.MaxSignatureSize+1)
	for i := 0; i < 50; i++ {
		folder := base + "f" + strconv.Itoa(100+i) + "/"
		mi := manifestOf(t, "p"+strconv.Itoa(i), 1)
		seedFolder(f, bucketAlice, folder, 2048, mi, signManifest(t, testPriv, mi))
	}
	r := keyRig(t, f)
	got := byKey(listOf(t, r.get("/api/archives", "t")))
	a := got[big+"x.tar.gz"]
	if a.Importable || signatureOf(a) != ArchiveSignatureUnreadable || reasonOf(a) != "its manifest.json.sig cannot be read" {
		t.Errorf("a signature one byte over the bound: importable %v signature %q reason %q", a.Importable, signatureOf(a), reasonOf(a))
	}
	if n, s := f.gets(big+manifestName), f.gets(big+signatureName); n != 0 || s != 0 {
		t.Errorf("the refused folder was read: manifest %d, signature %d", n, s)
	}
	verified := 0
	for _, a := range got {
		if signatureOf(a) == ArchiveSignatureVerified {
			verified++
		}
	}
	if verified != 50 {
		t.Errorf("verified %d of the 50 folders beside it, want 50: the refusal took a read", verified)
	}
}
