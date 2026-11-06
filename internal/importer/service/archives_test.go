package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

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

func TestListArchives(t *testing.T) {
	f := newFakeMinio()
	f.put("user-alice", base+"export.tar.gz", 2048)
	f.put("user-alice", base+"manifest.json", 10)
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
		if c.Op != "list" {
			t.Errorf("a list called %s: a list reads objects only", c.Op)
		}
	}
}

func TestListPairsByFolder(t *testing.T) {
	f := newFakeMinio()
	b := "user-alice"
	f.put(b, base+"root.tar.gz", 1)
	f.put(b, base+"manifest.json", 1)
	f.put(b, base+"sub/own.tar.gz", 1)
	f.put(b, base+"sub/manifest.json", 1)
	f.put(b, base+"two/a.tar.gz", 1)
	f.put(b, base+"two/b.tar.gz", 1)
	f.put(b, base+"two/manifest.json", 1)
	f.put(b, base+"bare/lonely.tar.gz", 1)
	f.put(b, base+"deep/er/down.tar.gz", 1)
	f.put(b, base+"deep/er/manifest.json", 1)
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
	f.put("user-alice", base+"x\x07y.tar.gz", 1)
	f.put("user-alice", base+"manifest.json", 1)
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
	f.put("user-alice", "elsewhere/other.tar.gz", 1)
	f.put("user-bob", base+"his.tar.gz", 1)
	f.put("user-bob", base+"manifest.json", 1)
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
	if len(calls) != 1 || calls[0].Op != "list" || calls[0].Bucket != "user-alice" || calls[0].Prefix != base || calls[0].Max != MaxListed {
		t.Errorf("calls = %+v, want one list of user-alice under %s", calls, base)
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
	if c := f.recorded(); len(c) != 1 || c[0].Max != MaxListed {
		t.Errorf("calls = %+v, want one list of %d", c, MaxListed)
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
