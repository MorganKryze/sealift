package s3

import (
	"strings"
	"testing"
	"time"
)

func TestSignMatchesAWSExamples(t *testing.T) {
	when := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		in    signInput
		want  string
		scope string
	}{
		{
			name: "GET object with a range",
			in: signInput{
				Method: "GET", URI: "/test.txt", Query: "",
				Headers: map[string]string{
					"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
					"x-amz-content-sha256": emptyBodyHash, "x-amz-date": "20130524T000000Z",
				},
			},
			want: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "GET bucket listing",
			in: signInput{
				Method: "GET", URI: "/", Query: canonicalQuery([][2]string{{"prefix", "J"}, {"max-keys", "2"}}),
				Headers: map[string]string{
					"host":                 "examplebucket.s3.amazonaws.com",
					"x-amz-content-sha256": emptyBodyHash, "x-amz-date": "20130524T000000Z",
				},
			},
			want: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.PayloadHash = emptyBodyHash
			tc.in.Region = "us-east-1"
			tc.in.AccessKey = []byte("AKIAIOSFODNN7EXAMPLE")
			tc.in.SecretKey = []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
			tc.in.Time = when
			auth, sig := sign(tc.in)
			if sig != tc.want {
				t.Errorf("signature = %s, want %s", sig, tc.want)
			}
			if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;") {
				t.Errorf("authorization = %s", auth)
			}
		})
	}
}

func TestCanonicalURIEncoding(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/b/a b", "/b/a%20b"},
		{"/b/a+b", "/b/a%2Bb"},
		{"/b/a~b", "/b/a~b"},
		{"/b/é", "/b/%C3%A9"},
		{"/b/日本", "/b/%E6%97%A5%E6%9C%AC"},
		{"/b/dir/file.tgz", "/b/dir/file.tgz"},
		{"/b/a=b&c", "/b/a%3Db%26c"},
		{"/b/100%", "/b/100%25"},
	}
	for _, tc := range cases {
		if got := canonicalURI(tc.in); got != tc.want {
			t.Errorf("canonicalURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalQuerySorts(t *testing.T) {
	got := canonicalQuery([][2]string{{"prefix", "a b"}, {"max-keys", "2"}, {"list-type", "2"}})
	if want := "list-type=2&max-keys=2&prefix=a%20b"; got != want {
		t.Errorf("query = %q, want %q", got, want)
	}
}
