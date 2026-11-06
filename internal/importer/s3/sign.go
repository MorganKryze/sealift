package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

const (
	service     = "s3"
	scopeEnd    = "aws4_request"
	dateLayout  = "20060102"
	stampLayout = "20060102T150405Z"
	algorithm   = "AWS4-HMAC-SHA256"
	// emptyBodyHash is the SHA-256 of an empty body; every request here has none.
	emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// signInput holds what Signature Version 4 covers. Header names are lower case.
type signInput struct {
	Method, URI, Query string
	Headers            map[string]string
	PayloadHash        string
	Region             string
	AccessKey          []byte
	SecretKey          []byte
	Time               time.Time
}

// sign returns the Authorization header value and the bare signature.
func sign(in signInput) (authorization, signature string) {
	names := make([]string, 0, len(in.Headers))
	for name := range in.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, name := range names {
		canonHeaders.WriteString(name + ":" + strings.TrimSpace(in.Headers[name]) + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonical := strings.Join([]string{
		in.Method, in.URI, in.Query, canonHeaders.String(), signedHeaders, in.PayloadHash,
	}, "\n")

	t := in.Time.UTC()
	scope := t.Format(dateLayout) + "/" + in.Region + "/" + service + "/" + scopeEnd
	toSign := algorithm + "\n" + t.Format(stampLayout) + "\n" + scope + "\n" + hexHash([]byte(canonical))

	key := mac(append([]byte("AWS4"), in.SecretKey...), t.Format(dateLayout))
	key = mac(key, in.Region)
	key = mac(key, service)
	key = mac(key, scopeEnd)
	signature = hex.EncodeToString(mac(key, toSign))

	authorization = algorithm + " Credential=" + string(in.AccessKey) + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return authorization, signature
}

func mac(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// encode percent-encodes every byte but the unreserved set, in upper case.
func encode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

// canonicalURI encodes each segment of a path and keeps the slashes. S3 does not encode twice.
func canonicalURI(path string) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = encode(s)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery encodes and sorts the pairs by name, then value.
func canonicalQuery(pairs [][2]string) string {
	enc := make([][2]string, len(pairs))
	for i, p := range pairs {
		enc[i] = [2]string{encode(p[0]), encode(p[1])}
	}
	sort.Slice(enc, func(i, j int) bool {
		if enc[i][0] != enc[j][0] {
			return enc[i][0] < enc[j][0]
		}
		return enc[i][1] < enc[j][1]
	})
	parts := make([]string, len(enc))
	for i, p := range enc {
		parts[i] = p[0] + "=" + p[1]
	}
	return strings.Join(parts, "&")
}
