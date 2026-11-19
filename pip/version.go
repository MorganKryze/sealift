// Package pip reads Python requirements files and the package index for
// sealift's pip projects.
package pip

import (
	"regexp"
	"strings"
)

var (
	separatorRuns = regexp.MustCompile(`[-_.]+`)
	nameRE        = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	// Public versions only: no local part and no wildcard. A leading "v" is
	// refused, which PEP 440 would tolerate.
	versionRE = regexp.MustCompile(`^(?:(\d+)!)?(\d+(?:\.\d+)*)` +
		`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d*))?` +
		`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?` +
		`(?:[-_.]?(dev)[-_.]?(\d*))?$`)
)

const maxVersionBytes = 128

// Normalize applies PEP 503: lower case, runs of -_. become one -.
func Normalize(name string) string {
	return separatorRuns.ReplaceAllString(strings.ToLower(name), "-")
}

// ValidName reports whether name is a PEP 508 project name.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// IsExactVersion reports whether v is a PEP 440 public version, with no
// wildcard and no local part.
func IsExactVersion(v string) bool {
	_, ok := canonicalVersion(v)
	return ok
}

// SameVersion reports PEP 440 equality: 1.0 equals 1.0.0.
func SameVersion(a, b string) bool {
	ca, ok := canonicalVersion(a)
	if !ok {
		return false
	}
	cb, ok := canonicalVersion(b)
	return ok && ca == cb
}

// canonicalVersion returns one spelling for every spelling of a version.
func canonicalVersion(v string) (string, bool) {
	if len(v) > maxVersionBytes {
		return "", false
	}
	m := versionRE.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return "", false
	}
	var b strings.Builder
	b.WriteString(number(m[1]))
	b.WriteByte('!')
	release := strings.Split(m[2], ".")
	for len(release) > 1 && number(release[len(release)-1]) == "0" {
		release = release[:len(release)-1]
	}
	for i, seg := range release {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(number(seg))
	}
	if m[3] != "" {
		kind := map[string]string{"alpha": "a", "a": "a", "beta": "b", "b": "b", "preview": "rc", "pre": "rc", "c": "rc", "rc": "rc"}[m[3]]
		b.WriteString("-" + kind + number(m[4]))
	}
	switch {
	case m[5] != "":
		b.WriteString("-post" + number(m[5]))
	case m[6] != "":
		b.WriteString("-post" + number(m[7]))
	}
	if m[8] != "" {
		b.WriteString("-dev" + number(m[9]))
	}
	return b.String(), true
}

// number drops leading zeros, and reads an empty string as 0.
func number(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
