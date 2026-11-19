// Package proof exists only to check that govulncheck fails the build.
package proof

import "golang.org/x/text/language"

// Parse calls the vulnerable code path.
func Parse(s string) (language.Tag, error) { return language.Parse(s) }
