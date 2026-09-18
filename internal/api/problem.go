// Package api holds the sealift HTTP contract's hand-written handlers,
// alongside the generated server types in api.gen.go.
package api

import (
	"encoding/json"
	"net/http"
)

// ptr returns a pointer to v, for the optional Problem fields the
// generated Problem struct declares as pointers.
func ptr[T any](v T) *T { return &v }

// NewProblem builds an RFC 9457 Problem Details body for status, with
// detail explaining this occurrence. Type is left as "about:blank" since
// the contract defines no per-error type URIs yet.
func NewProblem(status int, title, detail string) Problem {
	return Problem{
		Type:   ptr("about:blank"),
		Title:  title,
		Status: status,
		Detail: ptr(detail),
	}
}

// WriteProblem sends p as an application/problem+json response with p's
// own status code.
func WriteProblem(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}
