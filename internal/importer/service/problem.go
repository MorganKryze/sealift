package service

import (
	"encoding/json"
	"net/http"
)

func ptr[T any](v T) *T { return &v }

// writeProblem sends an RFC 9457 body with the given status. The detail
// never holds a token, a header or any text from the request.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Type: ptr("about:blank"), Title: title, Status: status, Detail: ptr(detail)})
}
