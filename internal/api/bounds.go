package api

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
)

const (
	// maxJSONBodyBytes bounds every JSON request body: 16 MiB.
	maxJSONBodyBytes = 16 << 20
	// maxRequestEntries bounds the reasons, the selected dependencies and
	// the dependencies of one reason in an export request.
	maxRequestEntries = 10_000
	// maxNameBytes is npm's own limit on a package name.
	maxNameBytes = 214
)

// boundJSONBodies reads every JSON request body through a 16 MiB limit.
func boundJSONBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mediaType == "application/json" {
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// requestError answers a body the generated code could not decode; a body
// over the bound gets a 413 that names it.
func requestError(w http.ResponseWriter, _ *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteProblem(w, NewProblem(http.StatusRequestEntityTooLarge, "request too large", "the request body is larger than 16 MiB"))
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// exportRequestBound names the bound an export request breaks, or returns "".
func exportRequestBound(body ExportRequest) string {
	if len(body.Selection) > maxRequestEntries {
		return fmt.Sprintf("the export selection holds more than %d dependencies", maxRequestEntries)
	}
	for name := range body.Selection {
		if len(name) > maxNameBytes {
			return fmt.Sprintf("a dependency name in the export selection is longer than %d bytes", maxNameBytes)
		}
	}
	if body.Reasons == nil {
		return ""
	}
	if len(*body.Reasons) > maxRequestEntries {
		return fmt.Sprintf("the export request holds more than %d reasons", maxRequestEntries)
	}
	for i, r := range *body.Reasons {
		if len(r.Dependencies) > maxRequestEntries {
			return fmt.Sprintf("reason %d holds more than %d dependencies", i+1, maxRequestEntries)
		}
		for _, name := range r.Dependencies {
			if len(name) > maxNameBytes {
				return fmt.Sprintf("reason %d names a dependency longer than %d bytes", i+1, maxNameBytes)
			}
		}
	}
	return ""
}
