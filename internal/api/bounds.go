package api

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

const (
	// maxJSONBodyBytes bounds every JSON request body: 16 MiB.
	maxJSONBodyBytes = 16 << 20
	// maxRequestEntries bounds the reasons, the selected dependencies and
	// the dependencies of one reason in an export request.
	maxRequestEntries = 10_000
	// maxMultipartBodyBytes bounds a project upload: its 40 parts of at
	// most 1 MiB each, plus 1 MiB for their headers.
	maxMultipartBodyBytes = (maxCreateParts + 1) << 20
	// maxNameBytes is npm's own limit on a package name.
	maxNameBytes = 214
)

// boundBodies caps the body of every /api request that has one, whatever
// it claims to be: a JSON body within 16 MiB, a project upload within
// maxMultipartBodyBytes. Any other type is refused with 415 before a byte
// is read, since every operation decodes JSON or multipart.
func boundBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}
		mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch mediaType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		case "multipart/form-data":
			r.Body = http.MaxBytesReader(w, r.Body, maxMultipartBodyBytes)
		default:
			WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, "unsupported media type", "the request body must be application/json, or multipart/form-data for a project upload"))
			return
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
