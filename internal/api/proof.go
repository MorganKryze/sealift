package api

import (
	"net/http"
	"os"
)

// ProofHandler exists only to check that CodeQL fails a path injection.
func ProofHandler(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(r.URL.Query().Get("f"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _ = w.Write(b)
}
