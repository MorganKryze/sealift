package api

import (
	"encoding/json"
	"net/http"
)

// HealthHandler answers a liveness probe. It carries no dependency, so a
// probe never blocks on the store, the job queue or a subprocess.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
	}{Status: "ok"})
}
