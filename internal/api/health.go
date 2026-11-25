package api

import (
	"encoding/json"
	"net/http"

	"github.com/MorganKryze/sealift/internal/tools"
)

// Readiness reports what the instance has prepared.
type Readiness interface {
	State() tools.Readiness
}

// toolsReadiness reads the tools manager's own check, the pinned Trivy and
// a database, for handlers built without a preparer.
type toolsReadiness struct{ m *tools.Manager }

func (r toolsReadiness) State() tools.Readiness {
	ready, missing := r.m.Ready()
	out := tools.Readiness{Ready: ready}
	for _, name := range missing {
		out.Items = append(out.Items, tools.Item{Name: name, State: tools.ItemPreparing})
	}
	return out
}

// LiveHandler answers a liveness probe: 200 while the process serves
// requests, whatever the preparation's state, so a probe never restarts an
// instance that is still downloading.
func LiveHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// HealthHandler answers a readiness probe from r's state: 200 once every
// item is ready, 503 with the names of the others until then. Causes stay
// out of this answer. The preparer's state is in memory, the signing key
// aside, which costs a stat of its file, so a probe never blocks on the
// job queue or a subprocess; handlers built
// without a preparer read the volume through toolsReadiness instead.
func HealthHandler(r Readiness) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		state := r.State()
		w.Header().Set("Content-Type", "application/json")
		if state.Ready {
			_ = json.NewEncoder(w).Encode(struct {
				Status string `json:"status"`
			}{Status: "ok"})
			return
		}
		missing := []string{}
		for _, it := range state.Items {
			if it.State != tools.ItemReady {
				missing = append(missing, it.Name)
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(struct {
			Status  string   `json:"status"`
			Missing []string `json:"missing"`
		}{Status: "preparing", Missing: missing})
	}
}
