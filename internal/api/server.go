package api

import (
	"net/http"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// Routes returns the routes this part of the backend serves: the health
// check and the running job's event stream. The generated strict server
// takes over once every operation of the contract has a handler.
func Routes(q *jobs.Queue) *http.ServeMux {
	events := &EventsHandler{Jobs: q}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", HealthHandler)
	mux.HandleFunc("GET /api/jobs/current/events", func(w http.ResponseWriter, r *http.Request) {
		resp, err := events.WatchJob(r.Context(), WatchJobRequestObject{})
		if err != nil {
			WriteProblem(w, NewProblem(http.StatusInternalServerError, "event stream failed", err.Error()))
			return
		}
		if err := resp.VisitWatchJobResponse(w); err != nil {
			// The status line is already sent, so the client sees a truncated
			// stream; the log line is the only place left to report it.
			logStreamError(r, err)
		}
	})
	return mux
}
