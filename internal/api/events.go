package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// Subscriptions is the narrow view of a job queue the events handler
// needs. *jobs.Queue satisfies it; a fake in tests can feed canned events
// without running a real worker goroutine.
type Subscriptions interface {
	Subscribe() (<-chan jobs.Event, func())
}

// EventsHandler serves the running job's event stream.
type EventsHandler struct {
	Jobs Subscriptions
}

// WatchJob implements the WatchJob operation of StrictServerInterface. It
// returns the strict response object as an open pipe: VisitWatchJobResponse
// reads from it and flushes after every read, so the risk check's finding
// holds here too, and the first event reaches the client without waiting
// for the job to end.
func (h *EventsHandler) WatchJob(ctx context.Context, _ WatchJobRequestObject) (WatchJobResponseObject, error) {
	events, unsubscribe := h.Jobs.Subscribe()
	pr, pw := io.Pipe()
	go streamEvents(ctx, events, unsubscribe, pw)
	return WatchJob200TexteventStreamResponse{Body: pr}, nil
}

// streamEvents copies events into pw as server-sent events until ctx is
// done or the channel closes, then releases the subscription and closes
// the pipe so the response ends.
func streamEvents(ctx context.Context, events <-chan jobs.Event, unsubscribe func(), pw *io.PipeWriter) {
	defer unsubscribe()
	defer pw.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			if err := writeSSE(pw, e); err != nil {
				return
			}
			if e.Kind == "end" {
				return
			}
		}
	}
}

// writeSSE encodes e as one server-sent event frame. io.Pipe blocks the
// write until the response side reads and flushes it, which is what keeps
// events from queuing up unread on this side.
func writeSSE(w io.Writer, e jobs.Event) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind, payload)
	return err
}
