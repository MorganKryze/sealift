import { useEffect, useReducer, useRef } from "react"

import {
  analysisEventsReducer,
  initialAnalysisEventsState,
  type AnalysisEventsState,
  type EventKind,
  type JobAction,
  type JobEvent,
} from "@/lib/analysisEvents"

// The server names every frame after jobs.Event.Kind ("event: step", …);
// EventSource's plain onmessage only fires for an unnamed frame, so each
// kind needs its own addEventListener.
const eventKinds: EventKind[] = ["step", "progress", "candidate", "log", "end"]

/**
 * Subscribes to the single job queue's event stream while active, folding
 * events into the reducer, and starts the state again on each connection.
 * The queue runs one job at a time but the stream is global, so events
 * belonging to a different job are ignored: storeId
 * is the directory id this hook was called with, not the queue id the
 * server assigns per submission.
 */
export function useJobEvents(analysisId: string, active: boolean, onEnd: () => void): AnalysisEventsState {
  // Each line takes the time it is received, so the reducer's clock stays at its default.
  const [state, dispatch] = useReducer((current: AnalysisEventsState, action: JobAction) => analysisEventsReducer(current, action), initialAnalysisEventsState)
  const onEndRef = useRef(onEnd)

  useEffect(() => {
    onEndRef.current = onEnd
  }, [onEnd])

  useEffect(() => {
    if (!active) {
      return
    }

    const source = new EventSource("/api/jobs/current/events")

    function handle(message: MessageEvent<string>) {
      const event = JSON.parse(message.data) as JobEvent
      if (event.storeId !== analysisId) {
        return
      }
      dispatch(event)
      if (event.kind === "end") {
        onEndRef.current()
      }
    }

    // Each connection, the first and every reconnect, replays the job so far: the state starts again
    // on open, so a replayed line is never shown twice.
    function restart() {
      dispatch({ kind: "reset" })
    }

    source.addEventListener("open", restart)
    for (const kind of eventKinds) {
      source.addEventListener(kind, handle)
    }

    // No onerror handler: EventSource reconnects on its own after a
    // dropped connection, including the one the server closes once a job
    // ends. Closing here on the first error would turn that into a
    // stream that never resumes. The refetchInterval on the project and
    // export queries covers whatever a reconnect still misses.

    return () => {
      source.removeEventListener("open", restart)
      for (const kind of eventKinds) {
        source.removeEventListener(kind, handle)
      }
      source.close()
    }
  }, [analysisId, active])

  return state
}
