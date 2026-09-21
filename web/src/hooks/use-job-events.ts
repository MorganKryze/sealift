import { useEffect, useReducer, useRef } from "react"

import {
  analysisEventsReducer,
  initialAnalysisEventsState,
  type AnalysisEventsState,
  type JobEvent,
} from "@/lib/analysisEvents"

/**
 * Subscribes to the single job queue's event stream while active, folding
 * events into the reducer. The queue runs one job at a time but the stream
 * is global, so events belonging to a different job are ignored.
 */
export function useJobEvents(analysisId: string, active: boolean, onEnd: () => void): AnalysisEventsState {
  const [state, dispatch] = useReducer(analysisEventsReducer, initialAnalysisEventsState)
  const onEndRef = useRef(onEnd)

  useEffect(() => {
    onEndRef.current = onEnd
  }, [onEnd])

  useEffect(() => {
    if (!active) {
      return
    }

    const source = new EventSource("/api/jobs/current/events")

    source.onmessage = (message) => {
      const event = JSON.parse(message.data) as JobEvent
      if (event.job !== analysisId) {
        return
      }
      dispatch(event)
      if (event.kind === "end") {
        source.close()
        onEndRef.current()
      }
    }

    source.onerror = () => {
      source.close()
    }

    return () => source.close()
  }, [analysisId, active])

  return state
}
