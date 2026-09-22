import type { components } from "@/api/schema"

export type EventKind = components["schemas"]["EventKind"]
export type JobEvent = components["schemas"]["Event"]
export type StepData = components["schemas"]["StepData"]
export type ProgressData = components["schemas"]["ProgressData"]
export type CandidateData = components["schemas"]["CandidateData"]
export type LogData = components["schemas"]["LogData"]
export type EndData = components["schemas"]["EndData"]

export interface StepEntry {
  name: string
  state: StepData["state"]
  durationMs?: number
  error?: string
}

export interface AnalysisEventsState {
  steps: StepEntry[]
  progress: ProgressData | null
  candidates: CandidateData[]
  logLines: string[]
  ended: boolean
  endState: EndData["state"] | null
}

export const initialAnalysisEventsState: AnalysisEventsState = {
  steps: [],
  progress: null,
  candidates: [],
  logLines: [],
  ended: false,
  endState: null,
}

/**
 * Folds one job-queue event into the running analysis state. Kept free of
 * EventSource and the DOM so the five event kinds can be scripted and
 * asserted on without a browser.
 */
export function analysisEventsReducer(state: AnalysisEventsState, event: JobEvent): AnalysisEventsState {
  switch (event.kind) {
    case "step": {
      const data = event.data as StepData
      const entry: StepEntry = { name: data.name, state: data.state, durationMs: data.durationMs, error: data.error }
      const index = state.steps.findIndex((step) => step.name === data.name)
      const steps = index === -1 ? [...state.steps, entry] : state.steps.map((step, i) => (i === index ? entry : step))
      return { ...state, steps }
    }
    case "progress":
      return { ...state, progress: event.data as ProgressData }
    case "candidate":
      return { ...state, candidates: [...state.candidates, event.data as CandidateData] }
    case "log":
      return { ...state, logLines: [...state.logLines, (event.data as LogData).line] }
    case "end":
      return { ...state, ended: true, endState: (event.data as EndData).state }
    default:
      return state
  }
}
