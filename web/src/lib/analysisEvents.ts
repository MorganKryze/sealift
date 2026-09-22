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
  /**
   * The same progress events, kept per step name instead of collapsed to
   * the latest one: progress carries its own step field (see
   * internal/jobs.progressData), so this survives a subscriber that only
   * replays the tail of a long run's history, where earlier steps and
   * their position in state.steps are no longer known. Keying by name,
   * not position, is also what keeps a later step's own progress
   * (analysis' scan-candidates resolves in two fixed batches) from
   * overwriting resolve-candidates' real count once that step has moved
   * on.
   */
  progressByStep: Record<string, ProgressData>
  candidates: CandidateData[]
  logLines: string[]
  ended: boolean
  endState: EndData["state"] | null
}

export const initialAnalysisEventsState: AnalysisEventsState = {
  steps: [],
  progress: null,
  progressByStep: {},
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
    case "progress": {
      const data = event.data as ProgressData
      return {
        ...state,
        progress: data,
        progressByStep: { ...state.progressByStep, [data.step]: data },
      }
    }
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
