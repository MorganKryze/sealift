import type { components } from "@/api/schema"

export type EventKind = components["schemas"]["EventKind"]
export type JobEvent = components["schemas"]["Event"]
export type StepData = components["schemas"]["StepData"]
export type ProgressData = components["schemas"]["ProgressData"]
export type EndData = components["schemas"]["EndData"]
export type CandidateData = components["schemas"]["CandidateData"]
export type LogData = components["schemas"]["LogData"]

/** One line of the live log: the browser's time of receipt, the short name of the step that ran, and what it said. */
export interface LogLine {
  at: string
  step: string
  text: string
  tone?: "ok" | "warn" | "bad"
}

/** The log keeps this many lines on screen; the count still says how many arrived. */
export const LOG_LINES_KEPT = 2000

/** An event of the stream, or the start of a new connection, whose replay fills the state again. */
export type JobAction = JobEvent | { kind: "reset" }

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
  ended: boolean
  endState: EndData["state"] | null
  /** The last LOG_LINES_KEPT lines, newest last. */
  log: LogLine[]
  /** Every line received on this connection, kept or not. */
  logCount: number
}

export const initialAnalysisEventsState: AnalysisEventsState = {
  steps: [],
  progress: null,
  progressByStep: {},
  ended: false,
  endState: null,
  log: [],
  logCount: 0,
}

// The analysis' steps in run order: a step reports itself when it ends, so the one running is the next one.
const ANALYSIS_ORDER = ["validate", "prepare-tools", "resolve-project", "scan-project", "list-candidates", "resolve-candidates", "scan-candidates", "rank", "check-combined"]

const SHORT_NAMES: Record<string, string> = {
  validate: "check",
  "prepare-tools": "tools",
  "resolve-project": "resolve",
  "scan-project": "scan",
  "list-candidates": "newer",
  "resolve-candidates": "candidate",
  "scan-candidates": "candidate",
  rank: "rank",
  "check-combined": "combined",
  "package-list": "list",
  download: "download",
  strip: "strip",
  archive: "pack",
  reports: "sign",
}

/**
 * The step running now, by its server name. An export reports each step as it starts; an analysis
 * reports a step only when it ends, so the step after the last one reported is the one running.
 */
export function currentStep(steps: StepEntry[]): string | undefined {
  const last = steps.at(-1)
  if (!last) return ANALYSIS_ORDER[0]
  if (last.state !== "done") return last.name
  const next = ANALYSIS_ORDER.indexOf(last.name) + 1
  return next > 0 ? ANALYSIS_ORDER[next] : undefined
}

const shortName = (name: string | undefined) => (name ? (SHORT_NAMES[name] ?? name) : "")

const RECEIVED = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })

/** The colour a log line takes, always beside the word that says the same. */
export function lineTone(text: string): LogLine["tone"] {
  if (/\bERR_[A-Z_]+/.test(text)) return "bad"
  if (/does not resolve|unreachable|failed|error/i.test(text)) return "warn"
  return undefined
}

/** A duration as the screens write it: "less than 1 s", "48 s", "5 min 18 s", "1 h 10 min". */
export function elapsed(ms: number): string {
  if (ms < 1000) return "less than 1 s"
  const seconds = Math.round(ms / 1000)
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return seconds % 60 === 0 ? `${minutes} min` : `${minutes} min ${seconds % 60} s`
  return minutes % 60 === 0 ? `${Math.floor(minutes / 60)} h` : `${Math.floor(minutes / 60)} h ${minutes % 60} min`
}

/** A wait in words, rounded to the minute past the first: "less than a minute", "about 5 minutes", "about 1 h 10 min". */
export function about(ms: number): string {
  const minutes = Math.round(ms / 60_000)
  if (ms < 60_000) return "less than a minute"
  if (minutes < 60) return `about ${minutes} ${minutes === 1 ? "minute" : "minutes"}`
  const hours = Math.floor(minutes / 60)
  return minutes % 60 === 0 ? `about ${hours} h` : `about ${hours} h ${minutes % 60} min`
}

/** The time left as a progress title: "About 5 minutes left", "Less than a minute left". */
export function timeLeft(ms: number | undefined): string | undefined {
  if (ms === undefined) return undefined
  const words = about(ms)
  return `${words.charAt(0).toUpperCase()}${words.slice(1)} left`
}

/** The estimate of the time left, while the step that gave it still runs. */
export function estimateOf(state: AnalysisEventsState): number | undefined {
  const progress = state.progress
  if (!progress || progress.estimatedRemainingMs === undefined) return undefined
  return state.steps.some((step) => step.name === progress.step) ? undefined : progress.estimatedRemainingMs
}

function stepLine(data: StepData): Pick<LogLine, "text" | "tone"> {
  switch (data.state) {
    case "done":
      return { text: `done in ${elapsed(data.durationMs ?? 0)}` }
    case "failed":
      return { text: data.error ? `failed: ${data.error}` : "failed", tone: "bad" }
    case "running":
      return { text: "started" }
    default:
      return { text: data.state }
  }
}

function withLine(state: AnalysisEventsState, line: LogLine): Pick<AnalysisEventsState, "log" | "logCount"> {
  const log = state.log.length < LOG_LINES_KEPT ? [...state.log, line] : [...state.log.slice(state.log.length - LOG_LINES_KEPT + 1), line]
  return { log, logCount: state.logCount + 1 }
}

/**
 * Folds one job-queue event into the running job's state. Kept free of EventSource and the DOM so the
 * event kinds can be scripted and asserted on without a browser. A reset starts the state again: each
 * connection replays the job so far, so the log shows each line once.
 */
export function analysisEventsReducer(state: AnalysisEventsState, action: JobAction, now: Date = new Date()): AnalysisEventsState {
  const at = RECEIVED.format(now)
  switch (action.kind) {
    case "reset":
      return initialAnalysisEventsState
    case "step": {
      const data = action.data as StepData
      const entry: StepEntry = { name: data.name, state: data.state, durationMs: data.durationMs, error: data.error }
      const index = state.steps.findIndex((step) => step.name === data.name)
      const steps = index === -1 ? [...state.steps, entry] : state.steps.map((step, i) => (i === index ? entry : step))
      return { ...state, steps, ...withLine(state, { at, step: shortName(data.name), ...stepLine(data) }) }
    }
    case "progress": {
      const data = action.data as ProgressData
      return {
        ...state,
        progress: data,
        progressByStep: { ...state.progressByStep, [data.step]: data },
      }
    }
    case "candidate": {
      const data = action.data as CandidateData
      return { ...state, ...withLine(state, { at, step: shortName(currentStep(state.steps)), text: `${data.dependency} ${data.version} · resolves`, tone: "ok" }) }
    }
    case "log": {
      const { line } = action.data as LogData
      const tone = lineTone(line)
      return { ...state, ...withLine(state, { at, step: shortName(currentStep(state.steps)), text: line, ...(tone ? { tone } : {}) }) }
    }
    case "end":
      return { ...state, ended: true, endState: (action.data as EndData).state }
    default:
      return state
  }
}
