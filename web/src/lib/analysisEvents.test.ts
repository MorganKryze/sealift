import { describe, expect, it } from "vitest"

import { analysisEventsReducer, initialAnalysisEventsState, LOG_LINES_KEPT, timeLeft, type AnalysisEventsState, type JobAction, type JobEvent } from "@/lib/analysisEvents"

const job = "job-1"

// A local time, so the formatted receipt time reads the same in every time zone.
const at = (seconds: number) => new Date(2026, 10, 26, 14, 11, seconds)
const fold = (actions: JobAction[], from: AnalysisEventsState = initialAnalysisEventsState) =>
  actions.reduce((state, action, i) => analysisEventsReducer(state, action, at(i % 60)), from)

describe("analysisEventsReducer", () => {
  it("folds a scripted sequence, including a log burst, into the final state", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "resolve", state: "running" } },
      { kind: "progress", job, data: { step: "resolve", done: 1, total: 4, estimatedRemainingMs: 9000 } },
      {
        kind: "candidate",
        job,
        data: { dependency: "left-pad", version: "1.3.0", vector: [0, 0, 0, 0, 0], signals: ["patch"] },
      },
      { kind: "log", job, data: { line: "resolving left-pad" } },
      { kind: "log", job, data: { line: "resolving chalk" } },
      { kind: "log", job, data: { line: "resolving lodash" } },
      { kind: "step", job, data: { name: "resolve", state: "done", durationMs: 1200 } },
      { kind: "end", job, data: { state: "done" } },
    ]

    const state = fold(events)

    expect(state.steps).toEqual([{ name: "resolve", state: "done", durationMs: 1200 }])
    expect(state.progress).toEqual({ step: "resolve", done: 1, total: 4, estimatedRemainingMs: 9000 })
    expect(state.ended).toBe(true)
    expect(state.endState).toBe("done")
  })

  it("keeps a step's own progress readable by name once a later step reports its own", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "list-candidates", state: "done", durationMs: 100 } },
      { kind: "progress", job, data: { step: "resolve-candidates", done: 1, total: 249 } },
      { kind: "progress", job, data: { step: "resolve-candidates", done: 249, total: 249 } },
      { kind: "step", job, data: { name: "resolve-candidates", state: "done", durationMs: 29000 } },
      { kind: "progress", job, data: { step: "scan-candidates", done: 1, total: 2 } },
      { kind: "progress", job, data: { step: "scan-candidates", done: 2, total: 2 } },
      { kind: "step", job, data: { name: "scan-candidates", state: "done", durationMs: 400 } },
    ]

    const state = fold(events)

    // resolve-candidates' own entry survives scan-candidates' own
    // progress, recorded separately under its own step name.
    expect(state.progressByStep["resolve-candidates"]).toEqual({ step: "resolve-candidates", done: 249, total: 249 })
    expect(state.progressByStep["scan-candidates"]).toEqual({ step: "scan-candidates", done: 2, total: 2 })
    expect(state.progress).toEqual({ step: "scan-candidates", done: 2, total: 2 })
  })

  // Finding 4: a subscriber that only replays the tail of a long run's
  // history (past the queue's replayLimit on "progress" events) may never
  // see list-candidates' own "step" event at all, only resolve-candidates'
  // progress. Keying progress by the step field it carries, instead of by
  // how many step events have been seen (state.steps.length), is what
  // keeps this attributed to resolve-candidates rather than falling under
  // whatever position list-candidates would otherwise have occupied.
  it("attributes progress by its own step field even when earlier step events were never replayed", () => {
    const events: JobEvent[] = [{ kind: "progress", job, data: { step: "resolve-candidates", done: 12, total: 38 } }]

    const state = fold(events)

    expect(state.steps).toEqual([])
    expect(state.progressByStep["resolve-candidates"]).toEqual({ step: "resolve-candidates", done: 12, total: 38 })
  })

  it("keeps steps in first-seen order while updating each one in place", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "resolve", state: "running" } },
      { kind: "step", job, data: { name: "scan", state: "queued" } },
      { kind: "step", job, data: { name: "resolve", state: "done", durationMs: 500 } },
    ]

    const state = fold(events)

    expect(state.steps.map((step) => step.name)).toEqual(["resolve", "scan"])
    expect(state.steps[0]).toEqual({ name: "resolve", state: "done", durationMs: 500, error: undefined })
  })

  it("carries a failed step's error message so the UI need not wait for a refetch", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "scan-project", state: "running" } },
      {
        kind: "step",
        job,
        data: { name: "scan-project", state: "failed", durationMs: 300, error: "database download timed out" },
      },
      { kind: "end", job, data: { state: "failed" } },
    ]

    const state = fold(events)

    expect(state.steps[0]).toEqual({
      name: "scan-project",
      state: "failed",
      durationMs: 300,
      error: "database download timed out",
    })
    expect(state.endState).toBe("failed")
  })

  it("keeps each log line with its time and step", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "validate", state: "done", durationMs: 120 } },
      { kind: "step", job, data: { name: "prepare-tools", state: "done", durationMs: 2400 } },
      { kind: "log", job, data: { line: "pnpm: WARN deprecated inflight@1.0.6" } },
      { kind: "step", job, data: { name: "resolve-project", state: "done", durationMs: 38000 } },
      { kind: "step", job, data: { name: "scan-project", state: "done", durationMs: 4000 } },
      { kind: "step", job, data: { name: "list-candidates", state: "done", durationMs: 900 } },
      { kind: "log", job, data: { line: "webpack-dev-server@5.2.2 does not resolve: pnpm install: exit status 1" } },
      { kind: "candidate", job, data: { dependency: "react-dom", version: "19.2.0", vector: [0, 0, 0, 0, 0], signals: [] } },
      { kind: "step", job, data: { name: "rank", state: "failed", durationMs: 10, error: "write ranking.json: disk full" } },
    ]

    const state = fold(events)

    expect(state.log).toEqual([
      { at: "14:11:00", step: "check", text: "done in less than 1 s" },
      { at: "14:11:01", step: "tools", text: "done in 2 s" },
      { at: "14:11:02", step: "resolve", text: "pnpm: WARN deprecated inflight@1.0.6" },
      { at: "14:11:03", step: "resolve", text: "done in 38 s" },
      { at: "14:11:04", step: "scan", text: "done in 4 s" },
      { at: "14:11:05", step: "newer", text: "done in less than 1 s" },
      { at: "14:11:06", step: "candidate", text: "webpack-dev-server@5.2.2 does not resolve: pnpm install: exit status 1", tone: "warn" },
      { at: "14:11:07", step: "candidate", text: "react-dom 19.2.0 · resolves", tone: "ok" },
      { at: "14:11:08", step: "rank", text: "failed: write ranking.json: disk full", tone: "bad" },
    ])
    expect(state.logCount).toBe(9)
  })

  it("keeps the last 2,000 lines and counts them all", () => {
    const events: JobEvent[] = Array.from({ length: 2014 }, (_, i) => ({ kind: "log", job, data: { line: `line ${i + 1}` } }))

    const state = fold(events)

    expect(LOG_LINES_KEPT).toBe(2000)
    expect(state.log).toHaveLength(2000)
    expect(state.log[0].text).toBe("line 15")
    expect(state.log.at(-1)?.text).toBe("line 2014")
    expect(state.logCount).toBe(2014)
  })

  it("starts again on reset", () => {
    const events: JobAction[] = [
      { kind: "step", job, data: { name: "validate", state: "done", durationMs: 120 } },
      { kind: "progress", job, data: { step: "resolve-candidates", done: 3, total: 9, estimatedRemainingMs: 6000 } },
      { kind: "log", job, data: { line: "left-pad@1.3.0 does not resolve" } },
      { kind: "reset" },
    ]

    expect(fold(events)).toEqual(initialAnalysisEventsState)
  })
})

describe("timeLeft", () => {
  it.each([
    [undefined, undefined],
    [0, "Less than a minute left"],
    [59_000, "Less than a minute left"],
    [60_000, "About 1 minute left"],
    [300_000, "About 5 minutes left"],
    [318_000, "About 5 minutes left"],
    [3_540_000, "About 59 minutes left"],
    [3_600_000, "About 1 h left"],
    [4_200_000, "About 1 h 10 min left"],
  ])("reads %s ms as %s", (ms, words) => {
    expect(timeLeft(ms)).toBe(words)
  })
})
