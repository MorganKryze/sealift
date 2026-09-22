import { describe, expect, it } from "vitest"

import { analysisEventsReducer, initialAnalysisEventsState, type JobEvent } from "@/lib/analysisEvents"

const job = "job-1"

describe("analysisEventsReducer", () => {
  it("folds a scripted sequence, including a log burst, into the final state", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "resolve", state: "running" } },
      { kind: "progress", job, data: { done: 1, total: 4, estimatedRemainingMs: 9000 } },
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

    const state = events.reduce(analysisEventsReducer, initialAnalysisEventsState)

    expect(state.steps).toEqual([{ name: "resolve", state: "done", durationMs: 1200 }])
    expect(state.progress).toEqual({ done: 1, total: 4, estimatedRemainingMs: 9000 })
    expect(state.candidates).toHaveLength(1)
    expect(state.logLines).toEqual(["resolving left-pad", "resolving chalk", "resolving lodash"])
    expect(state.ended).toBe(true)
    expect(state.endState).toBe("done")
  })

  it("keeps steps in first-seen order while updating each one in place", () => {
    const events: JobEvent[] = [
      { kind: "step", job, data: { name: "resolve", state: "running" } },
      { kind: "step", job, data: { name: "scan", state: "queued" } },
      { kind: "step", job, data: { name: "resolve", state: "done", durationMs: 500 } },
    ]

    const state = events.reduce(analysisEventsReducer, initialAnalysisEventsState)

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

    const state = events.reduce(analysisEventsReducer, initialAnalysisEventsState)

    expect(state.steps[0]).toEqual({
      name: "scan-project",
      state: "failed",
      durationMs: 300,
      error: "database download timed out",
    })
    expect(state.endState).toBe("failed")
  })
})
