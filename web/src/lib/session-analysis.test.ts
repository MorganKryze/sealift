import { describe, expect, it } from "vitest"

import type { Analysis } from "@/api/projects"
import { analysisSearch, shownAnalysis } from "@/lib/session-analysis"

const run = (id: string, createdAt: string): Analysis => ({ id, projectId: "web-portal", state: "done", createdAt })
const runs = [run("older", "2026-11-06T10:00:00Z"), run("newer", "2026-11-20T10:00:00Z")]

describe("shownAnalysis", () => {
  it("shows the analysis the link names", () => {
    expect(shownAnalysis(runs, "older")?.id).toBe("older")
  })

  it("falls back to the latest when the link names none or an unknown one", () => {
    expect(shownAnalysis(runs, undefined)?.id).toBe("newer")
    expect(shownAnalysis(runs, "gone")?.id).toBe("newer")
  })
})

describe("analysisSearch", () => {
  it("keeps a string analysis id and drops anything else", () => {
    expect(analysisSearch({ analysis: "older" })).toEqual({ analysis: "older" })
    expect(analysisSearch({ analysis: 3 })).toEqual({})
    expect(analysisSearch({ analysis: "" })).toEqual({})
    expect(analysisSearch({})).toEqual({})
  })
})
