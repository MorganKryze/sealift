import { describe, expect, it } from "vitest"

import type { Analysis, Export, Project } from "@/api/projects"

import { sessionSteps } from "./sessionSteps"

const analysis = (state: string): Analysis => ({ id: "a1", projectId: "p1", state, createdAt: "2026-09-22T10:00:00Z" }) as Analysis
const exp = (state: string): Export => ({ id: "e1", projectId: "p1", analysisId: "a1", state, createdAt: "2026-09-22T11:00:00Z" }) as Export
const project = (a?: Analysis, e?: Export): Project => ({ id: "p1", name: "demo", analyses: a ? [a] : [], exports: e ? [e] : [] }) as unknown as Project

const view = (p: Project, current: "drop" | "analysis" | "review" | "export") =>
  Object.fromEntries(sessionSteps({ project: p, current, onNavigate: () => {} }).map((s) => [s.id, `${s.status}${s.current ? "*" : ""}`]))

describe("sessionSteps", () => {
  it("keeps a failed analysis failed, whichever step is on screen", () => {
    expect(view(project(analysis("failed")), "drop").analysis).toBe("failed")
    expect(view(project(analysis("failed")), "analysis").analysis).toBe("failed*")
    expect(view(project(analysis("failed")), "review").review).toBe("upcoming*")
  })

  it("shows a running analysis as running, not done", () => {
    expect(view(project(analysis("running")), "drop").analysis).toBe("running")
  })

  it("offers review after the analysis without marking it done until an export exists", () => {
    expect(view(project(analysis("done")), "analysis")).toEqual({ drop: "done", analysis: "done*", review: "available", export: "upcoming" })
    expect(view(project(analysis("done"), exp("done")), "export")).toEqual({ drop: "done", analysis: "done", review: "done", export: "done*" })
  })

  it("marks a cancelled analysis cancelled, never failed or done", () => {
    expect(view(project(analysis("cancelled")), "analysis")).toEqual({ drop: "done", analysis: "cancelled*", review: "upcoming", export: "upcoming" })
    expect(view(project(analysis("cancelled")), "drop").analysis).toBe("cancelled")
  })

  it("leaves Seal to do after a cancelled export", () => {
    expect(view(project(analysis("done"), exp("cancelled")), "review")).toEqual({ drop: "done", analysis: "done", review: "available*", export: "upcoming" })
  })

  it("keeps a failed export failed and reachable", () => {
    const steps = sessionSteps({ project: project(analysis("done"), exp("failed")), current: "review", onNavigate: () => {} })
    const seal = steps.find((s) => s.id === "export")
    expect(seal?.status).toBe("failed")
    expect(seal?.onNavigate).toBeDefined()
  })

  it("follows the analysis on screen, not a later one", () => {
    const sealed = { ...analysis("done"), createdAt: "2026-09-22T09:00:00Z" } as Analysis
    const later = { ...analysis("cancelled"), id: "a2", createdAt: "2026-09-22T12:00:00Z" } as Analysis
    const p = { id: "p1", name: "demo", analyses: [sealed, later], exports: [exp("done")] } as unknown as Project
    const steps = sessionSteps({ project: p, analysis: sealed, current: "export", onNavigate: () => {} })
    expect(Object.fromEntries(steps.map((s) => [s.id, s.status]))).toEqual({ drop: "done", analysis: "done", review: "done", export: "done" })
  })
})
