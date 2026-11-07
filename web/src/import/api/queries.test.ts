import { describe, expect, it } from "vitest"

import type { ReportPackage } from "../lib/outcome"
import { importPollInterval, importsPollInterval, retryGroups } from "./queries"
import type { Import, ImportList } from "./queries"

const imp = (outcome: string) => ({ id: outcome, outcome }) as unknown as ImportList["imports"][number]

describe("imports poll interval", () => {
  it.each([
    ["a queued import", ["complete", "queued"], 5000],
    ["a running import", ["running", "refused"], 5000],
    ["only ended imports", ["complete", "incomplete", "refused", "interrupted"], false],
    ["no import", [], false],
  ])("is %s", (_name, outcomes, want) => {
    expect(importsPollInterval({ imports: outcomes.map(imp) })).toBe(want)
  })

  it("is off before the first answer", () => {
    expect(importsPollInterval(undefined)).toBe(false)
  })
})

function single(status: string, outcome: string, removal?: { removed: boolean; reason: string }): Import {
  return { id: "x", outcome: status === "ended" ? outcome : status, attempts: [{ n: 1, status, outcome: status === "ended" ? outcome : "", removal }] } as unknown as Import
}

describe("import poll interval", () => {
  it.each([
    ["queued", single("queued", ""), 2000],
    ["running", single("running", ""), 2000],
    ["complete with no removal recorded", single("ended", "complete"), 2000],
    ["complete with a removal", single("ended", "complete", { removed: true, reason: "" }), false],
    ["complete with a removal that kept the archive", single("ended", "complete", { removed: false, reason: "changed" }), false],
    ["incomplete", single("ended", "incomplete"), false],
    ["refused", single("ended", "refused"), false],
    ["interrupted", single("ended", "interrupted"), false],
  ])("is %s", (_name, imp, want) => {
    expect(importPollInterval(imp)).toBe(want)
  })

  it("follows the latest attempt, not an earlier one", () => {
    const imp = { id: "x", outcome: "incomplete", attempts: [{ n: 1, status: "ended", outcome: "complete" }, { n: 2, status: "ended", outcome: "incomplete" }] } as unknown as Import
    expect(importPollInterval(imp)).toBe(false)
  })

  it("is off before the first answer", () => {
    expect(importPollInterval(undefined)).toBe(false)
  })
})

const pkg = (state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({ name: "left-pad", version: "1.3.0", file: "x", state, reason: "", note: "", ...over })
const many = (n: number, state: string, over: Partial<ReportPackage> = {}) => Array.from({ length: n }, () => pkg(state, over))

describe("retryGroups", () => {
  it("splits what a retry clears as is from what needs a change first", () => {
    const g = retryGroups([
      ...many(40, "published"),
      ...many(2, "failed", { kind: "interrupted", reason: "interrupted" }),
      pkg("failed", { kind: "source", reason: "x" }),
      pkg("failed", { kind: "nexus", reason: "x" }),
      pkg("failed", { kind: "nexus", reason: "x" }),
      pkg("failed", { kind: "conflict", reason: "x" }),
      pkg("failed", { reason: "Nexus answered 500" }),
      pkg("pending"),
    ])
    expect(g.notInNexus).toBe(8)
    expect(g.asIs).toBe(4)
    expect(g.unknown).toBe(1)
    expect(g.changeFirst.map((c) => [c.kind, c.count])).toEqual([["conflict", 1], ["nexus", 2]])
    expect(g.changeFirst[0].words).toMatch(/delete it in Nexus/)
  })

  it("counts a v0.4.0 package that was not reached as clearing as is", () => {
    const g = retryGroups([pkg("failed", { reason: "not reached" }), pkg("failed", { reason: "interrupted" })])
    expect(g).toMatchObject({ notInNexus: 2, asIs: 2, unknown: 0, changeFirst: [] })
  })
})

