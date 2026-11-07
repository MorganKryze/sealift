import { describe, expect, it } from "vitest"

import { importPollInterval, importsPollInterval } from "./queries"
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
