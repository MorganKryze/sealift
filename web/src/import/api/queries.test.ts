import { describe, expect, it } from "vitest"

import { importsPollInterval } from "./queries"
import type { ImportList } from "./queries"

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
