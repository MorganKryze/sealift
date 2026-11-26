import { describe, expect, it } from "vitest"

import { failureMessage } from "./analysis-screen"

describe("failureMessage", () => {
  it("shows the recorded cause", () => {
    expect(failureMessage({ state: "failed", failure: { step: "resolve-project", message: "pnpm install: exit status 1" } })).toBe(
      "pnpm install: exit status 1",
    )
  })

  it("names the step when an older analysis recorded no cause", () => {
    expect(failureMessage({ state: "failed", failure: { step: "scan-project", message: "" } })).toBe(
      "It stopped while scanning the project. The version that ran it did not record why; the log has what it wrote.",
    )
  })

  it("reads a cancel as the user's action", () => {
    expect(failureMessage({ state: "cancelled", failure: { step: "resolve-candidates", message: "context canceled" } })).toBe(
      "You cancelled this analysis.",
    )
  })
})
