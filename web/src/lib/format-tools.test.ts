import { describe, expect, it } from "vitest"

import { formatDbDate, formatGoDuration } from "./format-tools"

describe("formatGoDuration", () => {
  it("turns a long Go duration into days", () => {
    expect(formatGoDuration("911h6m30.739902s")).toBe("37 days")
  })
  it("keeps short ages in hours or minutes", () => {
    expect(formatGoDuration("12h0m0s")).toBe("12 h")
    expect(formatGoDuration("35m10s")).toBe("35 min")
  })
})

describe("formatDbDate", () => {
  it("says never for the zero time", () => {
    expect(formatDbDate("0001-01-01T00:00:00Z")).toBe("never downloaded")
  })
})
