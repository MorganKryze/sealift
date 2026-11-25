import { describe, expect, it } from "vitest"

import { dbDateTitle, formatDbDate, formatGoDuration } from "./format-tools"

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
  const now = Date.parse("2026-11-25T14:00:00Z")
  it("reads relative within a week", () => {
    expect(formatDbDate("2026-11-25T09:00:00Z", now)).toBe("5 hours ago")
    expect(formatDbDate("2026-11-25T13:58:00Z", now)).toBe("2 minutes ago")
    expect(formatDbDate("2026-11-22T14:00:00Z", now)).toBe("3 days ago")
  })
  it("reads as a day past a week, with the year outside the current one", () => {
    expect(formatDbDate("2026-11-12T06:00:00Z", now)).toBe("12 Nov")
    expect(formatDbDate("2025-03-14T06:00:00Z", now)).toBe("14 Mar 2025")
  })
  it("gives the whole date and time for a title", () => {
    expect(dbDateTitle("2026-11-25T09:00:00Z")).toMatch(/25 Nov 2026/)
    expect(dbDateTitle("0001-01-01T00:00:00Z")).toBe("")
  })
})
