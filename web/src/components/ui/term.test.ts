import { describe, expect, it } from "vitest"

import { termSide } from "./term"

describe("termSide", () => {
  it("opens above a head term when the room above holds it, so the first row stays visible", () => {
    expect(termSide("above", { top: 400, bottom: 432 }, 900)).toBe("above")
  })

  it("falls back below when the room above is too short", () => {
    expect(termSide("above", { top: 80, bottom: 112 }, 900)).toBe("below")
  })

  it("opens above a term near the window's foot", () => {
    expect(termSide("below", { top: 800, bottom: 832 }, 900)).toBe("above")
    expect(termSide("below", { top: 300, bottom: 332 }, 900)).toBe("below")
  })
})
