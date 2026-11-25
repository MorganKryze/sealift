import { describe, expect, it } from "vitest"

import { initials } from "@/import/lib/places"

describe("initials", () => {
  it("takes the first letter of two parts, else the first two letters", () => {
    expect(initials("l.martin")).toBe("LM")
    expect(initials("alice")).toBe("AL")
    expect(initials("jo")).toBe("JO")
    expect(initials("anne_marie-dupont")).toBe("AM")
  })
})
