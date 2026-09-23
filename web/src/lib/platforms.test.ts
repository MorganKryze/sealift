import { describe, expect, it } from "vitest"

import { PLATFORMS, platformIdOf, targetOf } from "./platforms"

describe("platforms", () => {
  it("names the target sealift ships by default", () => {
    expect(platformIdOf({ os: "linux", cpu: "x64", libc: "glibc" })).toBe("linux-x64-glibc")
  })

  it("maps every choice back to the same os, cpu and libc", () => {
    for (const platform of PLATFORMS) {
      expect(platformIdOf(targetOf(platform.id)!)).toBe(platform.id)
    }
  })

  it("keeps a saved target that is not on the list instead of replacing it", () => {
    expect(platformIdOf({ os: "darwin", cpu: "arm64", libc: "" })).toBeUndefined()
  })
})
