import { describe, expect, it } from "vitest"

import type { DependencyResult } from "@/api/projects"

import { exportSelection } from "./exportSelection"

const dep = (name: string, current: string, best: string): DependencyResult =>
  ({ name, current, best, vector: [0, 0, 0, 0, 0], cves: [], candidates: [] }) as DependencyResult

describe("exportSelection", () => {
  const deps = [dep("axios", "0.21.1", "0.33.0"), dep("lodash", "4.17.20", "4.18.1"), dep("left-pad", "1.3.0", "")]

  it("takes sealift's proposal when nothing was stored, as in another browser or after a reload", () => {
    expect(exportSelection(deps, {})).toEqual({ axios: ["0.33.0"], lodash: ["4.18.1"] })
  })

  it("applies the user's picks over the proposal, and drops a dependency kept at its current version", () => {
    expect(exportSelection(deps, { axios: ["1.6.0"], lodash: [] })).toEqual({ axios: ["1.6.0"] })
  })
})
