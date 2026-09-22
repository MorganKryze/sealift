import { describe, expect, it } from "vitest"

import { ManifestPreviewError, parseManifestPreview } from "./manifestPreview"

const problems = (json: object) => parseManifestPreview(JSON.stringify(json), "x").problems.map((p) => `${p.where}: ${p.reason}`)

describe("parseManifestPreview", () => {
  it("finds no problem in an exactly pinned manifest", () => {
    expect(problems({ dependencies: { lodash: "4.17.20" }, devDependencies: { esbuild: "0.17.19" } })).toEqual([])
  })

  it("lists every problem the server would refuse, before anything is uploaded", () => {
    expect(
      problems({
        dependencies: { lodash: "^4.17.1", "left-pad": "npm:left-pad@1.3.0", local: "file:../local" },
        optionalDependencies: { fsevents: "2.3" },
        overrides: { qs: "6.11.0" },
        pnpm: { overrides: { qs: "6.11.0" } },
      }),
    ).toEqual([
      "overrides: not supported",
      "pnpm.overrides: not supported",
      "lodash ^4.17.1: version must be exact, such as 1.2.3",
      "left-pad npm:left-pad@1.3.0: only npm registry versions are supported",
      "local file:../local: only npm registry versions are supported",
      "fsevents 2.3: version must be exact, such as 1.2.3",
    ])
  })

  it("refuses a manifest with no dependency", () => {
    expect(problems({ name: "empty" })).toEqual(["dependencies: lists no dependency to update"])
  })

  it("refuses JSON that is not an object", () => {
    expect(() => parseManifestPreview('["lodash"]', "x")).toThrow(ManifestPreviewError)
  })
})
