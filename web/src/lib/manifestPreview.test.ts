import { describe, expect, it } from "vitest"

import { failingChecks, ManifestPreviewError, parseManifestPreview } from "./manifestPreview"

const read = (json: object) => parseManifestPreview(JSON.stringify(json), "x")
const check = (json: object, id: "exact" | "registry" | "fields") => read(json).checks.find((c) => c.id === id)

describe("parseManifestPreview", () => {
  it("names three checks with their evidence", () => {
    const preview = read({ name: "web-portal", dependencies: { lodash: "4.17.20", react: "18.3.1" }, devDependencies: { esbuild: "0.17.19" } })
    expect(preview.name).toBe("web-portal")
    expect(preview.checks.map((c) => [c.id, c.label, c.passed, c.evidence])).toEqual([
      ["exact", "Exact versions", true, "3 of 3 pinned"],
      ["registry", "Registry only", true, "3 of 3 on npm"],
      ["fields", "Supported fields", true, "dependencies · devDependencies"],
    ])
    expect(failingChecks(preview)).toEqual([])
  })

  it("counts ranges and lists each with its written value", () => {
    const exact = check({ dependencies: { express: "^4.18.2", lodash: "~4.17.21", pino: ">=9.0.0", react: "18.3.1" } }, "exact")
    expect(exact?.passed).toBe(false)
    expect(exact?.evidence).toBe("3 of 4 are ranges")
    expect(exact?.fix).toBe("Write the version you run, such as 4.18.2.")
    expect(exact?.offenders).toEqual([
      { name: "express", value: "^4.18.2" },
      { name: "lodash", value: "~4.17.21" },
      { name: "pino", value: ">=9.0.0" },
    ])
  })

  it("counts versions off the npm registry", () => {
    const json = {
      dependencies: { "@billing/shared-schemas": "git+ssh://git@gitlab.example.com/billing/shared-schemas.git#v3.2.0", "pdf-templates": "file:../pdf-templates", react: "18.3.1" },
      optionalDependencies: { "left-pad": "npm:left-pad@1.3.0" },
    }
    const registry = check(json, "registry")
    expect(registry?.passed).toBe(false)
    expect(registry?.evidence).toBe("3 of 4 off npm")
    expect(registry?.fix).toBe("This instance fetches from npm only; use a published version for each.")
    expect(registry?.offenders.map((o) => o.name)).toEqual(["@billing/shared-schemas", "pdf-templates", "left-pad"])
    // A version off npm is not counted again as a range.
    expect(check(json, "exact")?.passed).toBe(true)
  })

  it("names an unsupported field and its keys", () => {
    const fields = check({ dependencies: { react: "18.3.1" }, pnpm: { overrides: { semver: "7.5.4", "tough-cookie": "4.1.3", ws: "8.17.1" } } }, "fields")
    expect(fields?.passed).toBe(false)
    expect(fields?.evidence).toBe("1 field not supported")
    expect(fields?.fix).toBe("This instance resolves without overrides; remove the field.")
    expect(fields?.offenders).toEqual([{ name: "pnpm.overrides", value: "semver, tough-cookie, ws" }])

    const two = check({ dependencies: { react: "18.3.1" }, overrides: { qs: "6.11.0" }, resolutions: { qs: "6.11.0" } }, "fields")
    expect(two?.evidence).toBe("2 fields not supported")
    expect(two?.fix).toBe("This instance resolves without overrides; remove these fields.")
    expect(failingChecks(read({ dependencies: { express: "^4.18.2" }, overrides: {} })).map((c) => c.id)).toEqual(["exact", "fields"])
  })

  it("refuses a file with no dependency", () => {
    expect(() => read({ name: "empty" })).toThrow(ManifestPreviewError)
    expect(() => parseManifestPreview('["lodash"]', "x")).toThrow(ManifestPreviewError)
    expect(() => parseManifestPreview("{", "x")).toThrow(ManifestPreviewError)
  })
})
