import { describe, expect, it } from "vitest"

import type { ReportPackage } from "./outcome"
import { causeOf, causeWords, copyRequest, nexusPath, nextAction } from "./kinds"

describe("next action per kind", () => {
  it.each([
    ["interrupted", "as-is", /Retry the import/],
    ["source", "as-is", /Retry the import/],
    ["conflict", "change-first", /delete it in Nexus.*then retry/i],
    ["mismatch", "change-first", /Export the archive again/],
    ["nexus", "change-first", /import account may upload.*then retry/i],
    ["local", "change-first", /Ask the administrator.*data volume.*settings file/i],
  ])("%s is in group %s", (kind, group, words) => {
    const got = nextAction(kind)
    expect(got.group).toBe(group)
    expect(got.words).toMatch(words)
  })

  it.each([[undefined], [""], ["something-new"]])("no known kind (%s) gives the general words", (kind) => {
    expect(nextAction(kind)).toEqual({ group: "unknown", words: "Read the reason: it names what failed. Fix that, then retry." })
  })
})

const mb = (n: number) => Math.round(n * 1024 * 1024)
const failed = (over: Partial<ReportPackage>): ReportPackage => ({ name: "left-pad", version: "1.3.0", file: "left-pad-1.3.0.tgz", state: "failed", reason: "r", note: "", ...over })

describe("cause per failed package", () => {
  it.each([
    [{ kind: "nexus" }, "no-answer", "No answer from Nexus", "warn", true],
    [{ kind: "nexus", nexusStatus: 413 }, "too-large", "Too large for Nexus", "failure", false],
    [{ kind: "nexus", nexusStatus: 500 }, "refused", "Nexus refused it", "warn", true],
    [{ kind: "conflict" }, "conflict", "Another file under the same version", "failure", false],
    [{ kind: "source" }, "source", "Could not read the archive from MinIO", "warn", true],
    [{ kind: "interrupted" }, "interrupted", "Stopped before it was published", "warn", true],
    [{ kind: "mismatch" }, "mismatch", "Not the package the manifest names", "failure", false],
    [{ kind: "local" }, "local", "Failed on this side", "warn", true],
    [{}, "unknown", "Not in Nexus", "warn", true],
  ] as const)("%o is %s", (over, cause, title, tone, retry) => {
    expect(causeOf(failed(over as Partial<ReportPackage>))).toBe(cause)
    expect(causeWords(cause)).toEqual({ title, tone, retry })
  })

  it("reads a package with no kind and a 0.4.0 interrupted reason as stopped", () => {
    expect(causeOf(failed({ reason: "interrupted" }))).toBe("interrupted")
    expect(causeOf(failed({ state: "pending", reason: "" }))).toBe("interrupted")
  })

  it("reads 413 as too large on a nexus failure only", () => {
    expect(causeOf(failed({ kind: "conflict", nexusStatus: 413 }))).toBe("conflict")
  })
})

describe("what a cause copies", () => {
  it("asks to raise the limit above the largest refused file, to the instance's contact", () => {
    const files = [failed({ file: "a.whl", size: mb(16.3) }), failed({ file: "torch.whl", size: mb(906.4) })]
    expect(copyRequest("pypi-hosted", files, undefined)).toBe("Raise the upload limit of pypi-hosted above 906.4 MB: a.whl, torch.whl were refused as too large.")
    expect(copyRequest("npm-hosted", [failed({ file: "swc.tgz", size: mb(118.2) })], "Platform team")).toBe("To Platform team: Raise the upload limit of npm-hosted above 118.2 MB: swc.tgz was refused as too large.")
  })

  it("gives a component's path in the repository", () => {
    expect(nexusPath(failed({ name: "@types/node", version: "22.10.2" }), "npm")).toBe("@types/node/-/node-22.10.2.tgz")
    expect(nexusPath(failed({ name: "is-number", version: "7.0.0" }), "npm")).toBe("is-number/-/is-number-7.0.0.tgz")
    expect(nexusPath(failed({ name: "PyYAML", version: "6.0.2", file: "PyYAML-6.0.2-py3-none-any.whl" }), "pip")).toBe("packages/pyyaml/6.0.2/PyYAML-6.0.2-py3-none-any.whl")
  })
})
