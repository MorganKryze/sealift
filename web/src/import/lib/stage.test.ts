import { describe, expect, it } from "vitest"

import type { Attempt, ReportPackage } from "./outcome"
import { stageOf } from "./stage"

const pkg: ReportPackage = { name: "left-pad", version: "1.3.0", file: "npm/left-pad-1.3.0.tgz", state: "pending", reason: "", note: "" }

function attempt(status: string, packages: ReportPackage[], archiveChecked?: boolean): Attempt {
  return {
    n: 1, status, outcome: status === "ended" ? "incomplete" : "",
    report: {
      outcome: "", reason: "", unencrypted: false, importVersion: "", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages, archiveChecked,
    },
  }
}

describe("stage of an attempt", () => {
  it.each([
    ["queued", attempt("queued", []), "waiting"],
    ["running with no package listed", attempt("running", []), "manifest"],
    ["running with packages and the checks not passed", attempt("running", [pkg], false), "checks"],
    ["running with packages and no record of the checks", attempt("running", [pkg]), "checks"],
    ["running with packages and the checks passed", attempt("running", [pkg], true), "publishing"],
    ["ended", attempt("ended", [pkg], true), "ended"],
    ["a v0.4.0 record that ended, with no archiveChecked", attempt("ended", [pkg]), "ended"],
    ["an ended attempt that listed no package", attempt("ended", [], false), "ended"],
  ])("is %s", (_name, a, want) => {
    expect(stageOf(a)).toBe(want)
  })
})
