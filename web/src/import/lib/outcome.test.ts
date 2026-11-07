import { CircleAlert, CircleCheck, CirclePause, Clock, LoaderCircle, ShieldX } from "lucide-react"
import { describe, expect, it } from "vitest"

import type { Attempt, Import, ReportPackage } from "./outcome"
import { archiveName, counts, latestAttempt, notFinished, outcomeWords } from "./outcome"

const pkg = (over: Partial<ReportPackage> = {}): ReportPackage => ({
  name: "left-pad", version: "1.3.0", file: "npm/left-pad-1.3.0.tgz", state: "published", reason: "", note: "", ...over,
})

const attempt = (packages: ReportPackage[], over: Partial<Attempt> = {}): Attempt => ({
  n: 1, status: "ended", outcome: "incomplete",
  report: {
    outcome: "", reason: "", unencrypted: false, importVersion: "0.5.0",
    archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
    target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" },
    nexus: { url: "", repository: "" }, counts: { published: 0, present: 0, failed: 0 }, packages,
  },
  ...over,
})

describe("outcomeWords", () => {
  it.each([
    ["queued", "Queued", Clock, "waiting"],
    ["running", "Running", LoaderCircle, "progress"],
    ["complete", "Complete", CircleCheck, "done"],
    ["incomplete", "Incomplete", CircleAlert, "failure"],
    ["refused", "Refused", ShieldX, "failure"],
    ["interrupted", "Interrupted", CirclePause, "failure"],
  ])("%s reads %s with its own icon", (outcome, label, icon, tone) => {
    expect(outcomeWords(outcome)).toEqual({ label, icon, tone })
  })

  it("names an outcome it does not know instead of guessing", () => {
    expect(outcomeWords("exploded").label).toBe("Not recorded")
  })
})

describe("notFinished", () => {
  it.each([
    ["kind interrupted", pkg({ state: "failed", kind: "interrupted", reason: "the service stopped" }), true],
    ["no kind, reason interrupted", pkg({ state: "failed", reason: "interrupted" }), true],
    ["no kind, reason not reached", pkg({ state: "failed", reason: "not reached" }), true],
    ["a plain failure", pkg({ state: "failed", kind: "nexus", reason: "Nexus answered 500" }), false],
    ["a failure with no kind and another reason", pkg({ state: "failed", reason: "connection refused" }), false],
    ["kind nexus whose reason says interrupted", pkg({ state: "failed", kind: "nexus", reason: "interrupted" }), false],
    ["a published package", pkg({ state: "published" }), false],
  ])("%s", (_name, p, want) => {
    expect(notFinished(p)).toBe(want)
  })
})

describe("counts", () => {
  it("counts published, present, failed, not finished and pending apart", () => {
    const a = attempt([
      pkg({ state: "published" }), pkg({ state: "published" }), pkg({ state: "present" }),
      pkg({ state: "failed", kind: "nexus", reason: "x" }),
      pkg({ state: "failed", kind: "interrupted", reason: "interrupted" }),
      pkg({ state: "failed", reason: "not reached" }),
      pkg({ state: "pending" }), pkg({ state: "pending" }),
    ])
    expect(counts(a)).toEqual({ published: 2, present: 1, failed: 1, notFinished: 2, pending: 2, done: 4, total: 8 })
  })

  it("is all zero for an attempt that listed nothing", () => {
    expect(counts(attempt([]))).toEqual({ published: 0, present: 0, failed: 0, notFinished: 0, pending: 0, done: 0, total: 0 })
  })
})

describe("latestAttempt", () => {
  const imp = (attempts: Attempt[]) => ({ attempts }) as unknown as Import

  it("is the last attempt", () => {
    expect(latestAttempt(imp([attempt([], { n: 1 }), attempt([], { n: 2 })])).n).toBe(2)
  })

  it("is a queued first attempt when the record lists none", () => {
    const a = latestAttempt(imp([]))
    expect(a.n).toBe(1)
    expect(a.status).toBe("queued")
    expect(a.report.packages).toEqual([])
  })
})

describe("archiveName", () => {
  it("splits one folder below packages/npm/", () => {
    expect(archiveName("packages/npm/2026-11-05-hr-forms/packages_npm.tar.gz")).toEqual({
      folder: "2026-11-05-hr-forms/", file: "packages_npm.tar.gz",
    })
  })

  it("names packages/npm/ as the folder of an archive at the root", () => {
    expect(archiveName("packages/npm/packages_npm.tar.gz")).toEqual({ folder: "packages/npm/", file: "packages_npm.tar.gz" })
  })

  it("keeps every byte of a 1,024-byte key", () => {
    const folder = "f".repeat(1024 - "packages/npm/".length - "/".length - "packages_npm.tar.gz".length)
    const key = `packages/npm/${folder}/packages_npm.tar.gz`
    expect(key).toHaveLength(1024)
    const name = archiveName(key)
    expect(name.folder).toBe(`${folder}/`)
    expect(name.file).toBe("packages_npm.tar.gz")
  })
})
