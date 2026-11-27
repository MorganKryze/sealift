import { describe, expect, it } from "vitest"

import type { PipAnalysisResult, PipPackage } from "@/lib/pipReview"
import { pipCveTotals, pipGroups, pipNeededReasons, pipReasonsToSend, pipWaiting } from "@/lib/pipReview"

const target = { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" }
const wheel = (name: string, version: string) => ({ file: `${name}-${version}-py3-none-any.whl`, url: `https://files.example/${name}`, sha256: "a".repeat(64), size: 1000 })
const finding = (id: string, severity: string, fixedVersions: string[] = []) => ({ id, severity, fixedVersions })

function pkg(name: string, version: string, more: Partial<PipPackage> = {}): PipPackage {
  return { name, version, files: ["requirements.txt"], wheel: wheel(name, version), cves: [], ...more }
}
const previous = { projectId: "ledger", projectName: "ledger-service", exportId: "20261120T102000Z", analysisId: "20261120T101500Z", sealedAt: "2026-11-20T10:20:00Z" }

function resultOf(packages: PipPackage[], more: Partial<PipAnalysisResult> = {}): PipAnalysisResult {
  return { target, files: ["requirements.txt"], packages, blocking: [], warnings: [], previous, ...more }
}

// django jumps, ecdsa keeps a CVE no version fixes, requests is yanked, psycopg2 has no wheel, pillow
// changed its pin, attrs is new, jinja2 keeps a CVE a newer release fixes, idna did not move.
const crossing = resultOf([
  pkg("attrs", "24.2.0"),
  pkg("django", "5.1.4", { previous: { version: "4.2.16", cves: [finding("CVE-2024-45230", "HIGH", ["4.2.16"])], majorJump: true } }),
  pkg("ecdsa", "0.19.1", { cves: [finding("CVE-2024-23342", "HIGH")], previous: { version: "0.19.1", cves: [finding("CVE-2024-23342", "HIGH")], majorJump: false } }),
  pkg("idna", "3.10", { files: [], previous: { version: "3.10", cves: [], majorJump: false } }),
  pkg("jinja2", "3.1.4", { cves: [finding("CVE-2024-56201", "MEDIUM", ["3.1.5"])], previous: { version: "3.1.4", cves: [finding("CVE-2024-56201", "MEDIUM", ["3.1.5"])], majorJump: false } }),
  pkg("pillow", "10.4.0", { previous: { version: "10.2.0", cves: [finding("CVE-2024-28219", "HIGH", ["10.3.0"])], majorJump: false } }),
  pkg("psycopg2", "2.9.10", { wheel: undefined, previous: { version: "2.9.9", cves: [], majorJump: false } }),
  pkg("requests", "2.32.0", { yanked: { reason: "Yanked due to conflicts with CVE-2024-35195 mitigation" }, previous: { version: "2.32.0", cves: [], majorJump: false } }),
])
crossing.blocking = [{ name: "psycopg2", version: "2.9.10", kind: "source-only", detail: "source distribution only", pinnedAt: [{ file: "requirements.txt", line: 4 }] }]

const names = (list: PipPackage[]) => list.map((p) => p.name)

describe("pipGroups", () => {
  it("puts each package in one group, first match", () => {
    const groups = pipGroups(crossing)
    expect(names(groups["no-wheel"])).toEqual(["psycopg2"])
    expect(names(groups.reasons)).toEqual(["django", "ecdsa", "requests"])
    expect(names(groups.changed)).toEqual(["pillow"])
    expect(names(groups.added)).toEqual(["attrs"])
    expect(names(groups.fix)).toEqual(["jinja2"])
    expect(names(groups.unchanged)).toEqual(["idna"])
    expect(groups.packages).toEqual([])
    const all = Object.values(groups).flat().map((p) => p.name)
    expect(all.sort()).toEqual(names(crossing.packages).sort())
  })

  it("shows fix then packages with no previous crossing", () => {
    const first = resultOf([pkg("attrs", "24.2.0"), pkg("jinja2", "3.1.4", { cves: [finding("CVE-2024-56201", "MEDIUM", ["3.1.5"])] })], { previous: undefined })
    const groups = pipGroups(first)
    expect(names(groups.fix)).toEqual(["jinja2"])
    expect(names(groups.packages)).toEqual(["attrs"])
    expect(groups.added).toEqual([])
    expect(groups.unchanged).toEqual([])
  })
})

describe("pipNeededReasons", () => {
  it("puts a package in each reasons band it needs", () => {
    const both = resultOf([
      pkg("urllib3", "2.0.0", {
        cves: [finding("CVE-2025-0001", "LOW")],
        yanked: { reason: "" },
        previous: { version: "1.26.20", cves: [], majorJump: true },
      }),
    ])
    expect(pipNeededReasons(both)).toEqual([
      { kind: "major-jump", name: "urllib3", key: "major-jump:urllib3" },
      { kind: "cve-without-fix", name: "urllib3", key: "cve-without-fix:urllib3" },
      { kind: "yanked", name: "urllib3", key: "yanked:urllib3" },
    ])
  })

  it("asks per band in the set's order", () => {
    expect(pipNeededReasons(crossing).map((n) => n.key)).toEqual(["major-jump:django", "cve-without-fix:ecdsa", "yanked:requests"])
  })

  it("reads a fix of blank versions as no fix, as the server does", () => {
    const blank = resultOf([pkg("ecdsa", "0.19.1", { cves: [finding("CVE-2024-23342", "HIGH", [" "])] })])
    expect(pipNeededReasons(blank).map((n) => n.key)).toEqual(["cve-without-fix:ecdsa"])
  })

  it("reads a 0.7.0 analysis as a first crossing", () => {
    // pip-result.json as 0.7.0 writes it: no previous crossing, no yanked mark, no pin places; its yanked
    // release is a warning sentence.
    const legacy = {
      target,
      files: ["requirements.txt"],
      packages: [
        { name: "requests", version: "2.32.0", files: ["requirements.txt"], wheel: wheel("requests", "2.32.0"), cves: [] },
        { name: "jinja2", version: "3.1.4", files: [], wheel: wheel("jinja2", "3.1.4"), cves: [{ id: "CVE-2024-56201", severity: "MEDIUM", fixedVersions: ["3.1.5"], title: "jinja2: sandbox breakout" }] },
      ],
      blocking: [],
      warnings: ["requests==2.32.0 is yanked on the index: Yanked due to conflicts with CVE-2024-35195 mitigation"],
    } as PipAnalysisResult
    expect(pipNeededReasons(legacy)).toEqual([])
    const groups = pipGroups(legacy)
    expect(names(groups.fix)).toEqual(["jinja2"])
    expect(names(groups.packages)).toEqual(["requests"])
    expect(groups.changed).toEqual([])
    expect(pipCveTotals(legacy)).toEqual({ after: [0, 0, 1, 0, 0] })
  })
})

describe("pipCveTotals", () => {
  it("totals known CVEs before and after", () => {
    const left = resultOf([pkg("ecdsa", "0.19.1", { cves: [finding("CVE-2024-23342", "HIGH")], previous: { version: "0.19.0", cves: [finding("CVE-2024-23342", "HIGH"), finding("CVE-2023-0001", "CRITICAL", ["0.19.1"])], majorJump: false } })], {
      removed: [{ name: "py", version: "1.11.0", cves: [finding("CVE-2022-42969", "MEDIUM")] }],
    })
    expect(pipCveTotals(left)).toEqual({ before: [1, 1, 1, 0, 0], after: [0, 1, 0, 0, 0] })
  })

  it("counts an id once across packages", () => {
    const twice = resultOf([pkg("a", "1.0", { cves: [finding("CVE-1", "LOW")] }), pkg("b", "1.0", { cves: [finding("CVE-1", "LOW")] })], { previous: undefined })
    expect(pipCveTotals(twice)).toEqual({ after: [0, 0, 0, 1, 0] })
  })
})

describe("pipWaiting", () => {
  it("counts what needs you", () => {
    expect(pipWaiting(crossing, {})).toEqual({ noWheel: ["psycopg2"], missing: ["django", "ecdsa", "requests"] })
    const written = { "major-jump:django": "Moved in branch django-5", "cve-without-fix:ecdsa": "Verifies only", "yanked:requests": "  " }
    expect(pipWaiting(crossing, written)).toEqual({ noWheel: ["psycopg2"], missing: ["requests"] })
  })

  it("keeps a reason the archive refuses waiting", () => {
    expect(pipWaiting(crossing, { "major-jump:django": "two\nlines", "cve-without-fix:ecdsa": "ok", "yanked:requests": "ok" }).missing).toEqual(["django"])
  })
})

describe("pipReasonsToSend", () => {
  it("sends one reason per kind and package, trimmed", () => {
    const needed = pipNeededReasons(crossing)
    const texts = { "major-jump:django": " Moved in branch django-5 ", "cve-without-fix:ecdsa": "Verifies only", "yanked:requests": "Client tests run on 2.32.0" }
    expect(pipReasonsToSend(needed, texts)).toEqual([
      { kind: "major-jump", dependencies: ["django"], text: "Moved in branch django-5" },
      { kind: "cve-without-fix", dependencies: ["ecdsa"], text: "Verifies only" },
      { kind: "yanked", dependencies: ["requests"], text: "Client tests run on 2.32.0" },
    ])
  })
})
