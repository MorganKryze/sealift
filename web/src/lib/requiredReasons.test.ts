import { describe, expect, it } from "vitest"

import type { AnalysisResult, Candidate, DependencyResult } from "@/api/projects"
import { missingReasons, reasonKey, reasonProblem, reasonsToSend, requiredReasons, type NeededReason } from "@/lib/requiredReasons"

function candidate(version: string, overrides: Partial<Candidate> = {}): Candidate {
  return { version, vector: [0, 0, 0, 0, 0], cves: [], signals: [], key: true, resolved: true, leavesLine: false, ...overrides }
}

function dependency(overrides: Partial<DependencyResult> & { name: string; current: string }): DependencyResult {
  return { vector: [0, 0, 0, 0, 0], cves: [], candidates: [], ...overrides }
}

function result(dependencies: DependencyResult[], families: AnalysisResult["families"] = []): AnalysisResult {
  return {
    target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" },
    before: [0, 0, 0, 0, 0],
    dependencies,
    warnings: [],
    families,
  }
}

const react = dependency({
  name: "react", current: "18.2.0", jump: "19.2.0", family: "react 19",
  candidates: [candidate("18.3.1"), candidate("19.2.0", { leavesLine: true })],
})
const reactDOM = dependency({
  name: "react-dom", current: "18.2.0", jump: "19.2.0", family: "react 19",
  candidates: [candidate("18.3.1"), candidate("19.2.0", { leavesLine: true })],
})
const typesReact = dependency({
  name: "@types/react", current: "18.3.12", jump: "19.2.0", family: "react 19",
  candidates: [candidate("19.2.0", { leavesLine: true })],
})
const express = dependency({
  name: "express", current: "4.17.1", best: "4.21.2", jump: "5.1.0", vector: [0, 1, 0, 0, 0],
  cves: [{ id: "CVE-2024-29041", severity: "HIGH", package: "express@4.17.1", fixedIn: "4.19.2, 5.0.0" }],
  candidates: [candidate("4.21.2"), candidate("5.1.0", { leavesLine: true })],
})
const htmlMinifier = dependency({
  name: "html-minifier", current: "4.0.0", vector: [0, 0, 1, 0, 0],
  cves: [{ id: "CVE-2022-37620", severity: "MEDIUM", package: "html-minifier@4.0.0", fixedIn: "" }],
})
const reactFamily = [{ name: "react 19", members: ["@types/react", "react", "react-dom"] }]

describe("requiredReasons", () => {
  it("asks one reason per family of selected jumps", () => {
    const needed = requiredReasons(result([react, reactDOM, typesReact], reactFamily), {
      react: ["19.2.0"], "react-dom": ["19.2.0"], "@types/react": ["19.2.0"],
    })
    expect(needed).toEqual([
      {
        kind: "major-jump",
        dependencies: ["react", "react-dom", "@types/react"],
        label: "react 19",
        detail: "react 18.2.0 to 19.2.0, react-dom 18.2.0 to 19.2.0, @types/react 18.3.12 to 19.2.0",
      },
    ])
  })

  it("asks one per lone jump", () => {
    const needed = requiredReasons(result([express, react], reactFamily), { express: ["5.1.0"], react: ["18.3.1"] })
    expect(needed).toEqual([{ kind: "major-jump", dependencies: ["express"], label: "express", detail: "express 4.17.1 to 5.1.0" }])
  })

  it("asks one per dependency whose kept version carries a CVE without fix", () => {
    const sass = dependency({
      name: "sass", current: "1.0.0",
      candidates: [candidate("1.2.0", { cves: [{ id: "CVE-2025-0001", severity: "LOW", package: "sass@1.2.0", fixedIn: "" }] })],
    })
    const needed = requiredReasons(result([htmlMinifier, sass]), { sass: ["1.2.0"] })
    expect(needed).toEqual([
      {
        kind: "cve-without-fix", dependencies: ["html-minifier"], label: "html-minifier",
        detail: "html-minifier 4.0.0 keeps CVE-2022-37620, with no known fix",
      },
      { kind: "cve-without-fix", dependencies: ["sass"], label: "sass", detail: "sass 1.2.0 keeps CVE-2025-0001, with no known fix" },
    ])
  })

  it("counts an unknown fix as none", () => {
    const old = dependency({ name: "minimist", current: "0.0.8", cves: [{ id: "CVE-2021-44906", severity: "CRITICAL" }] })
    const needed = requiredReasons(result([old]), {})
    expect(needed.map((n) => [n.kind, n.label])).toEqual([["cve-without-fix", "minimist"]])
  })

  it("asks nothing for a CVE fixed in another line", () => {
    expect(requiredReasons(result([express]), {})).toEqual([])
  })

  it("asks nothing for the proposal alone when it stays in the line", () => {
    expect(requiredReasons(result([express, react], reactFamily), { express: ["4.21.2"], react: ["18.3.1"] })).toEqual([])
  })

  it("asks a name listed twice once, for what either of its entries needs", () => {
    const devExpress = { ...express, current: "5.1.0", best: undefined, jump: undefined, cves: [htmlMinifier.cves[0]], candidates: [] }
    const needed = requiredReasons(result([express, devExpress]), { express: ["5.1.0"] })
    expect(needed.map((n) => `${n.kind} ${n.dependencies.join(",")}`)).toEqual(["major-jump express", "cve-without-fix express"])
  })
})

describe("reasonProblem", () => {
  it("accepts one plain line", () => {
    expect(reasonProblem("needs React 19 for the new compiler")).toBeUndefined()
  })

  it.each([
    ["a line break", "first line\nsecond line"],
    ["a tab", "a\treason"],
    ["a line separator", "a\u2028reason"],
    ["a bidirectional override", "a\u202ereason"],
  ])("refuses %s", (_name, text) => {
    expect(reasonProblem(text)).toBe("Keep the reason on one line, with no tab or control character.")
  })

  it("counts characters once trimmed", () => {
    expect(reasonProblem(` ${"é".repeat(300)} `)).toBeUndefined()
    expect(reasonProblem("é".repeat(301))).toBe("Shorten the reason to 300 characters: it has 301.")
  })
})

describe("missingReasons", () => {
  const needed: NeededReason[] = [
    { kind: "major-jump", dependencies: ["react"], label: "react 19", detail: "" },
    { kind: "cve-without-fix", dependencies: ["html-minifier"], label: "html-minifier", detail: "" },
  ]

  it("names each reason left empty or unreadable", () => {
    expect(missingReasons(needed, {})).toBe("2 reasons missing: react 19, html-minifier")
    expect(missingReasons(needed, { [reasonKey(needed[0])]: "  ", [reasonKey(needed[1])]: "a\nb" })).toBe(
      "2 reasons missing: react 19, html-minifier",
    )
    expect(missingReasons(needed, { [reasonKey(needed[0])]: "ok" })).toBe("1 reason missing: html-minifier")
  })

  it("names five and counts the rest", () => {
    const many: NeededReason[] = Array.from({ length: 18 }, (_, i) => ({ kind: "cve-without-fix", dependencies: [`p${i}`], label: `p${i}`, detail: "" }))
    expect(missingReasons(many, {})).toBe("18 reasons missing: p0, p1, p2, p3, p4 and 13 more")
  })

  it("is empty once every reason is written", () => {
    expect(missingReasons(needed, { [reasonKey(needed[0])]: "ok", [reasonKey(needed[1])]: "dev only" })).toBe("")
  })
})

describe("reasonsToSend", () => {
  it("sends each needed reason trimmed, with its kind and dependencies", () => {
    const needed: NeededReason[] = [{ kind: "major-jump", dependencies: ["react", "react-dom"], label: "react 19", detail: "" }]
    expect(reasonsToSend(needed, { [reasonKey(needed[0])]: " the compiler needs 19 " })).toEqual([
      { kind: "major-jump", dependencies: ["react", "react-dom"], text: "the compiler needs 19" },
    ])
  })
})
