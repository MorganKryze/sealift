import { describe, expect, it } from "vitest"

import type { DependencyResult, Signal } from "@/api/projects"
import { afterVectorOf, cveFix, distinctCves, groupDependencies, groupOf, jumpKind, reasonFor } from "@/lib/reviewGroups"

function candidate(version: string, overrides: Partial<DependencyResult["candidates"][number]> = {}) {
  return {
    version,
    vector: [0, 0, 0, 0, 0],
    cves: [],
    signals: [] as Signal[],
    key: true,
    resolved: true,
    leavesLine: false,
    ...overrides,
  }
}

function dependency(overrides: Partial<DependencyResult> = {}): DependencyResult {
  return {
    name: "left-pad",
    current: "1.0.0",
    vector: [0, 1, 0, 0, 0],
    cves: [],
    candidates: [],
    ...overrides,
  }
}

describe("jumpKind", () => {
  it("calls an unparseable version a major jump", () => {
    expect(jumpKind("1.0.0", "not-a-version")).toBe("major")
  })

  it("calls a different major version a major jump", () => {
    expect(jumpKind("4.17.1", "5.1.0")).toBe("major")
  })

  it("calls a 0.x minor bump zero-minor, even though the major stays 0", () => {
    expect(jumpKind("0.21.1", "0.33.0")).toBe("zero-minor")
  })

  it("calls a same-major minor or patch bump minor-or-patch", () => {
    expect(jumpKind("4.17.1", "4.22.3")).toBe("minor-or-patch")
    expect(jumpKind("4.17.20", "4.17.21")).toBe("minor-or-patch")
  })
})

const family = (name: string, members: string[]) => ({ name, members })

describe("groupOf", () => {
  it("puts each dependency in one group", () => {
    const deps = [
      dependency({ name: "react", current: "18.2.0", jump: "19.2.0", family: "react 19", candidates: [candidate("18.3.1"), candidate("19.2.0", { leavesLine: true })] }),
      dependency({ name: "react-dom", current: "18.2.0", jump: "19.2.0", family: "react 19", candidates: [candidate("18.3.1"), candidate("19.2.0", { leavesLine: true })] }),
      dependency({ name: "express", current: "4.17.1", best: "4.21.2", jump: "5.1.0", candidates: [candidate("4.21.2"), candidate("5.1.0", { leavesLine: true })] }),
      dependency({ name: "lodash", current: "4.17.20", best: "4.17.21", candidates: [candidate("4.17.21")] }),
      dependency({
        name: "html-minifier", current: "4.0.0", vector: [0, 1, 0, 0, 0], candidates: [],
        cves: [{ id: "CVE-2022-37620", severity: "HIGH", package: "html-minifier@4.0.0", fixedIn: "" }],
      }),
      dependency({ name: "left-pad", current: "1.3.0", vector: [0, 0, 0, 0, 0], candidates: [] }),
    ]
    const selection = { react: ["19.2.0"], "react-dom": ["19.2.0"], express: ["4.21.2"] }
    const groups = groupDependencies(deps, selection, [family("react 19", ["react", "react-dom"])])

    expect(groups.reasons.map((d) => d.name)).toEqual(["react", "react-dom", "html-minifier"])
    expect(groups.updated.map((d) => d.name)).toEqual(["express", "lodash"])
    expect(groups.kept.map((d) => d.name)).toEqual([])
    expect(groups.unchanged.map((d) => d.name)).toEqual(["left-pad"])
    const all = Object.values(groups).flat().map((d) => d.name)
    expect(all.sort()).toEqual(deps.map((d) => d.name).sort())
  })

  it("moves a recorded jump to the reasons block", () => {
    const esbuild = dependency({ name: "esbuild", current: "0.21.5", best: "0.21.5", jump: "0.25.12", candidates: [candidate("0.25.12", { leavesLine: true })] })
    expect(groupOf(esbuild, undefined, [])).toBe("kept")
    expect(groupOf(esbuild, ["0.25.12"], [])).toBe("reasons")
  })

  it("moves every member of a family that jumps, even one whose own version stays", () => {
    const react = dependency({ name: "react", current: "18.2.0", jump: "19.2.0", family: "react 19", candidates: [candidate("19.2.0", { leavesLine: true })] })
    const types = dependency({ name: "@types/react", current: "18.3.12", jump: "19.2.2", family: "react 19", candidates: [candidate("19.2.2", { leavesLine: true })] })
    const groups = groupDependencies([react, types], { react: ["19.2.0"], "@types/react": [] }, [family("react 19", ["@types/react", "react"])])
    expect(groups.reasons.map((d) => d.name)).toEqual(["react", "@types/react"])
  })

  it("keeps a jump not taken on its major", () => {
    const express = dependency({ name: "express", current: "4.17.1", jump: "5.1.0", vector: [0, 0, 0, 0, 0], candidates: [candidate("5.1.0", { leavesLine: true })] })
    expect(groupOf(express, [], [])).toBe("kept")
    expect(groupOf(express, undefined, [])).toBe("kept")
  })

  it("reads an analysis with no jump, family or fix", () => {
    const old = dependency({
      name: "angular", current: "1.8.3", vector: [0, 1, 10, 0, 0], candidates: [candidate("2.0.0", { leavesLine: true })],
      cves: [{ id: "CVE-2024-21490", severity: "HIGH" }],
    })
    const plain = dependency({ name: "chalk", current: "4.1.2", vector: [0, 0, 0, 0, 0], candidates: [candidate("5.3.0", { leavesLine: true })] })
    const groups = groupDependencies([old, plain], {}, [])
    expect(groups.reasons.map((d) => d.name)).toEqual(["angular"])
    expect(groups.kept).toEqual([])
    expect(groups.unchanged.map((d) => d.name)).toEqual(["chalk"])
    expect(cveFix(old.cves[0])).toEqual({ kind: "unknown" })
    expect(cveFix({ id: "CVE-2022-37620", severity: "HIGH", fixedIn: " " })).toEqual({ kind: "none" })
    expect(cveFix({ id: "CVE-2024-29041", severity: "HIGH", fixedIn: "4.19.2, 5.0.0" })).toEqual({ kind: "fixed-in", versions: "4.19.2, 5.0.0" })
  })

  it("keeps a publisher change on an update: a fact, never a reason", () => {
    const lodash = dependency({
      name: "lodash", current: "4.17.20", best: "4.18.1",
      candidates: [candidate("4.18.1", { signals: [{ name: "publisher-changed", evidence: "published by jdalton", blocking: false }] })],
    })
    expect(groupOf(lodash, undefined, [])).toBe("updated")
  })
})

describe("afterVectorOf", () => {
  it("sums the picked candidate's vector for a changed dependency and the current vector otherwise", () => {
    const kept = dependency({ vector: [0, 1, 0, 0, 0] })
    const changed = dependency({
      current: "1.0.0",
      vector: [0, 2, 0, 0, 0],
      candidates: [candidate("2.0.0", { vector: [0, 0, 0, 0, 0] })],
    })

    const after = afterVectorOf([kept, changed], (d) => (d === kept ? d.current : "2.0.0"))

    expect(after).toEqual([0, 1, 0, 0, 0])
  })
})

describe("reasonFor", () => {
  it("says kept when the selection is the current version", () => {
    expect(reasonFor(dependency(), "1.0.0")).toBe("Kept at the current version")
  })

  it("counts fixed CVEs and names the jump kind", () => {
    const dep = dependency({
      current: "4.17.1",
      vector: [0, 2, 0, 0, 0],
      candidates: [candidate("4.22.3", { vector: [0, 0, 0, 0, 0] })],
    })
    expect(reasonFor(dep, "4.22.3")).toBe("Fixes 2 CVEs, minor or patch")
  })

  it("says a pick adds CVEs instead of fixing a negative number", () => {
    const dep = dependency({
      current: "0.21.1",
      vector: [0, 1, 0, 0, 0],
      candidates: [candidate("1.6.0", { vector: [0, 3, 3, 0, 0] })],
    })
    expect(reasonFor(dep, "1.6.0")).toBe("Adds 5 CVEs, major jump")
  })

  it("says when a pick changes no CVE count", () => {
    const dep = dependency({
      current: "4.17.1",
      vector: [0, 1, 0, 0, 0],
      candidates: [candidate("4.17.3", { vector: [0, 1, 0, 0, 0] })],
    })
    expect(reasonFor(dep, "4.17.3")).toBe("Fixes no CVE, minor or patch")
  })
})

describe("distinctCves", () => {
  it("lists an id found in two packages once, with its first entry", () => {
    const cves = [
      { id: "CVE-2021-23337", severity: "HIGH", package: "lodash@4.17.20", fixedIn: "4.17.21" },
      { id: "CVE-2021-23337", severity: "HIGH", package: "lodash.template@4.5.0", fixedIn: "" },
      { id: "CVE-2020-8203", severity: "HIGH", package: "lodash@4.17.20", fixedIn: "4.17.19" },
    ]
    expect(distinctCves(cves)).toEqual([cves[0], cves[2]])
  })
})
