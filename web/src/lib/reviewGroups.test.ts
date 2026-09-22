import { describe, expect, it } from "vitest"

import type { DependencyResult, Signal } from "@/api/projects"
import { afterVectorOf, groupDependencies, groupOf, jumpKind, reasonFor } from "@/lib/reviewGroups"

function candidate(version: string, overrides: Partial<DependencyResult["candidates"][number]> = {}) {
  return {
    version,
    vector: [0, 0, 0, 0, 0],
    cves: [],
    signals: [] as Signal[],
    key: true,
    resolved: true,
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

describe("groupOf", () => {
  it("puts a dependency with no best candidate in nothing", () => {
    const dep = dependency({ vector: [0, 0, 0, 0, 0], best: undefined, candidates: [] })
    expect(groupOf(dep)).toBe("nothing")
  })

  it("puts a major jump in decide", () => {
    const dep = dependency({
      current: "4.17.1",
      best: "5.1.0",
      candidates: [candidate("5.1.0", { signals: [{ name: "major-jump", evidence: "leaves major version 4", blocking: false }] })],
    })
    expect(groupOf(dep)).toBe("decide")
  })

  it("puts a 0.x minor jump in decide even with no signal at all", () => {
    const dep = dependency({
      current: "0.21.1",
      best: "0.33.0",
      candidates: [candidate("0.33.0")],
    })
    expect(groupOf(dep)).toBe("decide")
  })

  it("puts any non-publisher signal in decide", () => {
    const dep = dependency({
      current: "4.17.1",
      best: "4.19.2",
      candidates: [candidate("4.19.2", { signals: [{ name: "install-script-added", evidence: "runs an install script", blocking: false }] })],
    })
    expect(groupOf(dep)).toBe("decide")
  })

  it("keeps a publisher-changed candidate in proposed: a grey note, not a warning", () => {
    const dep = dependency({
      current: "4.17.20",
      best: "4.18.1",
      candidates: [candidate("4.18.1", { signals: [{ name: "publisher-changed", evidence: "published by jdalton", blocking: false }] })],
    })
    expect(groupOf(dep)).toBe("proposed")
  })

  it("puts a plain minor or patch bump with no signal in proposed", () => {
    const dep = dependency({ current: "7.22.5", best: "7.23.2", candidates: [candidate("7.23.2")] })
    expect(groupOf(dep)).toBe("proposed")
  })
})

describe("groupDependencies", () => {
  it("matches the demo manifest's grouping: axios and esbuild decide, express, lodash and @babel/traverse proposed", () => {
    const axios = dependency({
      name: "axios",
      current: "0.21.1",
      best: "0.33.0",
      candidates: [candidate("0.33.0")],
    })
    const express = dependency({
      name: "express",
      current: "4.17.1",
      best: "4.22.3",
      candidates: [candidate("4.22.3")],
    })
    const lodash = dependency({
      name: "lodash",
      current: "4.17.20",
      best: "4.18.1",
      candidates: [candidate("4.18.1", { signals: [{ name: "publisher-changed", evidence: "published by jdalton", blocking: false }] })],
    })
    const babelTraverse = dependency({
      name: "@babel/traverse",
      current: "7.22.5",
      best: "7.23.2",
      candidates: [candidate("7.23.2")],
    })
    const esbuild = dependency({
      name: "esbuild",
      current: "0.17.19",
      best: "0.25.0",
      candidates: [candidate("0.25.0")],
    })

    const groups = groupDependencies([axios, express, lodash, babelTraverse, esbuild])

    expect(groups.decide.map((d) => d.name)).toEqual(["axios", "esbuild"])
    expect(groups.proposed.map((d) => d.name)).toEqual(["express", "lodash", "@babel/traverse"])
    expect(groups.nothing).toEqual([])
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
