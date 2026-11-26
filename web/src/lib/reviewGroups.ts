import type { AnalysisResult, DependencyResult } from "@/api/projects"

export type ReviewGroupKey = "reasons" | "updated" | "kept" | "unchanged"

export type JumpKind = "major" | "zero-minor" | "minor-or-patch"

interface VersionParts {
  major: number
  minor: number
}

function parseVersion(version: string): VersionParts | null {
  const match = /^(\d+)\.(\d+)/.exec(version)
  if (!match) {
    return null
  }
  return { major: Number(match[1]), minor: Number(match[2]) }
}

/**
 * Classifies the move from current to a candidate version. An unparseable
 * version counts as a major jump, the same conservative fallback
 * rank.JumpOf uses. Inside 0.x, semver makes no compatibility promise
 * between minor versions, so a 0.x minor bump gets the same "may break"
 * treatment as a major one even though it leaves major version 0 unchanged.
 */
export function jumpKind(current: string, version: string): JumpKind {
  const from = parseVersion(current)
  const to = parseVersion(version)
  if (!from || !to || from.major !== to.major) {
    return "major"
  }
  if (from.major === 0 && from.minor !== to.minor) {
    return "zero-minor"
  }
  return "minor-or-patch"
}

/** One vulnerability behind a dependency's or a candidate's counts. */
export type Cve = DependencyResult["cves"][number]

/** Dependencies whose jumps move together. */
export type Family = NonNullable<AnalysisResult["families"]>[number]

/**
 * The version an export holds for one dependency, as exportSelection reads
 * it: the proposal while the developer has not touched it, the first pick
 * otherwise, the current version for an empty pick.
 */
export function pickedOf(dependency: DependencyResult, selected: string[] | undefined): string {
  return selected === undefined ? dependency.best || dependency.current : (selected[0] ?? dependency.current)
}

/** The CVEs one version of a dependency keeps, its current version's when the analysis lists no such candidate. */
export function cvesOf(dependency: DependencyResult, version: string): Cve[] {
  return version === dependency.current ? dependency.cves : (dependency.candidates.find((c) => c.version === version)?.cves ?? dependency.cves)
}

/** What a CVE's record says about its fix. An analysis of sealift 0.7.0 kept none, so its fix is unknown. */
export function cveFix(cve: Cve): { kind: "fixed-in"; versions: string } | { kind: "none" } | { kind: "unknown" } {
  if (cve.fixedIn === undefined) {
    return { kind: "unknown" }
  }
  const versions = cve.fixedIn.trim()
  return versions === "" ? { kind: "none" } : { kind: "fixed-in", versions }
}

/** The family a dependency's jump belongs to, from the dependency or the analysis' family list. */
export function familyOf(dependency: DependencyResult, families: Family[]): Family | undefined {
  return families.find((family) => family.name === dependency.family) ?? families.find((family) => family.members.includes(dependency.name))
}

/**
 * The one group of the review a dependency sits in, first match: the
 * reasons block for a jump the selection takes, a member of a family that
 * jumps, or a held version that keeps a CVE with no known fix; then updated
 * for a version change inside the line; then kept on its major when the
 * analysis recorded a jump not taken; unchanged otherwise. families lists
 * the families the selection jumps. A publisher change is a fact on the row
 * and never moves it.
 */
export function groupOf(dependency: DependencyResult, selected: string[] | undefined, families: Family[]): ReviewGroupKey {
  const picked = pickedOf(dependency, selected)
  const moved = picked !== dependency.current
  const leaves = moved && (dependency.candidates.find((c) => c.version === picked)?.leavesLine ?? false)
  if (leaves || families.some((family) => family.members.includes(dependency.name))) {
    return "reasons"
  }
  if (cvesOf(dependency, picked).some((cve) => cveFix(cve).kind !== "fixed-in")) {
    return "reasons"
  }
  if (moved) {
    return "updated"
  }
  if (dependency.jump && dependency.candidates.some((c) => c.version === dependency.jump)) {
    return "kept"
  }
  return "unchanged"
}

/** The families whose jump the selection takes: one member's selected version leaving its line moves the family. */
function jumpingFamilies(dependencies: DependencyResult[], selection: Record<string, string[]>, families: Family[]): Family[] {
  const jumping: Family[] = []
  for (const dependency of dependencies) {
    const picked = pickedOf(dependency, selection[dependency.name])
    const leaves = picked !== dependency.current && dependency.candidates.find((c) => c.version === picked)?.leavesLine
    const family = familyOf(dependency, families)
    if (leaves && family && !jumping.includes(family)) {
      jumping.push(family)
    }
  }
  return jumping
}

/** Each dependency in its one group, in the analysis' order. */
export function groupDependencies(
  dependencies: DependencyResult[],
  selection: Record<string, string[]>,
  families: Family[],
): Record<ReviewGroupKey, DependencyResult[]> {
  const jumping = jumpingFamilies(dependencies, selection, families)
  const groups: Record<ReviewGroupKey, DependencyResult[]> = { reasons: [], updated: [], kept: [], unchanged: [] }
  for (const dependency of dependencies) {
    groups[groupOf(dependency, selection[dependency.name], jumping)].push(dependency)
  }
  return groups
}

function totalOf(vector: number[]): number {
  return vector.reduce((sum, count) => sum + count, 0)
}

/** Sums the vector sealift ships for each dependency: the pick if it differs from current, current's own vector otherwise. */
export function afterVectorOf(dependencies: DependencyResult[], pickedVersionOf: (dependency: DependencyResult) => string): number[] {
  return dependencies.reduce<number[]>(
    (total, dependency) => {
      const picked = pickedVersionOf(dependency)
      const vector =
        picked === dependency.current
          ? dependency.vector
          : (dependency.candidates.find((candidate) => candidate.version === picked)?.vector ?? dependency.vector)
      return total.map((count, index) => count + (vector[index] ?? 0))
    },
    [0, 0, 0, 0, 0],
  )
}

/** The reason line under a dependency's name: what the pick fixes, how large a jump it is, how old it is. */
export function reasonFor(dependency: DependencyResult, selectedVersion: string): string {
  if (selectedVersion === dependency.current) {
    return "Kept at the current version"
  }
  const candidate = dependency.candidates.find((c) => c.version === selectedVersion)
  if (!candidate) {
    return ""
  }
  const fixed = totalOf(dependency.vector) - totalOf(candidate.vector)
  const kind = jumpKind(dependency.current, selectedVersion)
  const jumpText = kind === "major" ? "major jump" : kind === "zero-minor" ? "0.x minor jump, may break" : "minor or patch"
  const plural = (n: number) => `${n} CVE${n === 1 ? "" : "s"}`
  const effect = fixed > 0 ? `Fixes ${plural(fixed)}` : fixed < 0 ? `Adds ${plural(-fixed)}` : "Fixes no CVE"
  return `${effect}, ${jumpText}`
}

/** Keeps the first entry of each CVE id: an analysis lists an id once per package it was found in, most severe first. */
export function distinctCves(cves: DependencyResult["cves"]): DependencyResult["cves"] {
  const seen = new Set<string>()
  return cves.filter((cve) => {
    if (seen.has(cve.id)) {
      return false
    }
    seen.add(cve.id)
    return true
  })
}
