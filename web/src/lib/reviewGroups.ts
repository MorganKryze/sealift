import type { Candidate, DependencyResult } from "@/api/projects"

export type ReviewGroupKey = "decide" | "proposed" | "nothing"

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

function bestCandidateOf(dependency: DependencyResult): Candidate | undefined {
  return dependency.candidates.find((candidate) => candidate.version === dependency.best)
}

/**
 * Buckets one dependency into the review's three groups, by sealift's own
 * proposal (dependency.best) rather than whatever the user has since
 * picked, so a row never jumps groups under the cursor. publisher-changed
 * is informational only (rank.Signal.Blocking never includes it) and never
 * sends a row to "to decide" on its own.
 */
export function groupOf(dependency: DependencyResult): ReviewGroupKey {
  if (!dependency.best) {
    return "nothing"
  }
  const best = bestCandidateOf(dependency)
  const notableSignal = best?.signals.some((signal) => signal.name !== "publisher-changed") ?? false
  if (notableSignal || jumpKind(dependency.current, dependency.best) !== "minor-or-patch") {
    return "decide"
  }
  return "proposed"
}

export function groupDependencies(dependencies: DependencyResult[]): Record<ReviewGroupKey, DependencyResult[]> {
  const groups: Record<ReviewGroupKey, DependencyResult[]> = { decide: [], proposed: [], nothing: [] }
  for (const dependency of dependencies) {
    groups[groupOf(dependency)].push(dependency)
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
