import type { components } from "@/api/schema"
import { reasonProblem } from "@/lib/requiredReasons"

export type PipAnalysisResult = components["schemas"]["PipAnalysisResult"]
export type PipPackage = components["schemas"]["PipPackage"]
export type PipFinding = components["schemas"]["PipFinding"]
type Reason = components["schemas"]["Reason"]

export type PipReasonKind = "major-jump" | "cve-without-fix" | "yanked"
/** One reason a pip export asks: one per kind and package. */
export interface PipNeededReason {
  kind: PipReasonKind
  name: string
  /** Where its text lives in useReasons: `${kind}:${name}`. */
  key: string
}
export type PipGroupKey = "no-wheel" | "reasons" | "changed" | "added" | "fix" | "unchanged" | "packages"

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
const KINDS: PipReasonKind[] = ["major-jump", "cve-without-fix", "yanked"]

/** A CVE no version fixes, or whose fixing versions are all blank, as the server reads it. */
export function withoutFix(cve: PipFinding): boolean {
  return !cve.fixedVersions.some((v) => v.trim() !== "")
}

function needs(pkg: PipPackage, kind: PipReasonKind): boolean {
  if (kind === "major-jump") return pkg.previous?.majorJump === true
  if (kind === "cve-without-fix") return pkg.cves.some(withoutFix)
  return pkg.yanked !== undefined
}

/**
 * The reasons a pip export needs, band by band (major jumps, CVEs with no fix, yanked releases), each in
 * the set's order. A field an analysis from 0.7.0 lacks asks nothing.
 */
export function pipNeededReasons(result: PipAnalysisResult): PipNeededReason[] {
  return KINDS.flatMap((kind) => result.packages.filter((pkg) => needs(pkg, kind)).map((pkg) => ({ kind, name: pkg.name, key: `${kind}:${pkg.name}` })))
}

/** A package the target cannot install: it has no wheel, or the blocking list names it. */
function noWheel(result: PipAnalysisResult, pkg: PipPackage): boolean {
  return !pkg.wheel || result.blocking.some((b) => b.name === pkg.name)
}

/**
 * Each package of the set in one group, first match: no wheel, a reason needed, a pin changed since the
 * previous crossing, added since it, a known CVE a newer release fixes, then unchanged. With no previous
 * crossing recorded, the last two are fix and "packages".
 */
export function pipGroups(result: PipAnalysisResult): Record<PipGroupKey, PipPackage[]> {
  const groups: Record<PipGroupKey, PipPackage[]> = { "no-wheel": [], reasons: [], changed: [], added: [], fix: [], unchanged: [], packages: [] }
  const compared = result.previous !== undefined
  for (const pkg of result.packages) {
    const key: PipGroupKey = noWheel(result, pkg)
      ? "no-wheel"
      : KINDS.some((kind) => needs(pkg, kind))
        ? "reasons"
        : compared && pkg.previous && pkg.previous.version !== pkg.version
          ? "changed"
          : compared && !pkg.previous
            ? "added"
            : pkg.cves.some((cve) => !withoutFix(cve))
              ? "fix"
              : compared
                ? "unchanged"
                : "packages"
    groups[key].push(pkg)
  }
  return groups
}

/** Counts by severity, critical to unknown, each id once. */
export function pipVector(cves: PipFinding[]): number[] {
  const vector = [0, 0, 0, 0, 0]
  const seen = new Set<string>()
  for (const cve of cves) {
    if (seen.has(cve.id)) continue
    seen.add(cve.id)
    const index = SEVERITIES.indexOf(cve.severity.toUpperCase())
    vector[index === -1 ? 4 : index] += 1
  }
  return vector
}

/**
 * The known CVEs of the set, and of the previous crossing when one is recorded: its packages at their
 * versions then, those that left included. `before` is absent with no previous crossing.
 */
export function pipCveTotals(result: PipAnalysisResult): { before?: number[]; after: number[] } {
  const after = pipVector(result.packages.flatMap((pkg) => pkg.cves))
  if (!result.previous) return { after }
  const before = pipVector([...result.packages.flatMap((pkg) => pkg.previous?.cves ?? []), ...(result.removed ?? []).flatMap((pkg) => pkg.cves)])
  return { before, after }
}

/** A reason the archive takes; an empty or refused one still waits. */
export function pipReasonWritten(text: string | undefined): boolean {
  return text !== undefined && text.trim() !== "" && reasonProblem(text) === undefined
}

/**
 * What holds Seal: each package with no wheel, then one name per reason still missing or refused, so a
 * package that needs two reasons is named twice.
 */
export function pipWaiting(result: PipAnalysisResult, reasons: Record<string, string>): { noWheel: string[]; missing: string[] } {
  const blocked = [...result.packages.filter((pkg) => noWheel(result, pkg)).map((pkg) => pkg.name), ...result.blocking.map((b) => b.name)]
  return {
    noWheel: [...new Set(blocked)],
    missing: pipNeededReasons(result)
      .filter((need) => !pipReasonWritten(reasons[need.key]))
      .map((need) => need.name),
  }
}

/** The reasons a pip export request carries, trimmed, in the order they were asked. */
export function pipReasonsToSend(needed: PipNeededReason[], reasons: Record<string, string>): Reason[] {
  return needed.map((need) => ({ kind: need.kind, dependencies: [need.name], text: (reasons[need.key] ?? "").trim() }))
}

/** Where a package is pinned: each file and line, each file a 0.7.0 analysis names, or none for a dependency. */
export function pinnedPlaces(pkg: { pinnedAt?: { file: string; line: number }[]; files?: string[] }): string[] {
  if (pkg.pinnedAt && pkg.pinnedAt.length > 0) return pkg.pinnedAt.map((place) => `${place.file}, line ${place.line.toLocaleString("en-US")}`)
  return pkg.files ?? []
}

/** The CPU a wheel is built for, read from its file name's platform tag, or "any". */
export function wheelPlatform(file: string): string {
  const platform = file.replace(/\.whl$/, "").split("-").at(-1) ?? ""
  if (platform === "any") return "any"
  const cpu = platform.match(/(x86_64|aarch64|arm64|armv7l|ppc64le|s390x|i686|amd64|win32|universal2)/)
  return cpu ? cpu[1] : platform
}
