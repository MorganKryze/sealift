import type { AnalysisResult, DependencyResult, ExportRequest } from "@/api/projects"

type Cve = DependencyResult["cves"][number]

/** One reason the server asks before it exports a selection. */
export type NeededReason = { kind: "major-jump" | "cve-without-fix"; dependencies: string[]; label: string; detail: string }

type Reason = NonNullable<ExportRequest["reasons"]>[number]

/** The archive's reader takes 300 characters once trimmed (archive.MaxReasonRunes). */
export const MAX_REASON_CHARACTERS = 300
const MAX_REASON_BYTES = 4800

/** Where a reason's text lives in useReasons: unique per kind, family or dependency. */
export function reasonKey(needed: NeededReason): string {
  return `${needed.kind}:${needed.label}`
}

/** A CVE no version fixes, or whose fix an older analysis never recorded. */
function withoutFix(cve: Cve): boolean {
  return (cve.fixedIn ?? "").trim() === ""
}

/**
 * The versions of one entry the archive holds, with the CVEs no version
 * fixes: each selected version it lists, or its current version when it
 * lists none, since the project then keeps the one it has.
 */
function heldOf(dependency: DependencyResult, selected: string[]): { version: string; ids: string[] }[] {
  const cvesOf = (version: string) =>
    version === dependency.current ? dependency.cves : dependency.candidates.find((c) => c.version === version)?.cves
  const versions = [...new Set(selected)].filter((version) => cvesOf(version) !== undefined)
  const held = versions.length > 0 ? versions : [dependency.current]
  return held.map((version) => ({
    version,
    ids: [...new Set((cvesOf(version) ?? []).filter(withoutFix).map((cve) => cve.id))],
  }))
}

function andList(items: string[]): string {
  return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`
}

/**
 * The reasons an export of selection needs, as the server checks them: one
 * per family or lone dependency the selection takes out of its line, read
 * from each candidate's leavesLine and each dependency's family, then one
 * per dependency whose held version keeps a CVE with no known fix. A name
 * listed twice keeps all its jumps in one group, its family's when either
 * entry has one, since the server covers a jump by name. The
 * export sends includeProject false, so a dependency the selection leaves
 * out holds its current version.
 */
export function requiredReasons(result: AnalysisResult, selection: Record<string, string[]>): NeededReason[] {
  const jumps = new Map<string, { label: string; moves: { name: string; from: string; to: string }[] }>()
  const cves = new Map<string, string[]>()
  const familyOf = new Map<string, string>()
  for (const dependency of result.dependencies) {
    if (dependency.family && !familyOf.has(dependency.name)) {
      familyOf.set(dependency.name, dependency.family)
    }
  }

  for (const dependency of result.dependencies) {
    const selected = selection[dependency.name] ?? []
    for (const version of new Set(selected)) {
      const leaves = dependency.candidates.find((c) => c.version === version)?.leavesLine
      if (version === dependency.current || !leaves) {
        continue
      }
      const family = familyOf.get(dependency.name)
      const group = family ? `family ${family}` : `dependency ${dependency.name}`
      const jump = jumps.get(group) ?? { label: family || dependency.name, moves: [] }
      jump.moves.push({ name: dependency.name, from: dependency.current, to: version })
      jumps.set(group, jump)
    }
    for (const held of heldOf(dependency, selected)) {
      if (held.ids.length > 0) {
        const parts = cves.get(dependency.name) ?? []
        parts.push(`${dependency.name} ${held.version} keeps ${andList(held.ids)}`)
        cves.set(dependency.name, parts)
      }
    }
  }

  const needed: NeededReason[] = []
  for (const { label, moves } of jumps.values()) {
    needed.push({
      kind: "major-jump",
      dependencies: [...new Set(moves.map((move) => move.name))],
      label,
      detail: moves.map((move) => `${move.name} ${move.from} to ${move.to}`).join(", "),
    })
  }
  for (const [name, parts] of cves) {
    needed.push({ kind: "cve-without-fix", dependencies: [name], label: name, detail: `${[...new Set(parts)].join(", ")}, with no known fix` })
  }
  return needed
}

/**
 * What keeps text from being a reason the archive accepts, in words, or
 * undefined. An empty text is missing rather than wrong, so it has none.
 * Printable means what Go's unicode.IsPrint takes: letters, marks, numbers,
 * punctuation, symbols and the plain space, plus the no-break spaces
 * U+00A0, U+202F and U+3000 the archive accepts.
 */
export function reasonProblem(text: string): string | undefined {
  if (new TextEncoder().encode(text).length > MAX_REASON_BYTES) {
    return `Shorten the reason: it holds more than ${MAX_REASON_BYTES} bytes with its spaces.`
  }
  if (!/^[\p{L}\p{M}\p{N}\p{P}\p{S} \u00a0\u202f\u3000]*$/u.test(text)) {
    return "Keep the reason on one line, with no tab or control character."
  }
  const length = [...text.trim()].length
  if (length > MAX_REASON_CHARACTERS) {
    return `Shorten the reason to ${MAX_REASON_CHARACTERS} characters: it has ${length}.`
  }
  return undefined
}

/** The most names each part of the cause lists, so it stays a line or two in the bar. */
const NAMED_IN_CAUSE = 5

function counted(labels: string[], what: string): string {
  const names =
    labels.length > NAMED_IN_CAUSE
      ? `${labels.slice(0, NAMED_IN_CAUSE).join(", ")} and ${labels.length - NAMED_IN_CAUSE} more`
      : labels.join(", ")
  return `${labels.length} reason${labels.length === 1 ? "" : "s"} ${what}: ${names}`
}

/** Why Export waits, in words: the reasons left empty, then those written but refused. "" once all are written. */
export function missingReasons(needed: NeededReason[], reasons: Record<string, string>): string {
  const missing: string[] = []
  const toFix: string[] = []
  for (const n of needed) {
    const text = reasons[reasonKey(n)] ?? ""
    if (text.trim() === "") {
      missing.push(n.label)
    } else if (reasonProblem(text) !== undefined) {
      toFix.push(n.label)
    }
  }
  const parts = [missing.length > 0 ? counted(missing, "missing") : "", toFix.length > 0 ? counted(toFix, "to fix") : ""]
  return parts.filter((p) => p !== "").join(". ")
}

/** The reasons an export request carries, trimmed, in the order they were asked. */
export function reasonsToSend(needed: NeededReason[], reasons: Record<string, string>): Reason[] {
  return needed.map((n) => ({ kind: n.kind, dependencies: n.dependencies, text: (reasons[reasonKey(n)] ?? "").trim() }))
}
