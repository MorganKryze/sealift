import { apiFetch } from "@/api/client"
import type { Analysis, Export } from "@/api/projects"

type Run = Pick<Analysis, "id" | "createdAt">

const DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" })
const DAY_AND_YEAR = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" })

const localDay = (date: Date) => `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`

/** The local day a crossing started, with its year only outside the current one: "20 Nov", "20 Nov 2025". */
export function crossingDay(createdAt: string, now: Date = new Date()): string {
  const date = new Date(createdAt)
  return (date.getFullYear() === now.getFullYear() ? DAY : DAY_AND_YEAR).format(date)
}

/** A crossing's name: its project and day, with " · n" for the n-th analysis of that project started the same local day. */
export function crossingName(projectName: string, analysis: Run, analyses: Run[], now: Date = new Date()): string {
  const day = localDay(new Date(analysis.createdAt))
  const sameDay = analyses
    .filter((other) => localDay(new Date(other.createdAt)) === day)
    .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime() || a.id.localeCompare(b.id))
  const n = sameDay.findIndex((other) => other.id === analysis.id) + 1
  const name = `${projectName} · ${crossingDay(analysis.createdAt, now)}`
  return n > 1 ? `${name} · ${n}` : name
}

export type CrossingKind = "queued" | "running" | "waits" | "sealed" | "failed" | "cancelled" | "new"

/** A crossing's state in words, from its analysis and that analysis' latest export; a failure names the step the user knows. */
export function crossingState(analysis?: Analysis, exported?: Export): { label: string; kind: CrossingKind } {
  if (!analysis) return { label: "Not analysed yet", kind: "new" }
  switch (analysis.state) {
    case "queued":
      return { label: "Queued", kind: "queued" }
    case "running":
      return { label: "Analysing", kind: "running" }
    case "cancelled":
      return { label: "Cancelled", kind: "cancelled" }
    case "failed":
    case "interrupted":
      return { label: "Failed at Analyse", kind: "failed" }
  }
  switch (exported?.state) {
    case undefined:
      return { label: "Review waits", kind: "waits" }
    case "queued":
      return { label: "Queued", kind: "queued" }
    case "running":
      return { label: "Sealing", kind: "running" }
    case "done":
      return { label: "Sealed", kind: "sealed" }
    case "cancelled":
      return { label: "Cancelled", kind: "cancelled" }
    case "failed":
    case "interrupted":
      return { label: "Failed at Seal", kind: "failed" }
  }
}

const SHA256 = /^[0-9a-f]{64}$/

// Neither file's shape is in the API schema: the download route serves every file as bytes.
interface SealManifest {
  archive?: { sha256?: unknown; size?: unknown }
  packages?: unknown
  review?: { cves?: { before?: unknown; after?: unknown } }
}
interface SealSignature {
  publicKeySha256?: unknown
}

/** What manifest.json says of its archive; a figure the file does not hold stays absent, never 0. */
export interface SealFigures {
  packages?: number
  size?: number
  /** Known CVEs over every severity, before the crossing and in what it ships. */
  cves?: { before: number; after?: number }
}

const total = (value: unknown) => {
  if (!Array.isArray(value)) return undefined
  const counts = value.map(count)
  return counts.every((c) => c !== undefined) ? counts.reduce<number>((sum, c) => sum + (c ?? 0), 0) : undefined
}

/** summary.md's note: the known CVEs as figures when manifest.json holds both, in words otherwise. */
export function cveNote(figures: SealFigures | undefined): string {
  const cves = figures?.cves
  return cves && cves.after !== undefined ? `known CVEs ${cves.before} → ${cves.after}` : "known CVEs before and after"
}

const count = (value: unknown) => (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined)

/**
 * Reads the archive's sha256, package count and size from manifest.json and the signing key's sha256 from
 * manifest.json.sig, refusing either sha256 unless it is 64 lowercase hex characters.
 */
export async function readSeal(projectId: string, exportId: string): Promise<{ archiveSha256: string; keySha256: string; figures: SealFigures }> {
  const file = (name: string) => `/projects/${encodeURIComponent(projectId)}/exports/${encodeURIComponent(exportId)}/files/${name}`
  // Each cause starts with the file it comes from, so a screen can say which one did not read.
  const read = <T,>(name: string) =>
    apiFetch<T>(file(name)).catch((error: unknown) => {
      throw new Error(`${name}: ${error instanceof Error ? error.message : String(error)}`)
    })
  const [manifest, signature] = await Promise.all([read<SealManifest>("manifest.json"), read<SealSignature>("manifest.json.sig")])
  const archiveSha256 = manifest?.archive?.sha256
  if (typeof archiveSha256 !== "string" || !SHA256.test(archiveSha256)) {
    throw new Error("manifest.json: no archive sha256 of 64 lowercase hex characters")
  }
  const keySha256 = signature?.publicKeySha256
  if (typeof keySha256 !== "string" || !SHA256.test(keySha256)) {
    throw new Error("manifest.json.sig: no key sha256 of 64 lowercase hex characters")
  }
  const figures: SealFigures = {}
  const packages = Array.isArray(manifest.packages) ? manifest.packages.length : undefined
  if (packages !== undefined) figures.packages = packages
  const size = count(manifest.archive?.size)
  if (size !== undefined) figures.size = size
  const before = total(manifest.review?.cves?.before)
  if (before !== undefined) {
    const after = total(manifest.review?.cves?.after)
    figures.cves = after === undefined ? { before } : { before, after }
  }
  return { archiveSha256, keySha256, figures }
}

const sortKey = (name: string) => name.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "")

/** Orders project names ignoring case and punctuation, so "@acme/x" sorts under A. */
export function byName(a: string, b: string): number {
  return sortKey(a).localeCompare(sortKey(b), "en") || a.localeCompare(b, "en")
}

/** The letter a name files under in a list by name; a name that starts with a digit files under "#". */
export function nameLetter(name: string): string {
  const first = sortKey(name).charAt(0).toUpperCase()
  return /\p{L}/u.test(first) ? first : "#"
}
