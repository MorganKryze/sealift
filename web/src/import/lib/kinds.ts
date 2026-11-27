import { formatBytes } from "@/lib/utils"

import { notFinished, type ReportPackage } from "./outcome"

export type KindGroup = "as-is" | "change-first"

const KINDS: Record<string, { group: KindGroup; words: string }> = {
  interrupted: { group: "as-is", words: "The service stopped before this package ended. Retry the import: it uploads only what Nexus lacks." },
  source: { group: "as-is", words: "MinIO did not give the archive's bytes. Retry the import." },
  conflict: {
    group: "change-first",
    words: "Nexus holds this version with other bytes, and sealift never overwrites it. If that copy is the wrong one, delete it in Nexus, then retry.",
  },
  mismatch: { group: "change-first", words: "The archive does not hold what its manifest names. Export the archive again, upload it and start a new import." },
  nexus: { group: "change-first", words: "Nexus refused or did not answer. Check that it answers and that the import account may upload, then retry." },
  local: { group: "change-first", words: "The service could not use its own files. Ask the administrator to check its data volume and settings file, then retry." },
}

/** What to do about a failed package. A record without a kind, or a kind this version does not know, gets words that cover every cause. */
export function nextAction(kind?: string): { group: KindGroup | "unknown"; words: string } {
  if (kind && Object.hasOwn(KINDS, kind)) {
    return KINDS[kind]
  }
  return { group: "unknown", words: "Read the reason: it names what failed. Fix that, then retry." }
}

/** Why a package is not in Nexus, as the failed end groups it. */
export type Cause = "no-answer" | "too-large" | "refused" | "conflict" | "source" | "interrupted" | "mismatch" | "local" | "unknown"

/** The causes in the order their blocks show. */
export const CAUSES: Cause[] = ["no-answer", "too-large", "refused", "conflict", "source", "interrupted", "mismatch", "local", "unknown"]

const CAUSE_WORDS: Record<Cause, { title: string; tone: "warn" | "failure"; retry: boolean }> = {
  "no-answer": { title: "No answer from Nexus", tone: "warn", retry: true },
  "too-large": { title: "Too large for Nexus", tone: "failure", retry: false },
  refused: { title: "Nexus refused it", tone: "warn", retry: true },
  conflict: { title: "Another file under the same version", tone: "failure", retry: false },
  source: { title: "Could not read the archive from MinIO", tone: "warn", retry: true },
  interrupted: { title: "Stopped before it was published", tone: "warn", retry: true },
  mismatch: { title: "Not the package the manifest names", tone: "failure", retry: false },
  local: { title: "Failed on this side", tone: "warn", retry: true },
  unknown: { title: "Not in Nexus", tone: "warn", retry: true },
}

/**
 * The cause of a package not in Nexus, from its kind and the status Nexus answered. A package the run never
 * reached reads as stopped, as does a record of 0.4.0 or earlier whose reason says so.
 */
export function causeOf(p: ReportPackage): Cause {
  if (p.state === "pending" || notFinished(p)) return "interrupted"
  switch (p.kind) {
    case "nexus":
      if (p.nexusStatus == null) return "no-answer"
      return p.nexusStatus === 413 ? "too-large" : "refused"
    case "conflict":
    case "source":
    case "mismatch":
    case "local":
      return p.kind
    default:
      return "unknown"
  }
}

/** A cause's title, its tint, and whether a retry alone can clear it. */
export function causeWords(cause: Cause): { title: string; tone: "warn" | "failure"; retry: boolean } {
  return CAUSE_WORDS[cause]
}

/** What Copy request copies for Nexus's administrators: the repository, the size to go above and the files refused. */
export function copyRequest(repository: string, files: ReportPackage[], contact: string | undefined): string {
  const largest = Math.max(0, ...files.map((p) => p.size ?? 0))
  const names = files.map((p) => p.file).join(", ")
  const verb = files.length === 1 ? "was" : "were"
  const ask = `Raise the upload limit of ${repository || "the repository"} above ${formatBytes(largest)}: ${names} ${verb} refused as too large.`
  return contact ? `To ${contact}: ${ask}` : ask
}

/** A package's path in its Nexus repository: the npm tarball's, or the pypi file's under its normalized project and version. */
export function nexusPath(p: ReportPackage, ecosystem: "npm" | "pip"): string {
  if (ecosystem === "pip") return `packages/${p.name.toLowerCase().replace(/[-_.]+/g, "-")}/${p.version}/${p.file}`
  return `${p.name}/-/${p.name.slice(p.name.lastIndexOf("/") + 1)}-${p.version}.tgz`
}
