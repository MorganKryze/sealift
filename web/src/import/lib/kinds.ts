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
