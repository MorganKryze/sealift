import { CircleAlert, CircleCheck, CirclePause, CircleQuestionMark, Clock, LoaderCircle, ShieldX, type LucideIcon } from "lucide-react"

import type { components } from "../api/schema"

export type Import = components["schemas"]["Import"]
export type Attempt = components["schemas"]["Attempt"]
export type ReportPackage = components["schemas"]["ReportPackage"]

export type Outcome = "queued" | "running" | "complete" | "incomplete" | "refused" | "interrupted"

type Tone = "waiting" | "progress" | "done" | "failure"

const WORDS: Record<Outcome, { label: string; icon: LucideIcon; tone: Tone }> = {
  queued: { label: "Queued", icon: Clock, tone: "waiting" },
  running: { label: "Running", icon: LoaderCircle, tone: "progress" },
  complete: { label: "Complete", icon: CircleCheck, tone: "done" },
  incomplete: { label: "Incomplete", icon: CircleAlert, tone: "failure" },
  refused: { label: "Refused", icon: ShieldX, tone: "failure" },
  interrupted: { label: "Interrupted", icon: CirclePause, tone: "failure" },
}

/** The word and icon of an outcome. An outcome this version does not know reads "Not recorded". */
export function outcomeWords(outcome: string): { label: string; icon: LucideIcon; tone: Tone } {
  return Object.hasOwn(WORDS, outcome) ? WORDS[outcome as Outcome] : { label: "Not recorded", icon: CircleQuestionMark, tone: "waiting" }
}

/** The attempt the import stands at. A record with none reads as a queued first attempt. */
export function latestAttempt(imp: Import): Attempt {
  const last = imp.attempts[imp.attempts.length - 1]
  if (last) {
    return last
  }
  return {
    n: 1,
    status: "queued",
    outcome: "",
    report: {
      outcome: "", reason: "", unencrypted: false, importVersion: "",
      archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" },
      nexus: { url: "", repository: "" }, counts: { published: 0, present: 0, failed: 0 }, packages: [],
    },
  }
}

/** A failed package the attempt never finished: the service stopped or the run never reached it. A v0.4.0 record has no kind, so its reasons stand in. */
export function notFinished(p: ReportPackage): boolean {
  if (p.state !== "failed") {
    return false
  }
  if (p.kind != null) {
    return p.kind === "interrupted"
  }
  return p.reason === "interrupted" || p.reason === "not reached"
}

/** Packages by state. Not finished ones are counted apart from failures; done is what the attempt finished. */
export function counts(a: Attempt): { published: number; present: number; failed: number; notFinished: number; pending: number; done: number; total: number } {
  const out = { published: 0, present: 0, failed: 0, notFinished: 0, pending: 0, done: 0, total: 0 }
  for (const p of a.report.packages) {
    out.total++
    if (p.state === "published") {
      out.published++
    } else if (p.state === "present") {
      out.present++
    } else if (p.state === "failed") {
      if (notFinished(p)) {
        out.notFinished++
      } else {
        out.failed++
      }
    } else if (p.state === "pending") {
      out.pending++
    }
  }
  out.done = out.published + out.present + out.failed
  return out
}

const FOLDER = "packages/npm/"

/** An archive's folder below packages/npm/ and its file. An archive at the root names packages/npm/ as its folder. */
export function archiveName(key: string): { folder: string; file: string } {
  const rel = key.startsWith(FOLDER) ? key.slice(FOLDER.length) : key
  const cut = rel.lastIndexOf("/")
  if (cut < 0) {
    return { folder: key.startsWith(FOLDER) ? FOLDER : "", file: rel }
  }
  return { folder: rel.slice(0, cut + 1), file: rel.slice(cut + 1) }
}
