import type { Attempt } from "./outcome"

export type Stage = "waiting" | "manifest" | "checks" | "publishing" | "ended"

/**
 * Where an attempt stands, read from its record alone: the service reports no byte progress, so a
 * running attempt with packages listed and no passed check is still checking the archive.
 */
export function stageOf(a: Attempt): Stage {
  if (a.status === "queued") {
    return "waiting"
  }
  if (a.status !== "running") {
    return "ended"
  }
  if (a.report.packages.length === 0) {
    return "manifest"
  }
  return a.report.archiveChecked === true ? "publishing" : "checks"
}
