import type { DependencyResult } from "@/api/projects"

/**
 * The selection an export sends: sealift's proposal for every dependency,
 * with the user's own picks on top. A stored empty list means "keep the
 * current version"; a missing entry means the user never touched it, so
 * the proposal stands. Review's confirm and an export's retry both send
 * this, so a retry never depends on what one browser happened to store.
 */
export function exportSelection(dependencies: DependencyResult[], stored: Record<string, string[]>): Record<string, string[]> {
  const selection: Record<string, string[]> = {}
  for (const dependency of dependencies) {
    const picks = stored[dependency.name]
    const picked = picks === undefined ? dependency.best || dependency.current : (picks[0] ?? dependency.current)
    if (picked !== dependency.current) {
      selection[dependency.name] = [picked]
    }
  }
  return selection
}
