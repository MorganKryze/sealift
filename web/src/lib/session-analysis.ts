import type { Analysis } from "@/api/projects"
import { latestByDate } from "@/lib/utils"

/** The analysis route's search: the id of the analysis a crossing link opens, when it names one. */
export type AnalysisSearch = { analysis?: string }

/** Keeps only a non-empty string id, so a hand-edited link falls back to the latest analysis. */
export function analysisSearch(search: Record<string, unknown>): AnalysisSearch {
  return typeof search.analysis === "string" && search.analysis !== "" ? { analysis: search.analysis } : {}
}

/** The analysis the link names, else the latest one. */
export function shownAnalysis(analyses: Analysis[] | undefined, id: string | undefined): Analysis | undefined {
  return analyses?.find((candidate) => candidate.id === id) ?? latestByDate(analyses)
}
