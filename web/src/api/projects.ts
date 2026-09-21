import { apiFetch, apiFetchProblem } from "./client"
import type { components } from "./schema"

export type Project = components["schemas"]["Project"]
export type ProjectSummary = components["schemas"]["ProjectSummary"]
export type Problem = components["schemas"]["Problem"]
export type Analysis = components["schemas"]["Analysis"]
export type Export = components["schemas"]["Export"]
export type AnalysisResult = components["schemas"]["AnalysisResult"]
export type DependencyResult = components["schemas"]["DependencyResult"]
export type Candidate = components["schemas"]["Candidate"]
export type Signal = components["schemas"]["Signal"]
export type Target = components["schemas"]["Target"]
export type ExportRequest = components["schemas"]["ExportRequest"]

export function listProjects(): Promise<ProjectSummary[]> {
  return apiFetch<ProjectSummary[]>("/projects")
}

export function getProject(projectId: string): Promise<Project> {
  return apiFetch<Project>(`/projects/${projectId}`)
}

export function queueAnalysis(projectId: string): Promise<Analysis> {
  return apiFetch<Analysis>(`/projects/${projectId}/analyses`, { method: "POST" })
}

export function cancelAnalysis(projectId: string, analysisId: string): Promise<Analysis> {
  return apiFetch<Analysis>(`/projects/${projectId}/analyses/${analysisId}/cancel`, { method: "POST" })
}

export function queueExport(projectId: string, analysisId: string, body: ExportRequest): Promise<Export> {
  return apiFetchProblem<Export>(`/projects/${projectId}/analyses/${analysisId}/exports`, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function getExport(projectId: string, exportId: string): Promise<Export> {
  return apiFetch<Export>(`/projects/${projectId}/exports/${exportId}`)
}

/**
 * Thrown by createProject. Carries the parsed Problem Details body so the
 * caller can tell a validation failure (400, with an errors list) from any
 * other failure (title and detail only).
 */
export class ProjectUploadError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: Problem | null,
  ) {
    super(problem?.detail ?? problem?.title ?? "Upload failed")
    this.name = "ProjectUploadError"
  }
}

/**
 * Posts the manifest as multipart/form-data. Not routed through apiFetch:
 * that helper always sets a JSON content type, which would strip the
 * multipart boundary the browser needs to add here.
 */
export async function createProject(file: File): Promise<Project> {
  const body = new FormData()
  body.append("manifest", file)

  const response = await fetch("/api/projects", { method: "POST", body })

  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Problem | null
    throw new ProjectUploadError(response.status, problem)
  }

  return (await response.json()) as Project
}
