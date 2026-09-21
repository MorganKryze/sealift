import { apiFetch } from "./client"
import type { components } from "./schema"

export type Project = components["schemas"]["Project"]
export type ProjectSummary = components["schemas"]["ProjectSummary"]
export type Problem = components["schemas"]["Problem"]

export function listProjects(): Promise<ProjectSummary[]> {
  return apiFetch<ProjectSummary[]>("/projects")
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
