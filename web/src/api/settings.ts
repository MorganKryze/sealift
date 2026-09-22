import { apiFetch, apiFetchProblem } from "./client"
import type { components } from "./schema"

export type Settings = components["schemas"]["Settings"]
export type ToolsState = components["schemas"]["ToolsState"]

export function getSettings(): Promise<Settings> {
  return apiFetch<Settings>("/settings")
}

export function updateSettings(settings: Settings): Promise<Settings> {
  return apiFetchProblem<Settings>("/settings", { method: "PUT", body: JSON.stringify(settings) })
}

export function getTools(): Promise<ToolsState> {
  return apiFetch<ToolsState>("/tools")
}

/** Installs the latest Trivy release, or the named one; force skips the minimum release age. */
export function updateTrivy(force: boolean, version?: string): Promise<ToolsState> {
  return apiFetchProblem<ToolsState>("/tools/trivy/update", { method: "POST", body: JSON.stringify({ force, version }) })
}

export function activateTrivy(version: string): Promise<ToolsState> {
  return apiFetchProblem<ToolsState>("/tools/trivy/activate", { method: "POST", body: JSON.stringify({ version }) })
}

export function updateTrivyDB(): Promise<ToolsState> {
  return apiFetchProblem<ToolsState>("/tools/trivy/db/update", { method: "POST" })
}
