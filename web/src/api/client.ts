import type { components } from "./schema"

type Problem = components["schemas"]["Problem"]

const baseUrl = "/api"

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = "ApiError"
  }
}

/**
 * Thrown by apiFetchProblem. Carries the parsed Problem Details body so a
 * caller can tell a validation failure (400, with an errors list) from any
 * other failure (title and detail only).
 */
export class ProblemError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: Problem | null,
  ) {
    super(problem?.detail ?? problem?.title ?? "Request failed")
    this.name = "ProblemError"
  }
}

/**
 * Fetches from the API. The path carries dynamic ids, so it stays a plain
 * string rather than a schema-derived literal; the caller supplies the
 * response type instead, since openapi-typescript's operation types are
 * keyed by method and status and a single generic cannot infer that shape.
 */
export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  })

  if (!response.ok) {
    throw new ApiError(response.status, await response.text())
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

/**
 * Like apiFetch, but on failure parses the Problem Details body instead of
 * throwing the response text, for callers that need to branch on status,
 * title, detail or the field-level errors list.
 */
export async function apiFetchProblem<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  })

  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Problem | null
    throw new ProblemError(response.status, problem)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}
