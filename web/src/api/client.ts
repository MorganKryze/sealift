import type { components } from "./schema"

type Problem = components["schemas"]["Problem"]

const baseUrl = "/api"

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: Problem | null,
  ) {
    super(problem?.detail ?? problem?.title ?? `request failed with status ${status}`)
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

/** What every screen shows when a request never reached the server. */
export const UNREACHABLE: Problem = {
  type: "sealift-unreachable",
  title: "sealift is not reachable",
  status: 0,
  detail: "The request did not reach the server. Check that the sealift container is running, then try again.",
}

/**
 * Sends a request and turns every failure into the caller's typed error:
 * a response outside 2xx with its Problem body, and a request that never
 * reached the server (fetch rejects with a TypeError) with UNREACHABLE.
 * Screens only display typed errors, so an untyped one would fail silently.
 */
export async function send(
  url: string,
  init: RequestInit | undefined,
  fail: (status: number, problem: Problem | null) => Error,
): Promise<Response> {
  let response: Response
  try {
    response = await fetch(url, init)
  } catch {
    throw fail(0, UNREACHABLE)
  }
  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Problem | null
    throw fail(response.status, problem)
  }
  return response
}

/**
 * Fetches from the API. The path carries dynamic ids, so it stays a plain
 * string rather than a schema-derived literal; the caller supplies the
 * response type instead, since openapi-typescript's operation types are
 * keyed by method and status and a single generic cannot infer that shape.
 */
export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await send(
    `${baseUrl}${path}`,
    { ...init, headers: { "Content-Type": "application/json", ...init?.headers } },
    (status, problem) => new ApiError(status, problem),
  )

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

/**
 * Like apiFetch, but the caller needs to branch on the field-level errors
 * list a validation failure carries, not just its title and detail.
 */
export async function apiFetchProblem<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await send(
    `${baseUrl}${path}`,
    { ...init, headers: { "Content-Type": "application/json", ...init?.headers } },
    (status, problem) => new ProblemError(status, problem),
  )

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}
