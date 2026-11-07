import type { components } from "./schema"

export type Problem = components["schemas"]["Problem"]

/** The session behind the gateway is over: a 401, a redirect, or an answer below 500 that is not the service's JSON. */
export class SessionEnded extends Error {
  constructor() {
    super("The session has ended")
    this.name = "SessionEnded"
  }
}

export class ImportApiError extends Error {
  constructor(
    readonly status: number,
    readonly problem: Problem | null,
  ) {
    super(problem?.detail ?? problem?.title ?? `The request failed with status ${status}`)
    this.name = "ImportApiError"
  }
}

const UNREACHABLE: Problem = {
  type: "about:blank",
  title: "The service is not reachable",
  status: 0,
  detail: "The request did not reach the server. Check the network, then try again.",
}

// An error page from the gateway, such as nginx's 502 while the service restarts, is not an ended session.
const gatewayProblem = (status: number): Problem => ({
  type: "about:blank",
  title: "The gateway could not reach the import service",
  status,
  detail: "The gateway could not reach the import service, which may be restarting. Try again in a moment.",
})

// The only paths the screens may call: an import id starts with a letter or digit, so it never reads as a dot segment.
const CONTRACT = /^\/(me|archives|imports(\/[A-Za-z0-9][A-Za-z0-9._-]*(\/retry)?)?)$/

const JSON_TYPES = ["application/json", "application/problem+json"]

/** Calls the import contract under /api and returns the parsed body, or throws SessionEnded or ImportApiError. */
export async function importFetch<T>(path: "/me" | "/archives" | "/imports" | `/imports/${string}`, init?: RequestInit): Promise<T> {
  if (!CONTRACT.test(path)) {
    throw new Error(`${path} is not part of the import contract`)
  }
  let response: Response
  try {
    // The gateway answers an ended session with a redirect to its identity provider, on another origin:
    // followed, the browser fails the request with no status. Not followed, it reports an opaque redirect.
    response = await fetch(`/api${path}`, { ...init, redirect: "manual" })
  } catch {
    throw new ImportApiError(0, UNREACHABLE)
  }
  if (response.type === "opaqueredirect") {
    throw new SessionEnded()
  }
  // A gateway whose session ended may also answer with its sign-in page, often with a 200.
  const type = (response.headers.get("Content-Type") ?? "").split(";")[0].trim().toLowerCase()
  if (response.status === 401) {
    throw new SessionEnded()
  }
  if (!JSON_TYPES.includes(type)) {
    if (response.status >= 500) {
      throw new ImportApiError(response.status, gatewayProblem(response.status))
    }
    throw new SessionEnded()
  }
  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Problem | null
    throw new ImportApiError(response.status, problem)
  }
  return (await response.json()) as T
}
