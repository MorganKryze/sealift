import type { paths } from "./schema"

type ApiPath = keyof paths

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
 * Fetches from the API, constraining the path to one the schema declares.
 * The caller supplies the response type: openapi-typescript's operation
 * types are keyed by method and status, which a single generic cannot
 * infer without duplicating that structure here.
 */
export async function apiFetch<T>(path: ApiPath, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${String(path)}`, {
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
