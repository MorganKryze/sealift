import { useQuery, type UseQueryResult } from "@tanstack/react-query"

import { ImportApiError, importFetch, SessionEnded } from "./client"
import type { components } from "./schema"

/** A session that ended or a 4xx answers the same on a retry; a network failure or a 5xx may not. */
export function retryOnlyTransient(failureCount: number, error: Error): boolean {
  if (error instanceof SessionEnded) {
    return false
  }
  if (error instanceof ImportApiError && error.status >= 400 && error.status < 500) {
    return false
  }
  return failureCount < 3
}

export function useMe(): UseQueryResult<components["schemas"]["Me"], Error> {
  return useQuery({
    queryKey: ["me"],
    queryFn: () => importFetch<components["schemas"]["Me"]>("/me"),
    staleTime: 5 * 60_000,
  })
}
