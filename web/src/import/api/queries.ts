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

export type ImportList = components["schemas"]["ImportList"]

/** How often Imports reads again: every 5 s while one of the user's imports is queued or running. */
export function importsPollInterval(list: ImportList | undefined): number | false {
  const inFlight = list?.imports.some((i) => i.outcome === "queued" || i.outcome === "running")
  return inFlight ? 5000 : false
}

export function useImports(): UseQueryResult<ImportList, Error> {
  return useQuery({
    queryKey: ["imports"],
    queryFn: () => importFetch<ImportList>("/imports"),
    refetchInterval: (query) => importsPollInterval(query.state.data),
  })
}

export type ArchiveList = components["schemas"]["ArchiveList"]
export type Archive = components["schemas"]["Archive"]

/** The folder is read on load and on refetch() only: an upload at the gateway's side is not worth a poll. */
export function useArchives(): UseQueryResult<ArchiveList, Error> {
  return useQuery({
    queryKey: ["archives"],
    queryFn: () => importFetch<ArchiveList>("/archives"),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
}
