import { useMutation, useQuery, useQueryClient, type UseMutationResult, type UseQueryResult } from "@tanstack/react-query"

import { ImportApiError, importFetch, SessionEnded } from "./client"
import type { components } from "./schema"
import { nextAction } from "../lib/kinds"
import { latestAttempt, notFinished, type ReportPackage } from "../lib/outcome"

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

export type Import = components["schemas"]["Import"]

/** How often the import page reads again: every 2 s while its latest attempt is queued, running, or complete with no removal recorded. */
export function importPollInterval(imp: Import | undefined): number | false {
  if (!imp) {
    return false
  }
  const a = latestAttempt(imp)
  const inFlight = a.status === "queued" || a.status === "running" || (a.status === "ended" && a.outcome === "complete" && !a.removal)
  return inFlight ? 2000 : false
}

export function useImport(id: string): UseQueryResult<Import, Error> {
  return useQuery({
    queryKey: ["imports", id],
    queryFn: () => importFetch<Import>(`/imports/${encodeURIComponent(id)}`),
    refetchInterval: (query) => importPollInterval(query.state.data),
  })
}

/** An expected sha256 is empty or 64 hex digits once trimmed. */
export function validSha256(s: string): boolean {
  const t = s.trim()
  return t === "" || /^[0-9a-fA-F]{64}$/.test(t)
}

/** Starts an import. The JSON content type is required: the service refuses a cross-site start without it. */
export function useStartImport(): UseMutationResult<Import, Error, { archive: string; expectedSha256?: string }> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (body: { archive: string; expectedSha256?: string }) =>
      importFetch<Import>("/imports", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["imports"] }),
  })
}

/** Where a retry's answer goes: the new attempt shows in place, and its status region takes focus once drawn. */
export function useRetryImport(id: string): UseMutationResult<Import, Error, void> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () =>
      importFetch<Import>(`/imports/${encodeURIComponent(id)}/retry`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }),
    onSuccess: (imp) => {
      client.setQueryData(["imports", id], imp)
      void client.invalidateQueries({ queryKey: ["imports"], exact: true })
      requestAnimationFrame(() => document.querySelector<HTMLElement>("[role=status]")?.focus())
    },
    onError: (error) => {
      if (error instanceof ImportApiError && error.status === 409) {
        void client.invalidateQueries({ queryKey: ["imports", id] })
      }
    },
  })
}

/**
 * The packages a retry has to deal with, split by what it takes: a package pending or not finished
 * clears as is, a failure whose kind needs a change outside sealift lists that change, and a failure
 * with no known kind gets the general words.
 */
export function retryGroups(pkgs: ReportPackage[]): { notInNexus: number; asIs: number; changeFirst: { kind: string; count: number; words: string }[]; unknown: number } {
  const out = { notInNexus: 0, asIs: 0, unknown: 0 }
  const byKind = new Map<string, number>()
  for (const p of pkgs) {
    if (p.state !== "failed" && p.state !== "pending") {
      continue
    }
    out.notInNexus++
    const action = p.state === "failed" ? nextAction(p.kind) : { group: "as-is" }
    if (action.group === "as-is" || notFinished(p)) {
      out.asIs++
    } else if (action.group === "change-first" && p.kind) {
      byKind.set(p.kind, (byKind.get(p.kind) ?? 0) + 1)
    } else {
      out.unknown++
    }
  }
  const changeFirst = [...byKind].map(([kind, count]) => ({ kind, count, words: nextAction(kind).words }))
  changeFirst.sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind))
  return { ...out, changeFirst }
}

const ORDER = ["conflict", "mismatch", "nexus", "local"]
