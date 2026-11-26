import { useMutation, useQuery } from "@tanstack/react-query"
import { Timer, Trash2 } from "lucide-react"
import { useEffect, useId, useRef, useState } from "react"

import { ProblemError } from "@/api/client"
import { deleteProject } from "@/api/projects"
import { getInstance } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"

/** The deployment mode never changes while the server runs, so it is read once. */
export function useInstance() {
  return useQuery({ queryKey: ["instance"], queryFn: getInstance, staleTime: Infinity })
}

/** Shown under the topbar on every screen of an ephemeral instance. */
export function EphemeralBanner() {
  const { data } = useInstance()
  if (!data?.ephemeral) return null
  return (
    <div role="note" className="border-b border-line bg-card">
      <p className="mx-auto max-w-240 px-5 py-2 text-sm text-muted">
        <span className="font-medium text-ink">Ephemeral instance.</span> A project and the caches it filled are erased after {data.idleMinutes} {data.idleMinutes === 1 ? "minute" : "minutes"}{" "}
        without activity, or as soon as you erase it from its archive screen.
      </p>
    </div>
  )
}

interface EraseProjectProps {
  projectId: string
  /** The instance's idle delay, after which the sweep erases the project. */
  idleMinutes: number
  /** Called once the server erased the project, to leave its screens. */
  onErased: () => void
}

/** The tab keeps the version selection in sessionStorage, package names included. */
function clearTabStorage() {
  try {
    sessionStorage.clear()
  } catch {
    // Storage disabled: there is nothing in it to clear.
  }
}

/**
 * Sealed's erase row on an ephemeral instance: a closed amber row with the idle delay and Erase now. Erase now
 * asks in place, in red, with the focus on Keep it; only Erase erases, and Keep it or Escape gives the focus back.
 */
export function EraseProject({ projectId, idleMinutes, onErased }: EraseProjectProps) {
  const [confirming, setConfirming] = useState(false)
  const section = useRef<HTMLElement>(null)
  const focusNext = useRef<"keep" | "erase-now" | null>(null)
  const titleId = useId()
  const erase = useMutation({
    mutationFn: () => deleteProject(projectId),
    onSuccess: () => {
      clearTabStorage()
      onErased()
    },
    onError: (error) => {
      // Only a 409 (a job runs) left the project as it was. A 404 means the
      // sweep erased it already; any other failure came after the delete.
      if (!(error instanceof ProblemError) || error.status !== 409) clearTabStorage()
    },
  })
  const failure = erase.error instanceof ProblemError ? erase.error : null

  useEffect(() => {
    const target = focusNext.current
    focusNext.current = null
    if (target) section.current?.querySelector<HTMLElement>(`[data-focus=${target}]`)?.focus()
  }, [confirming])

  function ask(next: boolean) {
    focusNext.current = next ? "keep" : "erase-now"
    setConfirming(next)
  }

  return (
    <section ref={section} className="mt-5 flex flex-col gap-3">
      {confirming ? (
        <div
          role="alertdialog"
          aria-labelledby={titleId}
          onKeyDown={(event) => {
            if (event.key === "Escape") ask(false)
          }}
          className="tinted-bad flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5"
        >
          <Trash2 aria-hidden="true" className="size-4 flex-none text-bad" />
          <div className="min-w-0 flex-1">
            <p id={titleId} className="text-sm font-semibold text-ink">
              Erase this project and its files now?
            </p>
            <p className="text-[13px] text-ink-2">Download what you carry first.</p>
          </div>
          <Button type="button" variant="outline" data-focus="keep" onClick={() => ask(false)}>
            Keep it
          </Button>
          <Button
            type="button"
            aria-busy={erase.isPending ? true : undefined}
            onClick={() => {
              if (!erase.isPending) erase.mutate()
            }}
            className="border-bad bg-bad text-bg hover:border-bad hover:bg-bad"
          >
            <Trash2 aria-hidden="true" />
            Erase
          </Button>
        </div>
      ) : (
        <div className="tinted-warn flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
          <Timer aria-hidden="true" className="size-4 flex-none text-warn" />
          <p className="min-w-0 flex-1 text-sm text-ink">
            This project and its files are erased after <span className="figure">{`${idleMinutes} ${idleMinutes === 1 ? "minute" : "minutes"}`}</span> without activity.
          </p>
          <Button type="button" variant="outline" data-focus="erase-now" onClick={() => ask(true)}>
            <Trash2 aria-hidden="true" />
            Erase now
          </Button>
        </div>
      )}
      {failure ? <ProblemNotice status={failure.status} problem={failure.problem} /> : null}
    </section>
  )
}
