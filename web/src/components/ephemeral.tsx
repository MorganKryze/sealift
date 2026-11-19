import { useMutation, useQuery } from "@tanstack/react-query"
import { useState } from "react"

import { ProblemError } from "@/api/client"
import { deleteProject } from "@/api/projects"
import { getInstance } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"

/** The deployment mode never changes while the server runs, so it is read once. */
function useInstance() {
  return useQuery({ queryKey: ["instance"], queryFn: getInstance, staleTime: Infinity })
}

/** Shown under the topbar on every screen of an ephemeral instance. */
export function EphemeralBanner() {
  const { data } = useInstance()
  if (!data?.ephemeral) return null
  return (
    <div role="note" className="border-b border-line bg-card">
      <p className="mx-auto max-w-240 px-5 py-2 text-sm text-muted">
        <span className="font-medium text-ink">Ephemeral instance.</span> A project and the caches it filled are erased after {data.idleMinutes}{" "}
        minutes without activity, or as soon as you erase it from its archive screen.
      </p>
    </div>
  )
}

interface EraseProjectProps {
  projectId: string
  /** Called once the server erased the project, to leave its screens. */
  onErased: () => void
}

/** The archive screen's erase control, on an ephemeral instance only. */
export function EraseProject({ projectId, onErased }: EraseProjectProps) {
  const { data } = useInstance()
  const [confirming, setConfirming] = useState(false)
  const erase = useMutation({
    mutationFn: () => deleteProject(projectId),
    onSuccess: () => {
      // The tab keeps the version selection in sessionStorage, package names
      // included: nothing of the project may outlive the erase here either.
      try {
        sessionStorage.clear()
      } catch {
        // Storage disabled: there is nothing in it to clear.
      }
      onErased()
    },
  })
  const failure = erase.error instanceof ProblemError ? erase.error : null

  if (!data?.ephemeral) return null
  return (
    <section className="mt-7 flex flex-col gap-3">
      {confirming ? (
        <div
          role="alertdialog"
          aria-label="Erase this project"
          onKeyDown={(event) => {
            if (event.key === "Escape") setConfirming(false)
          }}
          className="rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-3.5 text-sm"
        >
          <p className="font-medium text-ink">Erase this project?</p>
          <p className="mt-1 text-ink">
            Its manifest, analyses, reports and archive leave this server, with the caches that recorded its packages. Download the archive,
            manifest.json and manifest.json.sig first: nothing brings them back.
          </p>
          <div className="mt-3 flex gap-2">
            <Button type="button" size="sm" disabled={erase.isPending} onClick={() => erase.mutate()}>
              Erase
            </Button>
            <Button type="button" size="sm" variant="ghost" autoFocus onClick={() => setConfirming(false)}>
              Keep it
            </Button>
          </div>
        </div>
      ) : (
        <div>
          <Button type="button" variant="outline" onClick={() => setConfirming(true)}>
            Erase this project now
          </Button>
        </div>
      )}
      {failure ? <ProblemNotice status={failure.status} problem={failure.problem} /> : null}
    </section>
  )
}
