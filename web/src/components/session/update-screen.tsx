import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { CircleX, FlaskConical, LoaderCircle, RotateCcw, TriangleAlert } from "lucide-react"
import { useId, useRef, useState } from "react"

import { createProject, listProjects, ProjectUploadError, type ProjectSummary } from "@/api/projects"
import { getSettings } from "@/api/settings"
import { ContactCard } from "@/components/frame/brand"
import { DropZone, takeJsonFile } from "@/components/projects/drop-zone"
import { CheckBlock } from "@/components/session/check-block"
import { DuplicateDialog } from "@/components/session/duplicate-dialog"
import { StepBar, stepBarStep } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { failingChecks, ManifestPreviewError, parseManifestPreview, type ManifestPreview } from "@/lib/manifestPreview"
import { sha256Hex } from "@/lib/utils"

interface PendingFile {
  file: File
  hash: string
  manifest: ManifestPreview
  modified?: Date
}

/** A file refused before anything was sent: the file and what is wrong with it, then what to drop instead. */
interface FileRefusal {
  file?: string
  problem: string
  instead: string
}

const STEPS = [stepBarStep("drop", "available", true), stepBarStep("analysis", "upcoming", false), stepBarStep("review", "upcoming", false), stepBarStep("export", "upcoming", false)]

const AT_ROOT = "Drop the package.json at your project's root; nothing was sent."

function refusal(name: string, error: unknown): FileRefusal {
  if (error instanceof ManifestPreviewError) {
    if (error.kind === "no-dependency") return { file: name, problem: "lists no dependency", instead: "Drop the package.json of a project with dependencies; nothing was sent." }
    return { file: name, problem: error.kind === "not-json" ? "is not valid JSON" : "is not a package.json", instead: AT_ROOT }
  }
  return { file: name, problem: "could not be read", instead: AT_ROOT }
}

// The cause of a start the server did not take, in words; Retry is the action in every case.
function startCause(error: unknown): string {
  if (!(error instanceof ProjectUploadError)) return "This instance did not start the analysis"
  const { status, problem } = error
  if (status === 0 || status === 502 || status === 503 || status === 504) return "No answer from this instance"
  if (problem?.type === "tools-missing") return "This instance is still preparing its tools"
  if (status === 413) return "The file is larger than this instance accepts"
  const first = problem?.errors?.[0]
  if (first) {
    const more = (problem?.errors?.length ?? 1) - 1
    const what = [first.name, first.value].filter(Boolean).join(" ") || first.field
    return `This instance refused ${what}: ${first.reason}${more > 0 ? ` and ${more} more` : ""}`
  }
  return `This instance refused the file (HTTP ${status})`
}

/**
 * Update's first step, Check. A chosen file is read and hashed in the browser: the only request before
 * Analyse is the lookup of a byte-identical file analysed before. Analyse sends the file, and the server
 * queues its analysis.
 */
export function UpdateScreen() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })
  const replaceRef = useRef<HTMLInputElement>(null)
  const replaceId = useId()
  const reasonId = useId()

  const [pending, setPending] = useState<PendingFile | null>(null)
  const [duplicate, setDuplicate] = useState<{ pending: PendingFile; match: ProjectSummary } | null>(null)
  const [fileError, setFileError] = useState<FileRefusal | null>(null)

  const uploadMutation = useMutation({
    mutationFn: (file: File) => createProject(file),
    onSuccess: (project) => {
      queryClient.setQueryData(["project", project.id], project)
      void queryClient.invalidateQueries({ queryKey: ["projects"] })
      void navigate({ to: "/crossings/$projectId", params: { projectId: project.id } })
    },
  })

  async function handleFile(file: File) {
    setFileError(null)
    uploadMutation.reset()
    try {
      const buffer = await file.arrayBuffer()
      const hash = await sha256Hex(buffer)
      const manifest = parseManifestPreview(new TextDecoder().decode(buffer), file.name.replace(/\.json$/i, ""))
      const next: PendingFile = { file, hash, manifest, modified: file.lastModified > 0 ? new Date(file.lastModified) : undefined }
      // The duplicate check only saves the user a repeat analysis: when the
      // lookup itself fails, go on to the check rather than blame the file.
      const matches = await listProjects(hash).catch(() => [])
      if (matches.length > 0) {
        setDuplicate({ pending: next, match: matches[0] })
      } else {
        setPending(next)
      }
    } catch (error) {
      setPending(null)
      setFileError(refusal(file.name, error))
    }
  }

  function handleInvalid(name: string | null) {
    setPending(null)
    setFileError(name === null ? { problem: "Several files were dropped", instead: AT_ROOT } : { file: name, problem: "is not a package.json", instead: AT_ROOT })
  }

  const target = settingsQuery.data?.target
  const failing = pending ? failingChecks(pending.manifest).length : 0
  const starting = uploadMutation.isPending

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={STEPS} />
      {pending ? (
        <>
          <div className="mb-5">
            <h1 className="text-[28px] font-bold tracking-tight text-ink [overflow-wrap:anywhere]">{`Update ${pending.manifest.name}`}</h1>
            {target ? (
              <p className="mt-1 text-muted">
                npm · Node <span className="figure text-ink-2">{target.node}</span> · {target.os} {target.cpu}
              </p>
            ) : null}
          </div>
          <CheckBlock key={pending.hash} manifest={pending.manifest} modified={pending.modified} busy={starting} onReplace={() => replaceRef.current?.click()} />
          <label htmlFor={replaceId} className="sr-only">
            Replace package.json
          </label>
          <input
            ref={replaceRef}
            id={replaceId}
            type="file"
            tabIndex={-1}
            accept="application/json,.json"
            className="sr-only"
            onChange={(event) => {
              takeJsonFile(event.target.files, { onFile: (file) => void handleFile(file), onInvalidFile: handleInvalid })
              event.target.value = ""
            }}
          />
          {uploadMutation.isError ? (
            <>
              <div role="alert" className="tinted-bad animate-enter mt-5 flex flex-wrap items-center gap-3 px-4 py-3">
                <CircleX aria-hidden="true" className="size-5 flex-none text-bad" />
                <div className="min-w-0 flex-1">
                  <p className="font-semibold text-ink">Analysis did not start</p>
                  <p className="text-[13px] text-ink-2">{`${startCause(uploadMutation.error)}; your file is still here.`}</p>
                </div>
                <Button type="button" size="page" onClick={() => uploadMutation.mutate(pending.file)}>
                  <RotateCcw aria-hidden="true" />
                  Retry
                </Button>
              </div>
              <ContactCard />
            </>
          ) : (
            <div className="mt-7 flex flex-wrap items-center justify-end gap-x-4 gap-y-2">
              {failing > 0 ? (
                <span id={reasonId} className="inline-flex items-center gap-1.5 text-[13px] text-warn">
                  <TriangleAlert aria-hidden="true" className="size-4" />
                  {`${failing} ${failing === 1 ? "check" : "checks"} to fix first`}
                </span>
              ) : null}
              <Button
                type="button"
                size="page"
                aria-disabled={failing > 0 ? true : undefined}
                aria-describedby={failing > 0 ? reasonId : undefined}
                aria-busy={starting ? true : undefined}
                onClick={() => {
                  if (failing === 0 && !starting) uploadMutation.mutate(pending.file)
                }}
              >
                {starting ? <LoaderCircle aria-hidden="true" className="motion-safe:animate-spin" /> : <FlaskConical aria-hidden="true" />}
                {starting ? "Starting" : "Analyse"}
              </Button>
            </div>
          )}
        </>
      ) : (
        <>
          <h1 className="mb-5 text-[28px] font-bold tracking-tight text-ink">Update a project</h1>
          <DropZone onFile={(file) => void handleFile(file)} onInvalidFile={handleInvalid} />
        </>
      )}

      {fileError ? (
        <div role="alert" className="tinted-bad animate-enter mt-4 flex items-start gap-3 px-4 py-3">
          <CircleX aria-hidden="true" className="mt-0.5 size-5 flex-none text-bad" />
          <div className="min-w-0">
            <p className="font-semibold text-ink [overflow-wrap:anywhere]">
              {fileError.file ? (
                <>
                  <span className="font-mono">{fileError.file}</span> {fileError.problem}
                </>
              ) : (
                fileError.problem
              )}
            </p>
            <p className="text-[13px] text-ink-2">{fileError.instead}</p>
          </div>
        </div>
      ) : null}

      {duplicate ? (
        <DuplicateDialog
          match={duplicate.match}
          onOpenChange={(open) => {
            if (!open) {
              setDuplicate(null)
              // The dialog opened from a file choice, not a trigger, so focus goes back to the file button by hand.
              requestAnimationFrame(() => document.querySelector<HTMLElement>("[data-choose-file]")?.focus())
            }
          }}
          onResume={() => {
            const id = duplicate.match.id
            setDuplicate(null)
            void navigate({ to: "/crossings/$projectId", params: { projectId: id } })
          }}
          onStartNew={() => {
            setPending(duplicate.pending)
            setDuplicate(null)
          }}
        />
      ) : null}
    </div>
  )
}
