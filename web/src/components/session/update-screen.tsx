import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { useState } from "react"

import { createProject, listProjects, ProjectUploadError, type ProjectSummary } from "@/api/projects"
import { getSettings } from "@/api/settings"
import { DropZone } from "@/components/projects/drop-zone"
import { DropPreview } from "@/components/session/drop-preview"
import { DuplicateDialog } from "@/components/session/duplicate-dialog"
import { StepBar, stepBarStep } from "@/components/step-bar"
import { ManifestPreviewError, parseManifestPreview, type ManifestPreview } from "@/lib/manifestPreview"
import { sha256Hex } from "@/lib/utils"

interface PendingFile {
  file: File
  hash: string
  manifest: ManifestPreview
}

const STEPS = [stepBarStep("drop", "available", true), stepBarStep("analysis", "upcoming", false), stepBarStep("review", "upcoming", false), stepBarStep("export", "upcoming", false)]

/**
 * Update's first step: drop a manifest. A file is only ever uploaded once the
 * drop preview's Analyse button is pressed; selecting a file just parses and
 * hashes it locally, to check for a byte-for-byte duplicate before anything
 * reaches the server.
 */
export function UpdateScreen() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })

  const [pending, setPending] = useState<PendingFile | null>(null)
  const [duplicate, setDuplicate] = useState<{ pending: PendingFile; match: ProjectSummary } | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)

  const uploadMutation = useMutation({
    mutationFn: (file: File) => createProject(file),
    onSuccess: (project) => {
      queryClient.setQueryData(["project", project.id], project)
      void queryClient.invalidateQueries({ queryKey: ["projects"] })
      void navigate({ to: "/sessions/$sessionId/analysis", params: { sessionId: project.id } })
    },
  })

  async function handleFile(file: File) {
    setFileError(null)
    uploadMutation.reset()
    try {
      const buffer = await file.arrayBuffer()
      const hash = await sha256Hex(buffer)
      const manifest = parseManifestPreview(new TextDecoder().decode(buffer), file.name.replace(/\.json$/i, ""))
      const next: PendingFile = { file, hash, manifest }
      // The duplicate check only saves the user a repeat analysis: when the
      // lookup itself fails, go on to the preview rather than blame the file.
      const matches = await listProjects(hash).catch(() => [])
      if (matches.length > 0) {
        setDuplicate({ pending: next, match: matches[0] })
      } else {
        setPending(next)
      }
    } catch (error) {
      setFileError(error instanceof ManifestPreviewError ? error.message : "Could not read that file.")
    }
  }

  if (pending) {
    return (
      <DropPreview
        manifest={pending.manifest}
        target={settingsQuery.data?.target}
        analysing={uploadMutation.isPending}
        error={uploadMutation.error instanceof ProjectUploadError ? uploadMutation.error : null}
        onAnalyse={() => uploadMutation.mutate(pending.file)}
        onChangeFile={() => {
          uploadMutation.reset()
          setPending(null)
        }}
      />
    )
  }

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <StepBar steps={STEPS} />
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-ink">Update a project</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          Drop a project&rsquo;s package.json. sealift finds the versions that fix its CVEs and packs them for the
          Nexus import.
        </p>
      </div>

      <div className="mt-6">
        <DropZone onFile={(file) => void handleFile(file)} onInvalidFile={setFileError}>
          Direct dependencies must be pinned to exact versions, such as 4.17.1.
          {settingsQuery.data ? (
            <>
              {" "}
              Target: {settingsQuery.data.target.os}/{settingsQuery.data.target.cpu} · {settingsQuery.data.target.libc}{" "}
              · Node {settingsQuery.data.target.node}.
            </>
          ) : null}
        </DropZone>
      </div>
      {fileError ? (
        <p role="alert" className="mt-3 text-sm text-severity-critical-fg">
          {fileError}
        </p>
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
            void navigate({ to: "/sessions/$sessionId", params: { sessionId: id } })
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
