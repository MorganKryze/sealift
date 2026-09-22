import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { useState } from "react"

import { createProject, listProjects, ProjectUploadError, type ProjectSummary } from "@/api/projects"
import { getSettings } from "@/api/settings"
import { DropZone } from "@/components/projects/drop-zone"
import { DropPreview } from "@/components/session/drop-preview"
import { DuplicateDialog } from "@/components/session/duplicate-dialog"
import { Badge } from "@/components/ui/badge"
import { ManifestPreviewError, parseManifestPreview, type ManifestPreview } from "@/lib/manifestPreview"
import { cn, formatWhen, isJobActive, sha256Hex } from "@/lib/utils"

interface PendingFile {
  file: File
  hash: string
  manifest: ManifestPreview
}

/**
 * The landing screen: drop a manifest, or resume a past session. A file is
 * only ever uploaded once the drop preview's Analyse button is pressed;
 * selecting a file just parses and hashes it locally, to check for a
 * byte-for-byte duplicate before anything reaches the server.
 */
export function HomeScreen() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })
  const historyQuery = useQuery({ queryKey: ["projects"], queryFn: () => listProjects() })

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
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-ink">New session</h1>
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

      <HistoryList
        query={historyQuery}
        onOpen={(id) => void navigate({ to: "/sessions/$sessionId", params: { sessionId: id } })}
      />

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

interface HistoryListProps {
  query: UseQueryResult<ProjectSummary[]>
  onOpen: (id: string) => void
}

function HistoryList({ query, onOpen }: HistoryListProps) {
  if (query.isPending) {
    return <p className="mt-9 text-sm text-muted">Loading past sessions…</p>
  }

  if (query.isError) {
    return (
      <p role="alert" className="mt-9 text-sm text-severity-critical-fg">
        Could not load past sessions.
      </p>
    )
  }

  const sessions = query.data
  if (sessions.length === 0) {
    return null
  }

  return (
    <div className="mt-9">
      <div className="mb-2.5 flex items-baseline gap-2.5">
        <h2 className="text-lg font-semibold text-ink">Past sessions</h2>
        <span className="text-sm text-muted">{sessions.length}</span>
      </div>
      <div className="rounded-xl border border-line">
        {sessions.map((session, index) => {
          const badge = sessionStatus(session)
          const when = session.lastExport?.createdAt ?? session.lastAnalysis?.createdAt
          return (
            <button
              key={session.id}
              type="button"
              onClick={() => onOpen(session.id)}
              className={cn(
                "grid w-full grid-cols-[1fr_auto_auto] items-center gap-4 px-4.5 py-3.5 text-left hover:bg-card",
                index > 0 && "border-t border-line",
              )}
            >
              <span>
                <span className="font-semibold text-ink">{session.name}</span>
                <br />
                <span className="text-sm text-muted">
                  {session.target.os}/{session.target.cpu} · {session.target.libc}
                </span>
              </span>
              <span className="text-sm text-muted">{when ? formatWhen(when) : ""}</span>
              <Badge variant={badge.variant}>{badge.label}</Badge>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function sessionStatus(session: ProjectSummary): { label: string; variant: "accent" | "critical" | "default" } {
  const { lastAnalysis, lastExport } = session
  const failedStates = new Set(["failed", "cancelled", "interrupted"])

  if (lastExport?.state === "done") {
    return { label: "Archive ready", variant: "accent" }
  }
  if (lastExport && failedStates.has(lastExport.state)) {
    return { label: "Export failed", variant: "critical" }
  }
  if (isJobActive(lastExport)) {
    return { label: "Exporting", variant: "default" }
  }
  if (lastAnalysis?.state === "done") {
    return { label: "Awaiting export", variant: "default" }
  }
  if (lastAnalysis && failedStates.has(lastAnalysis.state)) {
    return { label: "Analysis failed", variant: "critical" }
  }
  if (isJobActive(lastAnalysis)) {
    return { label: "Analysing", variant: "default" }
  }
  return { label: "Not analysed yet", variant: "default" }
}
