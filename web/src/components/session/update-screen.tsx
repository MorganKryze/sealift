import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { CircleX, FlaskConical, LoaderCircle, Pencil, RotateCcw, TriangleAlert, Upload } from "lucide-react"
import { useId, useRef, useState } from "react"

import { createPipProject, createProject, getProject, listProjects, ProjectUploadError, type Project, type ProjectSummary } from "@/api/projects"
import { getInstance, getSettings } from "@/api/settings"
import { ContactCard } from "@/components/frame/brand"
import { DropZone, takeDroppedFiles, type DroppedFiles } from "@/components/projects/drop-zone"
import { CheckBlock } from "@/components/session/check-block"
import { DuplicateDialog } from "@/components/session/duplicate-dialog"
import { RequirementsBlock } from "@/components/session/requirements-block"
import { StepBar, stepBarStep } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { Term } from "@/components/ui/term"
import { failingChecks, ManifestPreviewError, parseManifestPreview, type ManifestPreview } from "@/lib/manifestPreview"
import { parseRequirementsPreview, type RequirementsPreview } from "@/lib/requirementsPreview"
import { sha256Hex } from "@/lib/utils"

interface PendingFile {
  file: File
  hash: string
  manifest: ManifestPreview
  modified?: Date
}

/** Requirements files read in the browser, waiting for a project name and Analyse. */
interface PendingPip {
  files: File[]
  preview: RequirementsPreview
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

/** Thrown when a dropped file is no text a requirements file can be. */
class NotTextError extends Error {
  constructor(public readonly file: string) {
    super(`${file} is not text`)
  }
}

// A requirements file is UTF-8 text, as the server reads it; a control character other than a line or tab
// break marks an archive or a binary, which no one means as requirements.
// eslint-disable-next-line no-control-regex
const BINARY = /[\u0000-\u0008\u000E-\u001F\u007F]/

async function readText(file: File): Promise<{ name: string; text: string }> {
  let text: string
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer())
  } catch {
    throw new NotTextError(file.name)
  }
  if (BINARY.test(text)) throw new NotTextError(file.name)
  return { name: file.name, text }
}

// The project's name as the server takes it: 1 to 100 characters once trimmed, with a letter or digit to make its id from.
const MAX_NAME = 100
const nameProblem = (name: string) => (name.trim() === "" ? "Name the project first" : /[a-z0-9]/i.test(name) ? undefined : "Use a letter or a digit in the name")

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`

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
export function UpdateScreen({ from }: { from?: string } = {}) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })
  const replaceRef = useRef<HTMLInputElement>(null)
  const addRef = useRef<HTMLInputElement>(null)
  const replaceId = useId()
  const addId = useId()
  const reasonId = useId()
  const nameId = useId()

  const [pending, setPending] = useState<PendingFile | null>(null)
  const [pip, setPip] = useState<PendingPip | null>(null)
  const [name, setName] = useState("")
  const [naming, setNaming] = useState(true)
  const [duplicate, setDuplicate] = useState<{ pending: PendingFile; match: ProjectSummary } | null>(null)
  const [fileError, setFileError] = useState<FileRefusal | null>(null)

  // The pip target is the deployment's, which the instance answer carries; it is read once requirements files are.
  const instanceQuery = useQuery({ queryKey: ["instance"], queryFn: getInstance, staleTime: Infinity, enabled: pip !== null })
  // A new crossing of a pip project keeps that project's name.
  const fromQuery = useQuery({ queryKey: ["project", from], queryFn: () => getProject(from as string), enabled: Boolean(from) })

  const opened = (project: Project) => {
    queryClient.setQueryData(["project", project.id], project)
    void queryClient.invalidateQueries({ queryKey: ["projects"] })
    void navigate({ to: "/crossings/$projectId", params: { projectId: project.id } })
  }
  const uploadMutation = useMutation({ mutationFn: (file: File) => createProject(file), onSuccess: opened })
  const pipMutation = useMutation({ mutationFn: ({ name, files }: { name: string; files: File[] }) => createPipProject(name, files), onSuccess: opened })

  async function handleFile(file: File) {
    setFileError(null)
    setPip(null)
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

  async function readPip(files: File[]) {
    setFileError(null)
    pipMutation.reset()
    try {
      const preview = parseRequirementsPreview(await Promise.all(files.map(readText)))
      const newest = Math.max(...files.map((file) => file.lastModified))
      setPending(null)
      setPip({ files, preview, modified: newest > 0 ? new Date(newest) : undefined })
    } catch (error) {
      setPending(null)
      setPip(null)
      const file = error instanceof NotTextError ? error.file : undefined
      setFileError({ file, problem: file ? "is not a package.json or a requirements file" : "The files could not be read", instead: AT_ROOT })
    }
  }

  // A choice from the zone or Replace takes the place of what is on screen; Add file joins the files on screen,
  // a file of the same name taking the place of the one it shares that name with.
  function handleDropped(dropped: DroppedFiles) {
    if (dropped.kind === "refused") {
      setPending(null)
      setPip(null)
      setFileError({ file: dropped.file, problem: dropped.message, instead: dropped.instead })
    } else if (dropped.kind === "npm") {
      void handleFile(dropped.file)
    } else {
      void readPip(dropped.files)
    }
  }

  function handleAdded(files: FileList | null) {
    if (!pip || !files || files.length === 0) return
    const added = Array.from(files)
    const dropped = takeDroppedFiles([...pip.files.filter((file) => !added.some((a) => a.name === file.name)), ...added])
    if (dropped.kind === "pip") void readPip(dropped.files)
    else if (dropped.kind === "refused") setFileError({ file: dropped.file, problem: dropped.message, instead: dropped.instead })
  }

  const target = settingsQuery.data?.target
  const pipTarget = instanceQuery.data?.policy.pipTarget
  const fromName = fromQuery.data?.name
  const askName = !from || fromQuery.isError
  const projectName = askName ? name.trim() : (fromName ?? "")
  const failing = pending ? failingChecks(pending.manifest).length : pip ? pip.preview.checks.filter((check) => !check.passed).length : 0
  const unnamed = pip && askName ? nameProblem(name) : undefined
  const starting = uploadMutation.isPending || pipMutation.isPending
  const startPip = () => {
    if (pip && projectName !== "") pipMutation.mutate({ name: projectName, files: pip.files })
  }
  const refusedLines = pipMutation.error instanceof ProjectUploadError ? pipMutation.error.requirements : []

  const chooser = (
    <>
      <label htmlFor={replaceId} className="sr-only">
        Replace the files
      </label>
      <input
        ref={replaceRef}
        id={replaceId}
        type="file"
        multiple
        tabIndex={-1}
        className="sr-only"
        onChange={(event) => {
          if (event.target.files && event.target.files.length > 0) handleDropped(takeDroppedFiles(event.target.files))
          event.target.value = ""
        }}
      />
    </>
  )

  const startFailed = (retry: () => void, what: string) => (
    <>
      <div role="alert" className="tinted-bad animate-enter mt-5 flex flex-wrap items-center gap-3 px-4 py-3">
        <CircleX aria-hidden="true" className="size-5 flex-none text-bad" />
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-ink">Analysis did not start</p>
          <p className="text-[13px] text-ink-2">{`${startCause(uploadMutation.error ?? pipMutation.error)}; ${what}`}</p>
        </div>
        <Button type="button" size="page" onClick={retry}>
          <RotateCcw aria-hidden="true" />
          Retry
        </Button>
      </div>
      <ContactCard />
    </>
  )

  const actions = (reason: string | undefined, warn: boolean, start: () => void) => (
    <div className="mt-7 flex flex-wrap items-center justify-end gap-x-4 gap-y-2">
      {reason ? (
        <span id={reasonId} className={warn ? "inline-flex items-center gap-1.5 text-[13px] text-warn" : "inline-flex items-center gap-1.5 text-[13px] text-muted"}>
          {warn ? <TriangleAlert aria-hidden="true" className="size-4" /> : <Pencil aria-hidden="true" className="size-4" />}
          {reason}
        </span>
      ) : null}
      <Button
        type="button"
        size="page"
        aria-disabled={reason ? true : undefined}
        aria-describedby={reason ? reasonId : undefined}
        aria-busy={starting ? true : undefined}
        onClick={() => {
          if (!reason && !starting) start()
        }}
      >
        {starting ? <LoaderCircle aria-hidden="true" className="motion-safe:animate-spin" /> : <FlaskConical aria-hidden="true" />}
        {starting ? "Starting" : "Analyse"}
      </Button>
    </div>
  )

  const titleClass = "text-[28px] font-bold tracking-tight text-ink [overflow-wrap:anywhere]"
  const pipReason = failing > 0 ? `${failing} ${failing === 1 ? "check" : "checks"} to fix first` : (unnamed ?? (projectName === "" ? "Opens once the project's name is read" : undefined))

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={STEPS} />
      {pending ? (
        <>
          <div className="mb-5">
            <h1 className={titleClass}>{`Update ${pending.manifest.name}`}</h1>
            {target ? (
              <p className="mt-1 text-muted">
                npm · Node <span className="figure text-ink-2">{target.node}</span> · {target.os} {target.cpu}
              </p>
            ) : null}
          </div>
          <CheckBlock key={pending.hash} manifest={pending.manifest} modified={pending.modified} busy={starting} onReplace={() => replaceRef.current?.click()} />
          {chooser}
          {uploadMutation.isError
            ? startFailed(() => uploadMutation.mutate(pending.file), "your file is still here.")
            : actions(failing > 0 ? `${failing} ${failing === 1 ? "check" : "checks"} to fix first` : undefined, true, () => uploadMutation.mutate(pending.file))}
        </>
      ) : pip ? (
        <>
          <div className="mb-5">
            {askName && naming ? (
              <h1 className={`${titleClass} flex flex-wrap items-center gap-x-3 gap-y-2`}>
                <span>Update</span>
                <label htmlFor={nameId} className="sr-only">
                  Project name
                </label>
                <input
                  id={nameId}
                  // The name is the one thing requirements files do not carry, so the step starts there.
                  autoFocus
                  value={name}
                  maxLength={MAX_NAME}
                  placeholder="project name"
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setName(event.target.value)}
                  onBlur={() => {
                    if (!nameProblem(name)) setNaming(false)
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !nameProblem(name)) setNaming(false)
                  }}
                  className="h-11 w-full max-w-80 min-w-0 rounded-lg border border-field bg-bg px-3 text-[24px] font-normal tracking-normal text-ink placeholder:text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink"
                />
              </h1>
            ) : (
              <div className="flex flex-wrap items-center gap-x-2">
                <h1 className={titleClass}>{projectName ? `Update ${projectName}` : "Update"}</h1>
                {askName ? (
                  <Button type="button" variant="ghost" size="icon" aria-label="Rename the project" disabled={starting} onClick={() => setNaming(true)}>
                    <Pencil aria-hidden="true" />
                  </Button>
                ) : null}
              </div>
            )}
            {pipTarget ? (
              <p className="mt-1 text-muted">
                pip · Python <span className="figure text-ink-2">{pipTarget.python}</span> · {pipTarget.os} {pipTarget.cpu} · glibc <span className="figure text-ink-2">{pipTarget.glibc}</span>{" "}
                <Term id="target">
                  <span className="mt-2 block font-medium text-ink">Check on one of them</span>
                  <span className="mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 font-mono text-xs [overflow-wrap:anywhere]">
                    <span className="text-ink">python3 -VV</span>
                    <span>{`Python ${pipTarget.python}`}</span>
                    <span className="text-ink">ldd --version</span>
                    <span>{`ldd (GNU libc) ${pipTarget.glibc}`}</span>
                  </span>
                </Term>
              </p>
            ) : null}
          </div>
          <RequirementsBlock
            key={pip.files.map((file) => file.name).join("\n")}
            preview={pip.preview}
            modified={pip.modified}
            busy={starting}
            onReplace={() => replaceRef.current?.click()}
            onAddFiles={pip.preview.files.some((file) => file.missing.length > 0) ? () => addRef.current?.click() : undefined}
          />
          {chooser}
          <label htmlFor={addId} className="sr-only">
            Add requirements files
          </label>
          <input
            ref={addRef}
            id={addId}
            data-add-files
            type="file"
            multiple
            tabIndex={-1}
            className="sr-only"
            onChange={(event) => {
              handleAdded(event.target.files)
              event.target.value = ""
            }}
          />
          {refusedLines.length > 0 ? (
            <>
              <div role="alert" className="tinted-bad animate-enter mt-5 flex flex-wrap items-start gap-3 px-4 py-3">
                <CircleX aria-hidden="true" className="mt-0.5 size-5 flex-none text-bad" />
                <div className="min-w-0 flex-1">
                  <p className="font-semibold text-ink">Analysis did not start</p>
                  <p className="text-[13px] text-ink-2">{`${plural(refusedLines.length, "problem", "problems")} in the requirements files`}</p>
                  <ul className="mt-2">
                    {refusedLines.map((problem, i) => (
                      <li
                        key={`${problem.file}:${problem.line ?? 0}:${i}`}
                        className="grid min-h-8 min-w-0 grid-cols-1 items-baseline gap-x-4 gap-y-0.5 border-b border-bad-line/50 py-1.5 text-[13px] sm:grid-cols-[minmax(0,11rem)_minmax(0,1fr)]"
                      >
                        <span className="min-w-0 font-mono text-xs text-ink-2 [overflow-wrap:anywhere]">{problem.line ? `${problem.file}:${problem.line}` : problem.file}</span>
                        <span className="min-w-0">
                          {problem.text ? <span className="block font-mono text-xs font-semibold text-ink [font-variant-ligatures:none] [overflow-wrap:anywhere]">{problem.text}</span> : null}
                          <span className="block text-ink-2 [overflow-wrap:anywhere]">{problem.reason}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
                <Button type="button" size="page" onClick={() => replaceRef.current?.click()}>
                  <Upload aria-hidden="true" />
                  Replace files
                </Button>
              </div>
              <ContactCard />
            </>
          ) : pipMutation.isError ? (
            startFailed(startPip, "your files are still here.")
          ) : (
            actions(pipReason, failing > 0, startPip)
          )}
        </>
      ) : (
        <>
          <h1 className="mb-5 text-[28px] font-bold tracking-tight text-ink">Update a project</h1>
          <DropZone onFiles={handleDropped} />
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
