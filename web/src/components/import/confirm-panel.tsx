import { Link, useNavigate } from "@tanstack/react-router"
import { useEffect, useRef, useState } from "react"

import { ApiFailure } from "@/components/import/api-failure"
import { Button } from "@/components/ui/button"
import { ImportApiError, SessionEnded } from "@/import/api/client"
import { useArchives, useImports, useStartImport, validSha256, type Archive } from "@/import/api/queries"
import { archiveName, type Import } from "@/import/lib/outcome"

import { ImportFailure } from "./import-failure"

const BAD_SHA = "The sha256 is 64 hexadecimal digits, 0 to 9 and a to f. Check the value you copied, or leave the field empty."

interface ConfirmPanelProps {
  archive: Archive
  /** The user's own queued or running import: the new one waits for it. */
  ownActive?: Import
  onClose: () => void
}

/** The panel under an archive row: what the import does, the optional sha256 and the button that starts it. */
export function ConfirmPanel({ archive, ownActive, onClose }: ConfirmPanelProps) {
  const { folder, file } = archiveName(archive.key)
  const label = `${folder}${file}`
  const [sha, setSha] = useState("")
  const [invalid, setInvalid] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const start = useStartImport()
  const navigate = useNavigate()
  const archives = useArchives()
  const imports = useImports()

  useEffect(() => {
    input.current?.focus()
  }, [])

  const submit = () => {
    if (!validSha256(sha)) {
      setInvalid(true)
      return
    }
    setInvalid(false)
    const expectedSha256 = sha.trim()
    start.mutate(expectedSha256 ? { archive: archive.key, expectedSha256 } : { archive: archive.key }, {
      onSuccess: (created) => void navigate({ to: "/imports/$importId", params: { importId: created.id } }),
    })
  }
  const refresh = () => {
    void Promise.all([archives.refetch(), imports.refetch()])
    onClose()
  }

  const error = start.error
  const conflictId = error instanceof ImportApiError && error.status === 409 ? ((error.problem as { importId?: string } | null)?.importId ?? "") : ""

  return (
    <section aria-label={`Start the import of ${label}`} className="col-span-3 -mx-1 rounded-lg border border-line bg-card p-5" onKeyDown={(e) => e.key === "Escape" && onClose()}>
      <p className="max-w-[72ch] text-sm leading-6">
        The import reads the archive and its manifest.json, checks the archive&apos;s sha256, publishes each package to Nexus and removes nothing from MinIO until every package is in Nexus.{" "}
        {ownActive ? (
          <>
            Your import of {archiveName(ownActive.archive.key).folder}
            {archiveName(ownActive.archive.key).file} is {ownActive.outcome}. This one waits for it.
          </>
        ) : (
          "Imports run one at a time for every user, so this one may wait its turn."
        )}
      </p>
      <form
        className="mt-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <label htmlFor="expected-sha256" className="block text-sm font-medium">
          Expected sha256 (optional)
        </label>
        <p id="expected-sha256-help" className="mt-1 max-w-[72ch] text-xs text-muted">
          Paste the archive&apos;s sha256 as you received it through another channel. A different archive is refused and nothing is published.
        </p>
        <input
          id="expected-sha256"
          ref={input}
          value={sha}
          onChange={(e) => setSha(e.target.value)}
          spellCheck={false}
          autoComplete="off"
          aria-invalid={invalid}
          aria-describedby={invalid ? "expected-sha256-help expected-sha256-error" : "expected-sha256-help"}
          className="mt-2 h-8 w-full max-w-[72ch] rounded-md border border-line bg-background px-3 font-mono text-[13px] text-ink outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        {invalid ? (
          <p id="expected-sha256-error" className="mt-2 max-w-[72ch] text-sm text-severity-critical-fg">
            {BAD_SHA}
          </p>
        ) : null}
        <div className="mt-4 flex items-center gap-3">
          <Button type="submit" size="sm" disabled={start.isPending}>
            {start.isPending ? "Starting" : "Start the import"}
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </form>
      {error ? (
        <div className="mt-4">
          <Failure error={error} conflictId={conflictId} onRetry={submit} onRefresh={refresh} />
        </div>
      ) : null}
    </section>
  )
}

function Failure({ error, conflictId, onRetry, onRefresh }: { error: Error; conflictId: string; onRetry: () => void; onRefresh: () => void }) {
  if (error instanceof SessionEnded) {
    return <ApiFailure error={error} />
  }
  if (!(error instanceof ImportApiError)) {
    return <ApiFailure error={error} onRetry={onRetry} />
  }
  const action = "inline-flex h-8 items-center justify-center rounded-md border border-line bg-background px-3 text-sm font-medium text-ink outline-none hover:bg-card focus-visible:ring-2 focus-visible:ring-accent"
  const detail = error.problem?.detail ?? error.problem?.title ?? "The request failed."
  if (error.status === 409 && conflictId) {
    return (
      <div role="alert" className="rounded-lg border border-severity-critical p-4">
        <p className="text-sm">This archive has an import that has not completed.</p>
        <p className="mt-2 text-sm text-muted">Follow or retry that import instead of starting a second one.</p>
        <div className="mt-3">
          <Link to="/imports/$importId" params={{ importId: conflictId }} className={action}>
            Open that import
          </Link>
        </div>
      </div>
    )
  }
  if (error.status === 409) {
    return (
      <div role="alert" className="rounded-lg border border-severity-critical p-4">
        <p className="text-sm [overflow-wrap:anywhere]">{detail}</p>
        <p className="mt-2 text-sm text-muted">Nothing was started.</p>
      </div>
    )
  }
  if (error.status === 404) {
    return (
      <div role="alert" className="rounded-lg border border-severity-critical p-4">
        <p className="text-sm">This archive is no longer in your folder.</p>
        <p className="mt-2 text-sm text-muted">Refresh the list to see what the folder holds now. Nothing was started.</p>
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={onRefresh}>
            Refresh
          </Button>
        </div>
      </div>
    )
  }
  return (
    <ImportFailure
      title="The import could not be started"
      cause={detail}
      next="Try again. Nothing was started."
      detail={`${error.status} ${error.problem?.title ?? ""}`.trim()}
      onRetry={onRetry}
    />
  )
}
