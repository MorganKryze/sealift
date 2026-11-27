import { TriangleAlert } from "lucide-react"

import { archiveName, ecosystemOf, latestAttempt, type Import } from "@/import/lib/outcome"
import { formatBytes, formatWhen } from "@/lib/utils"

import { importName } from "./import-row"
import { OutcomeBadge } from "./outcome-badge"

const NOT_READ = "Not read"

function Fact({ label, children, mono }: { label: string; children: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={`mt-0.5 text-sm [overflow-wrap:anywhere] ${mono ? "font-mono text-[13px]" : ""}`}>{children}</dd>
    </div>
  )
}

/** The top of the import page: the import named by its signed crossing or its folder, where the latest attempt stands and what it reads from. */
export function ImportPageHeader({ imp }: { imp: Import }) {
  const attempt = latestAttempt(imp)
  const { folder, file } = archiveName(imp.archive.key)
  const name = importName(imp)
  // Under a crossing's name, the archive's place; under a folder's, the file it holds.
  const place = name === folder ? file : name === file ? "" : `${folder}${file}`
  const { target, nexus, unencrypted } = attempt.report
  // A queued attempt has no report yet: the archive's folder says which target it will read.
  const pip = (attempt.report.ecosystem || ecosystemOf(imp.archive.key)) === "pip"
  const started = attempt.startedAt ? formatWhen(attempt.startedAt) : attempt.status === "queued" ? "Not started yet" : "Not recorded"
  return (
    <header>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-semibold tracking-tight [overflow-wrap:anywhere]">{name}</h1>
          {place ? <p className="mt-1 font-mono text-xs text-muted [overflow-wrap:anywhere]">{place}</p> : null}
        </div>
        <OutcomeBadge outcome={imp.outcome} />
      </div>
      {unencrypted ? (
        <p className="mt-4 flex items-start gap-2 rounded-lg border border-line bg-card p-3 text-sm">
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-severity-high" />
          <span>Plain http: Nexus, MinIO or the key set is reached unencrypted. Package contents and credentials cross the network unencrypted there.</span>
        </p>
      ) : null}
      <dl className="mt-5 grid grid-cols-[repeat(auto-fill,minmax(168px,1fr))] gap-x-5 gap-y-3.5">
        <Fact label="Attempt">{String(attempt.n)}</Fact>
        <Fact label="Started">{started}</Fact>
        <Fact label="Archive size">{formatBytes(imp.archive.size)}</Fact>
        <Fact label="Nexus repository" mono>{nexus.repository || NOT_READ}</Fact>
        <Fact label="Nexus address" mono>{nexus.url || NOT_READ}</Fact>
        <Fact label="Target OS">{target.os || NOT_READ}</Fact>
        <Fact label="CPU">{target.cpu || NOT_READ}</Fact>
        {pip ? (
          <>
            <Fact label="Python">{target.python || NOT_READ}</Fact>
            <Fact label="glibc">{target.glibc || NOT_READ}</Fact>
          </>
        ) : (
          <>
            <Fact label="libc">{target.libc || NOT_READ}</Fact>
            <Fact label="Node">{target.node || NOT_READ}</Fact>
            <Fact label="pnpm">{target.pnpmVer || NOT_READ}</Fact>
          </>
        )}
      </dl>
    </header>
  )
}
