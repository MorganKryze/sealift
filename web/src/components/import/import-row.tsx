import { Link } from "@tanstack/react-router"
import { ChevronRight } from "lucide-react"

import { Progress } from "@/components/ui/progress"
import { archiveName, counts, latestAttempt, type Attempt, type Import } from "@/import/lib/outcome"
import { formatWhen } from "@/lib/utils"

import { OutcomeBadge } from "./outcome-badge"

const clamp = "line-clamp-2 [overflow-wrap:anywhere]"

function plural(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`
}

/** One import of the list: a single link to the import, with what its latest attempt did. */
export function ImportRow({ imp }: { imp: Import }) {
  const attempt = latestAttempt(imp)
  const { folder, file } = archiveName(imp.archive.key)
  return (
    <li className="border-t border-line first:border-t-0">
      <Link
        to="/imports/$importId"
        params={{ importId: imp.id }}
        className="grid min-h-18 grid-cols-[minmax(0,1fr)_128px_288px_16px] items-center gap-5 px-5 py-4 text-ink outline-none hover:bg-card focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
      >
        <div className="min-w-0">
          <p title={file} className={`font-mono text-[13px] font-medium ${clamp}`}>
            {file}
          </p>
          <p className="mt-1 flex min-w-0 gap-2 text-xs text-muted">
            <span title={folder} className={`min-w-0 font-mono text-[11.5px] ${clamp}`}>
              {folder}
            </span>
            <time dateTime={imp.createdAt} className="flex-none whitespace-nowrap before:mr-2 before:content-['·']">
              {formatWhen(imp.createdAt)}
            </time>
          </p>
        </div>
        <div>
          <OutcomeBadge outcome={imp.outcome} />
          <p className="mt-1 text-xs text-muted">Attempt {attempt.n}</p>
        </div>
        <Summary imp={imp} attempt={attempt} file={file} />
        <ChevronRight aria-hidden className="size-4 text-muted" />
      </Link>
    </li>
  )
}

export function Figures({ attempt }: { attempt: Attempt }) {
  const c = counts(attempt)
  return (
    <div className="flex gap-3.5 whitespace-nowrap text-[13px]">
      <span>
        <b className="font-mono font-semibold">{c.published}</b> published
      </span>
      <span>
        <b className="font-mono font-semibold">{c.present}</b> present
      </span>
      <span className={c.failed > 0 ? "font-semibold text-severity-critical-fg" : undefined}>
        <b className="font-mono font-semibold">{c.failed}</b> failed
      </span>
    </div>
  )
}

function Summary({ imp, attempt, file }: { imp: Import; attempt: Attempt; file: string }) {
  const c = counts(attempt)
  const missing = c.failed + c.notFinished + c.pending
  const reason = attempt.report.reason || "Reason not recorded"
  switch (imp.outcome) {
    case "queued":
      return (
        <div>
          <p className="text-[13px] font-medium">Waiting its turn</p>
          <p className="mt-1 text-xs text-muted">One import runs at a time for every user of the service, in the order they were started.</p>
        </div>
      )
    case "running":
      return (
        <div>
          {c.total > 0 ? (
            <>
              <Progress key={attempt.n} value={(c.done / c.total) * 100} label={`Progress of ${file}`} />
              <p className="mt-1.5 text-xs text-muted">{`${c.done} of ${c.total} packages`}</p>
            </>
          ) : (
            <p className="text-xs text-muted">Reading the manifest</p>
          )}
        </div>
      )
    case "refused":
      return (
        <div>
          <p className={`text-[13px] ${clamp}`}>{reason}</p>
          <p className="mt-1 text-xs text-muted">Nothing was published. Start a new import from Archives.</p>
        </div>
      )
    case "incomplete":
    case "interrupted":
      return (
        <div>
          <Figures attempt={attempt} />
          <p className={`mt-1 text-xs text-muted ${clamp}`}>
            {missing === 0
              ? reason
              : imp.outcome === "interrupted"
                ? `${plural(missing, "package", "packages")} not in Nexus. The service stopped before the attempt ended. Open the import to retry.`
                : `${plural(missing, "package", "packages")} not in Nexus. Open the import to retry.`}
          </p>
        </div>
      )
    default:
      return <Figures attempt={attempt} />
  }
}
