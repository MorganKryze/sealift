import { useQueryClient } from "@tanstack/react-query"
import { Check, ChevronDown, CircleX, DoorOpen, FileArchive, Hourglass, RotateCcw, ShieldCheck, X } from "lucide-react"
import { useId, useState, type ReactNode } from "react"

import { JobProgress, LogBlock, type CancelWords } from "@/components/job-progress"
import { stepBarStep, type StepBarStep } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { useCancelImport, useRetryImport } from "@/import/api/queries"
import { archiveName, counts, ecosystemOf, type Attempt, type Import, type ReportPackage } from "@/import/lib/outcome"
import { stageOf } from "@/import/lib/stage"
import { elapsed, timeLeft, type LogLine } from "@/lib/analysisEvents"
import { cn, formatBytes } from "@/lib/utils"

const COUNT = new Intl.NumberFormat("en-US")
const plural = (n: number, one: string) => `${COUNT.format(n)} ${n === 1 ? one : `${one}s`}`
const CLOCK = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
const DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" })

// Lines kept on screen; the count above them says how many came.
const LOG_LINES_KEPT = 2000
// Two polls that saw progress must be this far apart before the time left shows.
const RATE_GAP_MS = 3000

/**
 * Packages per ms over the polls this page saw, oldest first: from the first poll that saw a package end to the
 * last, once two such polls stand a few seconds apart. Before that, undefined, and the title says it is estimating.
 */
export function publishRate(samples: { at: number; ended: number }[]): number | undefined {
  const moved = samples.filter((s, i) => i > 0 && s.ended > samples[i - 1].ended)
  if (moved.length < 2) return undefined
  const first = moved[0]
  const last = moved[moved.length - 1]
  if (last.at - first.at < RATE_GAP_MS) return undefined
  return (last.ended - first.ended) / (last.at - first.at)
}

/** Whether the attempt got past its checks: a package it ended says so after the report stops saying it. */
function checked(a: Attempt): boolean {
  return a.report.archiveChecked === true || a.report.packages.some((p) => p.state === "published" || p.state === "present" || (p.state === "failed" && p.kind !== "interrupted"))
}

/** Check, Publish and In Nexus as the attempt stands; a queued attempt runs none. */
export function attemptSteps(a: Attempt): StepBarStep[] {
  const steps = (check: StepBarStep["status"], publish: StepBarStep["status"], inNexus: StepBarStep["status"], current: 0 | 1 | 2) => [
    stepBarStep("check", check, current === 0),
    stepBarStep("publish", publish, current === 1),
    stepBarStep("in-nexus", inNexus, current === 2),
  ]
  switch (stageOf(a)) {
    case "waiting":
      return steps("upcoming", "upcoming", "upcoming", 0)
    case "manifest":
    case "checks":
      return steps("running", "upcoming", "upcoming", 0)
    case "publishing":
      return steps("done", "running", "upcoming", 1)
  }
  switch (a.outcome) {
    case "complete":
      return steps("done", "done", "done", 2)
    case "refused":
      return steps("failed", "upcoming", "upcoming", 0)
    case "cancelled":
      return checked(a) ? steps("done", "cancelled", "upcoming", 1) : steps("cancelled", "upcoming", "upcoming", 0)
    default:
      return checked(a) ? steps("done", "failed", "upcoming", 1) : steps("failed", "upcoming", "upcoming", 0)
  }
}

interface Entry {
  key: string
  line: Omit<LogLine, "at">
}

function packageLine(p: ReportPackage): Entry["line"] {
  const name = `${p.name} ${p.version}`
  if (p.state === "published") return { step: "publish", text: `${name} · published`, tone: "ok" }
  if (p.state === "present") return { step: "publish", text: `${name} · already in Nexus, same sha512` }
  // A package the run never reached is no failure of its own: no red.
  if (p.kind === "interrupted") return { step: "stopped", text: `${name} · ${p.reason || "not reached"}` }
  return { step: "failed", text: `${name} · ${p.reason || "failed"}`, tone: "bad" }
}

/** What the report tells so far, one entry per fact, each with a key that never changes within the attempt. */
function entries(imp: Import | undefined, a: Attempt): Entry[] {
  const r = a.report
  const out: Entry[] = []
  const total = r.packages.length
  if (total > 0) {
    const eco = r.ecosystem ?? (imp ? ecosystemOf(imp.archive.key) : undefined)
    const facts = [r.crossing?.project, eco, plural(total, "package"), r.crossing ? `sealed ${DAY.format(new Date(r.crossing.sealedAt))}` : undefined]
    out.push({ key: "manifest", line: { step: "manifest", text: facts.filter(Boolean).join(" · ") } })
  }
  if (checked(a)) {
    out.push({ key: "signature", line: { step: "check", text: "signature Ed25519 · the key this side trusts · ok" } })
    const file = r.archive.file || (imp ? archiveName(imp.archive.key).file : "")
    const size = r.archive.size || imp?.archive.size
    out.push({ key: "archive", line: { step: "check", text: [file, size ? formatBytes(size) : undefined, "sha256 ok", `${COUNT.format(total)} sha512 ok`].filter(Boolean).join(" · ") } })
  }
  if (r.nexus.repository) out.push({ key: "nexus", line: { step: "nexus", text: r.nexus.url ? `${r.nexus.repository} on ${r.nexus.url}` : r.nexus.repository } })
  for (const p of r.packages) {
    if (p.state !== "pending") out.push({ key: `package ${p.file}`, line: packageLine(p) })
  }
  return out
}

/** An ended attempt's log, rebuilt from its report with no time. */
export function attemptLog(a: Attempt): LogLine[] {
  return entries(undefined, a).map((e) => ({ at: "", ...e.line }))
}

interface LogState {
  attempt: Attempt
  seen: Set<string>
  lines: LogLine[]
  count: number
  samples: { at: number; ended: number }[]
}

/**
 * Adds what the attempt's latest read tells that no earlier read told: a line per fact, stamped with the time the
 * page received it. The first read rebuilds the lines from the report, with no time.
 */
function fold(prev: LogState | undefined, imp: Import, a: Attempt, at: number | undefined): LogState {
  const seen = new Set(prev?.seen)
  const stamp = prev && at !== undefined ? CLOCK.format(new Date(at)) : ""
  const fresh: LogLine[] = []
  for (const e of entries(imp, a)) {
    if (seen.has(e.key)) continue
    seen.add(e.key)
    fresh.push({ at: stamp, ...e.line })
  }
  const kept = [...(prev?.lines ?? []), ...fresh]
  const samples = prev?.samples ?? []
  const last = samples[samples.length - 1]
  const sample = stageOf(a) === "publishing" && at !== undefined && (!last || at > last.at) ? [{ at, ended: counts(a).done }] : []
  return {
    attempt: a,
    seen,
    lines: kept.length > LOG_LINES_KEPT ? kept.slice(kept.length - LOG_LINES_KEPT) : kept,
    count: (prev?.count ?? 0) + fresh.length,
    samples: [...samples, ...sample],
  }
}

/** The attempt's log and the polls it was built from, kept for as long as the attempt's node stays mounted. */
function useAttemptLog(imp: Import, a: Attempt): LogState {
  const client = useQueryClient()
  const at = client.getQueryState(["imports", imp.id])?.dataUpdatedAt || undefined
  const [log, setLog] = useState(() => fold(undefined, imp, a, at))
  if (log.attempt !== a) {
    const next = fold(log, imp, a, at)
    setLog(next)
    return next
  }
  return log
}

/** The archive the attempt reads: its folder and file, its size and ecosystem, and once its checks passed, the Compliant chip. */
function ArchiveLine({ imp, attempt, compliant }: { imp: Import; attempt: Attempt; compliant: boolean }) {
  const [open, setOpen] = useState(false)
  const checksId = useId()
  const captionId = useId()
  const { folder, file } = archiveName(imp.archive.key)
  const eco = attempt.report.ecosystem ?? ecosystemOf(imp.archive.key)
  const total = attempt.report.packages.length
  return (
    <div className="mt-6 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-rule px-4 py-3">
      <span className="grid size-8 flex-none place-items-center rounded-lg bg-hover text-ink-2">
        <FileArchive aria-hidden="true" className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="font-mono text-[13px] [overflow-wrap:anywhere]">
          <span className="text-muted">{folder}</span>
          <span className="text-ink">{file}</span>
        </p>
        <p className="mt-0.5 text-[13px] text-muted">
          <b className="font-semibold text-ink">{formatBytes(imp.archive.size)}</b>
          {` · ${eco}`}
        </p>
      </div>
      {compliant ? (
        <button
          type="button"
          aria-expanded={open}
          aria-controls={checksId}
          onClick={() => setOpen((o) => !o)}
          className="tinted-ok inline-flex h-8 items-center gap-1.5 !rounded-full px-3 text-[13px] font-semibold text-ok transition-[transform] duration-160 ease-out motion-safe:active:scale-[0.97]"
        >
          <ShieldCheck aria-hidden="true" className="size-4" />
          Compliant
          <ChevronDown aria-hidden="true" className={cn("size-4 transition-transform duration-200 ease-out motion-reduce:transition-none", open && "rotate-180")} />
        </button>
      ) : null}
      {compliant && open ? (
        <div id={checksId} className="animate-fade basis-full pl-11">
          <p id={captionId} className="text-xs font-semibold text-muted">
            3 checks passed
          </p>
          <ul aria-labelledby={captionId}>
            <CheckLine label="Signature">Ed25519, by the key this side trusts</CheckLine>
            <CheckLine label="Archive">sha256 as the signed manifest states it</CheckLine>
            <CheckLine label="Packages">{`${plural(total, "sha512")} as the manifest lists them`}</CheckLine>
          </ul>
        </div>
      ) : null}
    </div>
  )
}

function CheckLine({ label, children }: { label: string; children: ReactNode }) {
  return (
    <li className="grid min-h-8.5 grid-cols-[16px_92px_minmax(0,1fr)] items-center gap-2.5 text-[13px]">
      <Check aria-hidden="true" className="size-4 text-ok" />
      <span className="font-semibold">{label}</span>
      <span className="min-w-0 text-muted [overflow-wrap:anywhere]">{children}</span>
    </li>
  )
}

const titleClass = "text-[34px] leading-tight font-bold tracking-tight text-ink outline-none"

/** A count and what it counts, the figure in weight 600. */
const Figure = ({ n }: { n: number }) => <b className="font-semibold text-ink">{COUNT.format(n)}</b>

function Queued({ imp, attempt }: { imp: Import; attempt: Attempt }) {
  const cancel = useCancelImport(imp.id)
  const ahead = imp.queueAhead
  const busy = cancel.isPending
  return (
    <div>
      <h1 data-attempt-title tabIndex={-1} aria-live="polite" className={titleClass}>
        Waiting its turn
      </h1>
      {ahead !== undefined ? (
        <p className="mt-1.5 text-[15px] text-muted">
          {ahead === 0 ? (
            "No import ahead of this one"
          ) : (
            <>
              <Figure n={ahead} />
              {` ${ahead === 1 ? "import" : "imports"} ahead of this one`}
            </>
          )}
        </p>
      ) : null}
      <ArchiveLine imp={imp} attempt={attempt} compliant={false} />
      <div className="mt-7 flex flex-wrap items-center justify-end gap-x-3 gap-y-3">
        {busy ? null : (
          <p className="mr-auto inline-flex items-center gap-2 text-[13px] text-muted">
            <DoorOpen aria-hidden="true" className="size-4 flex-none" />
            Keeps its place if you leave this page
          </p>
        )}
        {/* Nothing has run yet, so nothing is lost: the cancel needs no confirm. */}
        <Button type="button" variant="tinted" size="page" aria-disabled={busy ? true : undefined} onClick={() => (busy ? undefined : cancel.mutate())}>
          {busy ? <Hourglass aria-hidden="true" /> : <X aria-hidden="true" />}
          <span className="grid">
            <span className="col-start-1 row-start-1">{busy ? "Cancelling" : "Cancel"}</span>
            <span aria-hidden="true" className="invisible col-start-1 row-start-1">
              {busy ? "Cancel" : "Cancelling"}
            </span>
          </span>
        </Button>
      </div>
      {cancel.isError ? (
        <p role="alert" className="mt-3 text-right text-sm text-ink-2">
          The service did not take the cancel. The import keeps its place.
        </p>
      ) : null}
    </div>
  )
}

function Cancelled({ imp, attempt, log }: { imp: Import; attempt: Attempt; log: LogState }) {
  const retry = useRetryImport(imp.id)
  const c = counts(attempt)
  const inNexus = c.published + c.present
  const missing = c.total - inNexus
  const took = attempt.startedAt && attempt.endedAt ? Date.parse(attempt.endedAt) - Date.parse(attempt.startedAt) : undefined
  return (
    <div>
      <h1 data-attempt-title tabIndex={-1} aria-live="polite" className={titleClass}>
        Import cancelled
      </h1>
      <p className="mt-1.5 text-[15px] text-muted">
        {took !== undefined && took >= 0 ? (
          <>
            {"After "}
            <b className="font-semibold text-ink">{elapsed(took)}</b>
            {". "}
          </>
        ) : null}
        <Figure n={inNexus} />
        {" of "}
        <Figure n={c.total} />
        {" packages are in Nexus."}
      </p>
      <ArchiveLine imp={imp} attempt={attempt} compliant={checked(attempt)} />
      <LogBlock className="mt-3" lines={log.lines} count={log.count} />
      <div className="mt-7 flex flex-wrap items-center justify-end gap-3">
        {retry.isError ? (
          <p role="alert" className="mr-auto text-sm text-ink-2 [overflow-wrap:anywhere]">
            {retry.error.message}
          </p>
        ) : null}
        <Button type="button" size="page" aria-disabled={retry.isPending ? true : undefined} onClick={() => (retry.isPending ? undefined : retry.mutate())}>
          <RotateCcw aria-hidden="true" />
          {missing > 0 ? `Retry ${plural(missing, "package")}` : "Retry import"}
        </Button>
      </div>
    </div>
  )
}

/**
 * The import page while its latest attempt waits, checks or publishes, and once it was cancelled. The route keys it
 * by attempt number, so one node lives for the whole attempt: the title, the bar and the log keep their place while
 * the page polls. An attempt that ended any other way draws nothing here; the end below says how it ended.
 */
export function AttemptProgress({ imp, attempt }: { imp: Import; attempt: Attempt }) {
  const stage = stageOf(attempt)
  const log = useAttemptLog(imp, attempt)
  const cancel = useCancelImport(imp.id)

  if (stage === "waiting") return <Queued imp={imp} attempt={attempt} />
  if (stage === "ended") return attempt.outcome === "cancelled" ? <Cancelled imp={imp} attempt={attempt} log={log} /> : null

  const c = counts(attempt)
  const inNexus = c.published + c.present
  const checking = stage !== "publishing"
  const rate = checking ? undefined : publishRate(log.samples)
  const left = rate ? timeLeft((c.total - c.done) / rate) : undefined
  const words: CancelWords = {
    label: "Cancel",
    confirm: "Cancel import",
    lost: "Packages already in Nexus stay there; a retry publishes the rest.",
    keep: "Keep running",
    onConfirm: () => cancel.mutateAsync(),
  }
  const counted = checking ? (
    <>
      <b className="font-semibold text-ink">{formatBytes(imp.archive.size)}</b>
      {" read once against its signed manifest"}
    </>
  ) : (
    <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1.5">
      <span>
        <Figure n={inNexus} />
        {" of "}
        <Figure n={c.total} />
        {" packages in Nexus"}
      </span>
      {c.failed > 0 ? (
        <>
          <span className="tinted-bad inline-flex h-7 items-center gap-1.5 !rounded-full px-2.5 text-[13px] font-semibold text-bad">
            <CircleX aria-hidden="true" className="size-4" />
            {`${plural(c.failed, "package")} failed`}
          </span>
          <span className="text-[13px]">Causes at the end</span>
        </>
      ) : null}
    </span>
  )
  return (
    <>
      <JobProgress
        title={checking ? "Checking the archive" : (left ?? "Estimating time left")}
        counted={counted}
        progress={checking ? undefined : { done: inNexus, total: c.total }}
        estimating={checking}
        aside={checking ? undefined : <ArchiveLine imp={imp} attempt={attempt} compliant />}
        log={log.lines}
        logCount={log.count}
        live
        note="Keeps running if you leave this page"
        cancel={words}
      />
      {cancel.isError ? (
        <p role="alert" className="mt-3 text-right text-sm text-ink-2">
          The service did not take the cancel. The import goes on.
        </p>
      ) : null}
    </>
  )
}
