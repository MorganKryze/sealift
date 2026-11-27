import { Link } from "@tanstack/react-router"
import {
  Archive,
  ArchiveX,
  Ban,
  CircleAlert,
  CircleCheck,
  CirclePause,
  CircleQuestionMark,
  CircleX,
  Clock,
  FileDiff,
  GitCompareArrows,
  Info,
  PackageX,
  RotateCcw,
  ServerCrash,
  ShieldX,
  type LucideIcon,
} from "lucide-react"
import { Fragment, useId, useState, type ReactNode } from "react"

import { CopyControl } from "@/components/copy-control"
import { compareFingerprint, Fingerprint } from "@/components/fingerprint/fingerprint"
import { ContactCard, useBrand } from "@/components/frame/brand"
import { LogBlock } from "@/components/job-progress"
import { Button } from "@/components/ui/button"
import { ImportApiError } from "@/import/api/client"
import { useRetryImport } from "@/import/api/queries"
import { CAUSES, causeOf, causeWords, copyRequest, nexusPath, type Cause } from "@/import/lib/kinds"
import { counts, ecosystemOf, latestAttempt, type Import, type ReportPackage } from "@/import/lib/outcome"
import { cn, formatBytes, formatWhen } from "@/lib/utils"

import { attemptLog } from "./progress"
import { RetryAction } from "./retry-card"

function Card({ icon: Icon, tone, title, children, panel = "border-line bg-card" }: { icon: LucideIcon; tone: string; title: ReactNode; children: ReactNode; panel?: string }) {
  return (
    <section aria-labelledby="end-heading" className={`mt-6 rounded-xl border p-5 ${panel}`}>
      <div className="flex items-start gap-2">
        <Icon aria-hidden className={`mt-1 size-[18px] shrink-0 ${tone}`} />
        <h2 id="end-heading" className="text-lg font-semibold tracking-tight">
          {title}
        </h2>
      </div>
      <div className="mt-2 grid max-w-[72ch] gap-2">{children}</div>
    </section>
  )
}

function Etag({ title, value, label }: { title: string; value: string; label: string }) {
  return (
    <div>
      <dt className="text-sm text-muted">{title}</dt>
      <dd className="mt-1 flex flex-wrap items-start gap-x-3 gap-y-2">
        <code className="min-w-0 font-mono text-[13px] [overflow-wrap:anywhere]">{value}</code>
        <CopyControl text={value} label={label} />
      </dd>
    </div>
  )
}

/** The words for the counts of a complete attempt. Only a complete attempt says every package is in Nexus. */
function inNexus(imp: Import): string {
  const c = counts(latestAttempt(imp))
  return `All ${c.total} packages are in Nexus: ${c.published} published, ${c.present} present.`
}

/** The objects the import read and removal guards: a record of sealift 0.4 holds no signature. */
function objectsOf(imp: Import): string {
  return imp.signature ? "the archive, the manifest and the signature" : "the archive and the manifest"
}

/**
 * How the latest attempt ended, in the cases the report and the progress cannot say: a complete
 * attempt and what became of the archive, a refusal, an interruption. An incomplete attempt is the
 * retry card's. The archive's removal is read from the attempt's removal record alone.
 */
export function EndState({ imp }: { imp: Import }) {
  const a = latestAttempt(imp)
  if (a.status !== "ended") {
    return null
  }
  if (a.outcome === "complete") {
    if (!a.removal) {
      return (
        <Card icon={Info} tone="text-accent" title="Checking the archive's removal">
          <p>{inNexus(imp)}</p>
          <p className="text-muted">The archive's removal is being checked. This page updates until the service records what became of it.</p>
        </Card>
      )
    }
    if (a.removal.removed) {
      return (
        <Card icon={CircleCheck} tone="text-severity-resolved-fg" title={a.removal.reason ? "Archive removed from MinIO, its manifest or signature kept" : "Archive removed from MinIO"}>
          <p>{inNexus(imp)}</p>
          {a.removal.reason ? (
            <p className="[overflow-wrap:anywhere]">{a.removal.reason}</p>
          ) : (
            <p>{`sealift removed ${objectsOf(imp)} from your folder, after checking that each still carried the ETag it read at the start.`}</p>
          )}
          <dl className="mt-2 grid gap-3">
            <Etag title="Archive ETag" value={imp.archive.etag} label="archive ETag" />
            <Etag title="Manifest ETag" value={imp.manifest.etag} label="manifest ETag" />
            {imp.signature ? <Etag title="Signature ETag" value={imp.signature.etag} label="signature ETag" /> : null}
          </dl>
        </Card>
      )
    }
    return (
      <Card icon={Archive} tone="text-accent" title="Archive kept in MinIO">
        <p>{`${inNexus(imp)} The archive stays in MinIO. Its reason:`}</p>
        <p className="rounded-md border border-line bg-background p-3 text-sm [overflow-wrap:anywhere]">{a.removal.reason || "Not recorded"}</p>
        <p className="text-muted">
          {`Retry adds an attempt: it checks every package again and removes the archive only if ${objectsOf(imp)} still carry the ETags this import read. An archive replaced since is refused.`}
        </p>
        <RetryAction imp={imp} />
      </Card>
    )
  }
  if (a.outcome === "incomplete") {
    return <FailedEnd imp={imp} />
  }
  if (a.outcome === "refused") {
    const reason = a.report.reason
    return (
      <Card icon={ShieldX} tone="text-severity-critical-fg" panel="border-severity-critical/40 bg-severity-critical/10" title="Refused before the first package">
        <p className="[overflow-wrap:anywhere]">{reason || "Not recorded"}</p>
        <p>This attempt published nothing and read no package.</p>
        <div className="mt-2">
          <Link to="/import" className="inline-flex h-9 items-center gap-2 rounded-md bg-accent px-4 text-sm font-medium text-background outline-none hover:brightness-90 focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2">
            <Archive aria-hidden className="size-4" />
            Go to archives
          </Link>
        </div>
      </Card>
    )
  }
  if (a.outcome === "interrupted") {
    const c = counts(a)
    const unfinished = c.notFinished + c.pending
    return (
      <Card icon={CirclePause} tone="text-severity-high" title={`Stopped before it ended, ${a.endedAt ? `at ${formatWhen(a.endedAt)}` : "Not recorded"}`}>
        <p>The service stopped or restarted before this attempt ended.</p>
        <p>{`${c.done} of ${c.total} packages were finished. ${unfinished} were not finished, counted apart from failures.`}</p>
      </Card>
    )
  }
  return null
}

const COUNT = new Intl.NumberFormat("en-US")
const UPLOAD_DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" })
const plural = (n: number, one: string, many = `${one}s`) => `${COUNT.format(n)} ${n === 1 ? one : many}`

const ICONS: Record<Cause, LucideIcon> = {
  "no-answer": Clock,
  "too-large": Ban,
  refused: CircleAlert,
  conflict: FileDiff,
  source: ArchiveX,
  interrupted: CirclePause,
  mismatch: PackageX,
  local: ServerCrash,
  unknown: CircleQuestionMark,
}

/** The two sha512 a conflict's reason names, when it names them as the publisher writes them. */
function digestsOf(reason: string): { shipped: string; nexus: string } | undefined {
  const m = /shipped sha512 ([0-9a-f]{128}), nexus sha512 ([0-9a-f]{128})/.exec(reason)
  return m ? { shipped: m[1], nexus: m[2] } : undefined
}

/** What Nexus says of its copy: the date and the account, the one it says, or nothing. */
function uploadedWords(p: ReportPackage): string | undefined {
  const at = p.nexusUploadedAt ? new Date(p.nexusUploadedAt) : undefined
  const day = at && !Number.isNaN(at.getTime()) ? UPLOAD_DAY.format(at) : undefined
  if (day && p.nexusUploader) return `Uploaded ${day} by ${p.nexusUploader}`
  if (day) return `Uploaded ${day}`
  if (p.nexusUploader) return `Uploaded by ${p.nexusUploader}`
  return undefined
}

/** A failed attempt's end: the count not in Nexus, one closed block per cause with its action, the log folded, the contact last. */
function FailedEnd({ imp }: { imp: Import }) {
  const a = latestAttempt(imp)
  const c = counts(a)
  const missing = a.report.packages.filter((p) => p.state === "failed" || p.state === "pending")
  const byCause = new Map<Cause, ReportPackage[]>()
  for (const p of missing) {
    const cause = causeOf(p)
    byCause.set(cause, [...(byCause.get(cause) ?? []), p])
  }
  const log = attemptLog(a)
  const shown = CAUSES.filter((cause) => byCause.has(cause))
  // One primary per screen: the first cause a retry clears leads, any other Retry stays secondary.
  const lead = shown.find((cause) => causeWords(cause).tone === "warn")
  return (
    <section aria-labelledby="end-heading" className="mt-6 max-w-190">
      <h2 id="end-heading" className="text-[28px] font-bold tracking-tight text-ink">
        {`${plural(missing.length, "package")} not in Nexus`}
      </h2>
      <p className="mt-1 text-[15px] text-muted">
        <b className="font-semibold text-ink tabular-nums">{COUNT.format(c.published + c.present)}</b>
        {" of "}
        <b className="font-semibold text-ink tabular-nums">{COUNT.format(c.total)}</b>
        {" packages in Nexus. The archive stays in MinIO until all are in."}
      </p>
      <div className="mt-5 grid gap-3">
        {shown.map((cause) => (
          <CauseBlock key={cause} imp={imp} cause={cause} pkgs={byCause.get(cause) ?? []} lead={cause === lead} />
        ))}
      </div>
      <LogBlock className="mt-3" lines={log} copyText={log.map((line) => [line.step, line.text].join(" ")).join("\n")} />
      <ContactCard caption="Still blocked after these steps?" />
    </section>
  )
}

function CauseBlock({ imp, cause, pkgs, lead }: { imp: Import; cause: Cause; pkgs: ReportPackage[]; lead: boolean }) {
  const brand = useBrand()
  const a = latestAttempt(imp)
  const words = causeWords(cause)
  const Icon = ICONS[cause]
  const headingId = useId()
  const eco = a.report.ecosystem ?? ecosystemOf(imp.archive.key)
  // PyPI publishes several files per version and Nexus takes or refuses each, so these causes name the file.
  const byFile = eco === "pip" && (cause === "too-large" || cause === "conflict" || cause === "refused")
  const warn = words.tone === "warn"
  const retry = <RetryButton imp={imp} cause={cause} pkgs={pkgs} primary={lead} />
  return (
    <section aria-labelledby={headingId} className={cn("rounded-lg px-4 py-3.5", warn ? "tinted-warn" : "tinted-bad")}>
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <Icon aria-hidden="true" className={cn("size-[18px] flex-none", warn ? "text-warn" : "text-bad")} />
        <h3 id={headingId} className="font-semibold text-ink">
          {words.title}
        </h3>
        <span className={cn("rounded-full border bg-bg px-2 text-xs leading-5 font-semibold", warn ? "border-warn-line text-warn" : "border-bad-line text-bad")}>
          {plural(pkgs.length, "package")}
        </span>
      </div>
      <div className="mt-2.5 pl-[28px]">
        <PackageList pkgs={pkgs} byFile={byFile} sized={cause === "too-large"} />
        {warn ? (
          <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div className="min-w-0 max-w-[62ch] text-sm text-ink-2">
              <Diagnosis cause={cause} pkgs={pkgs} all={a.report.packages} eco={eco} />
            </div>
            <div className="flex-none">{retry}</div>
          </div>
        ) : (
          <>
            <div className="mt-3 max-w-[62ch] text-sm text-ink-2">
              <Diagnosis cause={cause} pkgs={pkgs} all={a.report.packages} eco={eco} />
            </div>
            <ol aria-label="Steps" className="mt-3 grid">
              {cause === "too-large" ? (
                <>
                  <Step n={1} text={pkgs.length === 1 ? "Raise Nexus's upload limit above this file's size" : "Raise Nexus's upload limit above the largest of these files"}>
                    <CopyControl text={copyRequest(a.report.nexus.repository, pkgs, brand.contact?.label)} label="request" />
                  </Step>
                  <Step n={2} text="Once the limit is raised">
                    {retry}
                  </Step>
                </>
              ) : null}
              {cause === "conflict" ? <ConflictSteps pkgs={pkgs} eco={eco} byFile={byFile} retry={retry} /> : null}
              {cause === "mismatch" ? <Step n={1} text={`Bring the archive again from ${brand.online}, then start a new import`} /> : null}
            </ol>
          </>
        )}
      </div>
    </section>
  )
}

function Step({ n, text, children, after }: { n: number; text: string; children?: ReactNode; after?: ReactNode }) {
  return (
    <li className="border-t border-bad-line py-2.5 first:border-t-0 sm:first:border-t">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span aria-hidden="true" className="grid size-6 flex-none place-items-center rounded-full border border-rule-2 bg-bg text-xs font-semibold text-ink">
          {n}
        </span>
        <span className="min-w-0 flex-1 text-sm text-ink">{text}</span>
        {children ? <span className="ml-auto flex-none">{children}</span> : null}
      </div>
      {after}
    </li>
  )
}

const GRID_FIRST = 9

/** A cause's packages: their names when they are few, else a grid of the first 9 that opens in place to all of them. */
function PackageList({ pkgs, byFile, sized }: { pkgs: ReportPackage[]; byFile: boolean; sized: boolean }) {
  const [open, setOpen] = useState(false)
  const listId = useId()
  const grid = pkgs.length > 4
  const shown = grid && !open ? pkgs.slice(0, GRID_FIRST) : pkgs
  return (
    <>
      <ul id={listId} className={grid ? cn("grid gap-x-6", sized ? "sm:grid-cols-2" : "sm:grid-cols-3") : "flex flex-wrap gap-2"}>
        {shown.map((p, i) => (
          <li
            key={`${p.file}-${i}`}
            className={cn(
              "min-w-0 font-mono text-[12.5px] text-ink [overflow-wrap:anywhere]",
              grid ? "flex items-baseline justify-between gap-3 border-b border-rule py-1.5" : "flex items-baseline gap-2 rounded-md border border-rule-2 bg-bg px-2 py-0.5",
            )}
          >
            {byFile ? (
              <span>{p.file}</span>
            ) : (
              <span>
                <span>{p.name}</span> <span className="font-semibold">{p.version}</span>
              </span>
            )}
            {sized && p.size ? <span className="flex-none font-sans text-[13px] font-semibold text-ink-2 tabular-nums">{formatBytes(p.size)}</span> : null}
          </li>
        ))}
      </ul>
      {grid && pkgs.length > GRID_FIRST ? (
        <Button variant="outline" size="sm" className="mt-2.5" aria-expanded={open} aria-controls={listId} onClick={() => setOpen((was) => !was)}>
          {open ? "Show fewer" : `Show all ${plural(pkgs.length, "package")}`}
        </Button>
      ) : null}
    </>
  )
}

/** What was seen, in words: the raw text Nexus sent stays in the log. */
function Diagnosis({ cause, pkgs, all, eco }: { cause: Cause; pkgs: ReportPackage[]; all: ReportPackage[]; eco: "npm" | "pip" }) {
  const one = pkgs.length === 1
  const these = one ? "this package" : `these ${plural(pkgs.length, "package")}`
  switch (cause) {
    case "no-answer":
      return <p>{`Nexus did not answer for ${these}. Nothing needs to change before a retry.`}</p>
    case "too-large": {
      const through = Math.max(0, ...all.filter((p) => p.state === "published").map((p) => p.size ?? 0))
      const smallest = Math.min(...pkgs.map((p) => p.size ?? Infinity))
      return (
        <p>
          {one ? "Nexus refused this file as too large." : `Nexus refused these ${COUNT.format(pkgs.length)} files as too large.`}
          {through > 0 ? (
            <>
              {" The largest file that went through is "}
              <b className="font-semibold text-ink">{formatBytes(through)}</b>
              {through < smallest ? (one ? ", so the limit sits between the two sizes." : ", so the limit sits below the smallest of them.") : "."}
            </>
          ) : null}
        </p>
      )
    }
    case "refused": {
      const statuses = [...new Set(pkgs.map((p) => p.nexusStatus))].sort()
      const said = statuses.length === 1 ? `${statuses[0]}` : `${statuses.slice(0, -1).join(", ")} and ${statuses.at(-1)}`
      return <p>{`Nexus answered ${said} to ${these}. Its words are in the log.`}</p>
    }
    case "conflict": {
      const held = eco === "pip" ? (one ? "this file" : `these ${COUNT.format(pkgs.length)} files`) : one ? "this version" : `these ${COUNT.format(pkgs.length)} versions`
      const origin = eco === "pip" ? "PyPI" : "npm"
      return (
        <p>
          {`Nexus holds ${held} with a different sha512. `}
          {one ? `The archive's copy is the one ${origin} published. ` : `The archive's copies are the ones ${origin} published. `}
          {`sealift never overwrites a package, so a retry alone cannot fix ${one ? "it" : "them"}.`}
        </p>
      )
    }
    case "source":
      return <p>{`MinIO did not give the archive's bytes for ${these}. A retry reads the archive again.`}</p>
    case "interrupted":
      return <p>{`The import stopped before ${these} ${one ? "was" : "were"} published. Nothing needs to change before a retry.`}</p>
    case "mismatch":
      return <p>{`The archive does not hold what its manifest names for ${these}, so a retry would read the same files.`}</p>
    case "local":
      return <p>{`Something on this side failed for ${these}: a file of the service or its Nexus client. If a retry fails the same way, ask the contact below.`}</p>
    default: {
      const reasons = [...new Set(pkgs.map((p) => p.reason).filter(Boolean))]
      return (
        <>
          <p>{reasons.length > 0 ? "Recorded by an older sealift, with no cause. Its reasons:" : "Recorded by an older sealift, with no cause and no reason."}</p>
          {reasons.map((reason) => (
            <p key={reason} className="mt-1 font-mono text-[12.5px] [overflow-wrap:anywhere]">
              {reason}
            </p>
          ))}
        </>
      )
    }
  }
}

function ConflictSteps({ pkgs, eco, byFile, retry }: { pkgs: ReportPackage[]; eco: "npm" | "pip"; byFile: boolean; retry: ReactNode }) {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  const one = pkgs.length === 1
  const paths = pkgs.map((p) => nexusPath(p, eco))
  return (
    <>
      <Step
        n={1}
        text={one ? "Compare the two sha512" : "Compare the two sha512 of each"}
        after={
          open ? (
            <div id={panelId} className="mt-3 grid gap-4 pl-9">
              {pkgs.map((p, i) => (
                <ConflictCompare key={`${p.file}-${i}`} p={p} named={!one} byFile={byFile} />
              ))}
            </div>
          ) : null
        }
      >
        <Button variant="outline" size="sm" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((was) => !was)}>
          <GitCompareArrows aria-hidden="true" />
          Compare
        </Button>
      </Step>
      <Step n={2} text={one ? "Remove the copy in Nexus" : `Remove the ${COUNT.format(pkgs.length)} copies in Nexus`}>
        <CopyControl text={paths.join("\n")} label={one ? "its path" : `${COUNT.format(pkgs.length)} paths`} />
      </Step>
      <Step n={3} text={one ? "Once the copy is removed" : "Once the copies are removed"}>
        {retry}
      </Step>
    </>
  )
}

/** One conflict's two sha512, the one in Nexus with its differing characters marked, and what Nexus says of its copy. */
function ConflictCompare({ p, named, byFile }: { p: ReportPackage; named: boolean; byFile: boolean }) {
  const d = digestsOf(p.reason)
  const uploaded = uploadedWords(p)
  const marked = d ? new Set(compareFingerprint(d.shipped, d.nexus).differs) : new Set<number>()
  return (
    <div className="grid min-w-0 gap-1.5">
      {named ? <p className="font-mono text-[12.5px] text-ink [overflow-wrap:anywhere]">{byFile ? p.file : `${p.name} ${p.version}`}</p> : null}
      {d ? (
        <>
          <p className="text-[13px] font-semibold text-ink">In the archive</p>
          <Fingerprint value={d.shipped} label={`sha512 in the archive of ${p.file}`} />
          <p className="mt-1 inline-flex items-center gap-1.5 text-[13px] font-semibold text-ink">
            In Nexus
            <CircleX role="img" aria-label="differs" className="size-3.5 text-bad" />
          </p>
          <span className="inline-flex max-w-full min-w-0 items-start gap-1">
            <span className="flex min-w-0 flex-wrap gap-x-[1ch] gap-y-0.5 rounded-lg border border-bad-line bg-bg px-2.5 py-1.5 font-mono text-xs leading-5 text-ink">
              {(d.nexus.match(/.{1,8}/g) ?? []).map((group, g) => (
                <span key={g} className="whitespace-nowrap">
                  {[...group].map((char, k) =>
                    marked.has(g * 8 + k) ? (
                      <mark key={k} className="rounded-sm bg-bad-tint font-semibold text-bad underline decoration-2 underline-offset-2">
                        {char}
                      </mark>
                    ) : (
                      <Fragment key={k}>{char}</Fragment>
                    ),
                  )}
                </span>
              ))}
            </span>
            <CopyControl text={d.nexus} label={`sha512 in Nexus of ${p.file}`} compact />
          </span>
        </>
      ) : null}
      {uploaded ? <p className="text-[13px] text-muted [overflow-wrap:anywhere]">{uploaded}</p> : null}
    </div>
  )
}

/** Retries a cause's packages only; a refusal says why beside the button, and the blocks stay as they were. */
function RetryButton({ imp, cause, pkgs, primary }: { imp: Import; cause: Cause; pkgs: ReportPackage[]; primary: boolean }) {
  const retry = useRetryImport(imp.id)
  const label = `Retry ${plural(pkgs.length, "package")}`
  const failure = retry.isError ? retry.error : null
  const refused = failure instanceof ImportApiError && failure.status >= 400 && failure.status < 500
  const why = (failure instanceof ImportApiError ? (failure.problem?.detail ?? failure.problem?.title ?? failure.message) : (failure?.message ?? "")).replace(/\.$/, "")
  return (
    <span className="inline-flex flex-col items-end gap-2">
      <Button
        variant={primary ? "default" : "outline"}
        size={primary ? "default" : "sm"}
        aria-label={`${label}: ${causeWords(cause).title}`}
        disabled={retry.isPending}
        onClick={() => retry.mutate({ packages: pkgs.map((p) => p.file) })}
      >
        <RotateCcw aria-hidden="true" />
        {retry.isPending ? "Starting" : label}
      </Button>
      {failure ? (
        <span role="alert" className="max-w-[48ch] text-right text-[13px] text-bad [overflow-wrap:anywhere]">
          {`${refused ? "The retry was refused" : "The retry could not be started"}: ${why}. Nothing was changed.`}
        </span>
      ) : null}
    </span>
  )
}
