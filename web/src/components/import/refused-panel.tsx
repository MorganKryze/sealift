import { Check, CircleX, Copy, FileArchive, FileJson, FileKey, GitCompareArrows, KeyRound, Minus, ShieldCheck, X } from "lucide-react"
import { Fragment, useState, type ReactNode } from "react"

import { CopyControl } from "@/components/copy-control"
import { Fingerprint, FingerprintCompare } from "@/components/fingerprint/fingerprint"
import { ContactCard, useBrand } from "@/components/frame/brand"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import type { Archive } from "@/import/api/queries"
import { archiveName, FOLDERS, latestAttempt, type Import } from "@/import/lib/outcome"
import { cn, formatBytes } from "@/lib/utils"

import { crossingLabel, folderLabel, uploaded } from "./archive-row"

const HEX = /^[0-9a-f]{64}$/
// The archive check's own words for a digest that differs (archive/verify.go). Any other reason is shown as a sentence:
// a sha256 is never read out of free text.
const SHA_REFUSAL = /^archive sha256 ([0-9a-f]{64}) differs from the (manifest's|expected sha256) ([0-9a-f]{64})$/

// "expected": the archive matches its manifest, the sha256 the user typed differs (archive/verify.go checks the manifest first).
type Cause = "key" | "signature" | "archive" | "expected" | "folder" | "other"
type FileState = "not-checked" | "passed" | "do-not-match" | "differs" | "missing" | "unreadable"

const WORD: Record<FileState, string> = {
  "not-checked": "Not checked",
  passed: "Passed",
  "do-not-match": "Do not match",
  differs: "Differs",
  missing: "Missing",
  unreadable: "Cannot be read",
}
const BAD = new Set<FileState>(["do-not-match", "differs", "missing", "unreadable"])

interface FileRow {
  name: string
  size?: number
  modified?: string
  state: FileState
}

interface Facts {
  name: string
  path: string
  cause: Cause
  lead: string
  stop?: string
  /** When the folder reached MinIO, said in the header when no file list carries each file's time. */
  modified?: string
  files: FileRow[]
  signer?: string
  sha?: { got: string; want: string }
  wantSize?: number
  expected?: string
}

const sentence = (text: string) => `${text.charAt(0).toUpperCase()}${text.slice(1)}${/[.!?]$/.test(text) ? "" : "."}`

/** What a refusal is about, from the listing's verdict and, on an import's page, the attempt's reason. */
function factsOf(archive: Archive | undefined, imp: Import | undefined, name: string | undefined): Facts {
  const key = archive?.key ?? imp?.archive.key ?? ""
  const { file } = archiveName(key)
  const path = key.slice(0, key.length - file.length)
  const attempt = imp ? latestAttempt(imp) : undefined
  const impReason = attempt?.outcome === "refused" ? attempt.report.reason : ""
  const reason = impReason || archive?.reason || ""
  const sha = SHA_REFUSAL.exec(impReason)
  const signature = archive?.signature
  const project = archive?.signature === "verified" ? archive.crossing?.project : attempt?.report.crossing?.project
  const at = archive?.modified ?? imp?.createdAt ?? ""
  const title = name ?? (project ? crossingLabel(project, at, [at]) : folderLabel(key))

  let cause: Cause = "other"
  if (sha) cause = sha[2] === "manifest's" ? "archive" : "expected"
  else if (signature === "unknown-key") cause = "key"
  else if (signature === "mismatch") cause = "signature"
  else if (archive?.reason === "the archive does not match its manifest") cause = "archive"
  else if (archive?.reason?.startsWith("its manifest is ")) cause = "folder"
  const lead =
    cause === "key"
      ? "Signed with a key this side does not trust."
      : cause === "signature"
        ? "The signature does not match the manifest."
        : cause === "archive"
          ? "The archive does not match its manifest."
          : cause === "expected"
            ? "The archive matches its manifest. The sha256 you typed differs."
          : sentence(reason || "Reason not recorded")
  const stop =
    cause === "key" || cause === "signature" || signature === "unsigned" || signature === "unreadable" ? "signature" : cause === "archive" || cause === "expected" ? "archive" : cause === "folder" ? "folder" : undefined

  // The folder's files as MinIO lists them, else the objects the import read; neither on an archive of 0.7.0.
  const listed = archive?.files
  const read = imp ? [imp.archive, imp.manifest, imp.signature] : undefined
  const names = [file, "manifest.json", "manifest.json.sig"]
  const files = names.map((n, i): FileRow => {
    const entry = listed ? listed.find((f) => f.name === n) : read?.[i] ? { size: read[i]!.size, modified: undefined } : undefined
    const known = listed !== undefined || read !== undefined
    let state: FileState = "not-checked"
    if (!entry && known) state = "missing"
    else if (cause === "signature") state = i === 0 ? "not-checked" : "do-not-match"
    else if (cause === "archive") state = i === 0 ? "differs" : "passed"
    else if (cause === "expected") state = "passed"
    else if (signature === "unreadable") state = (i === 1 && reason === "its manifest cannot be read") || (i === 2 && reason.includes("manifest.json.sig cannot be read")) ? "unreadable" : "not-checked"
    else if (cause === "folder" && signature === "verified" && i > 0) state = "passed"
    return { name: n, size: entry?.size, modified: entry?.modified, state }
  })

  const expected = sha?.[3] ?? (imp && HEX.test(imp.expectedSha256) ? imp.expectedSha256 : undefined)
  return {
    name: title,
    path,
    cause,
    lead,
    stop,
    modified: cause === "key" ? archive?.modified : undefined,
    files,
    signer: archive?.signerKeySha256 && HEX.test(archive.signerKeySha256) ? archive.signerKeySha256 : undefined,
    sha: sha ? { got: sha[1], want: sha[3] } : undefined,
    wantSize: archive?.declaredSize !== undefined && archive.declaredSize !== archive.size ? archive.declaredSize : undefined,
    expected,
  }
}

const ICON = [FileArchive, FileJson, FileKey]

function Chip({ state, hidden = false }: { state: FileState; hidden?: boolean }) {
  const bad = BAD.has(state)
  const Icon = bad ? X : state === "passed" ? Check : Minus
  return (
    <span
      aria-hidden={hidden ? true : undefined}
      className={cn(
        "inline-flex h-7 flex-none items-center gap-1 self-center !rounded-full px-2.5 text-[13px] font-semibold whitespace-nowrap",
        bad ? "border border-bad-line bg-bg text-bad" : state === "passed" ? "tinted-ok text-ok" : "border border-rule-2 bg-bg text-ink-2",
      )}
    >
      <Icon aria-hidden="true" className="size-3.5" />
      {WORD[state]}
    </span>
  )
}

function FileLine({ row, index, chip, children }: { row: FileRow; index: number; chip: boolean; children?: ReactNode }) {
  const Icon = ICON[index]
  const now = new Date()
  return (
    <div role="listitem" className="grid grid-cols-[20px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-2 px-4 py-2.5">
      <Icon aria-hidden="true" className={cn("mt-0.5 size-4", BAD.has(row.state) ? "text-bad" : "text-muted")} />
      <div className="min-w-0">
        <p data-file-name="" className="font-mono text-[13px] text-ink [overflow-wrap:anywhere]">
          {row.name}
        </p>
        <p className="text-[13px] text-muted">
          {row.size !== undefined ? <b className="font-semibold text-ink">{formatBytes(row.size)}</b> : null}
          {row.size !== undefined && row.modified ? " · " : null}
          {row.modified ? uploaded(row.modified, now) : null}
          {row.size === undefined && !row.modified ? (row.state === "missing" ? "Not in the folder" : "Not listed") : null}
        </p>
      </div>
      {chip ? <Chip state={row.state} /> : <span className="sr-only">{WORD[row.state]}</span>}
      {children ? <div className="col-start-2 col-end-4 grid gap-2 text-[13px]">{children}</div> : null}
    </div>
  )
}

function Marked({ value, other, testId }: { value: string; other: string; testId: string }) {
  return (
    <span data-testid={testId} className="flex min-w-0 flex-wrap gap-x-[1ch] gap-y-0.5 font-mono text-xs leading-5">
      {(value.match(/.{1,8}/g) ?? []).map((group, g) => (
        <Fragment key={g}>
          {g > 0 ? " " : null}
          <span className="whitespace-nowrap">
            {[...group].map((char, c) =>
              char !== other[g * 8 + c] ? (
                <mark key={c} className="rounded-sm bg-bad-tint font-semibold text-bad underline decoration-2 underline-offset-2">
                  {char}
                </mark>
              ) : (
                char
              ),
            )}
          </span>
        </Fragment>
      ))}
    </span>
  )
}

/** Both sha256 one over the other, the characters that differ marked in each. */
function ShaCompare({ got, want, typed = false }: { got: string; want: string; typed?: boolean }) {
  return (
    <div data-testid="sha256-compare" className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-2">
      <span className="pt-0.5 text-muted">In MinIO</span>
      <Marked value={got} other={want} testId="in-minio" />
      <CopyControl text={got} label="the sha256 in MinIO" compact />
      <span className="pt-0.5 text-muted">{typed ? "Typed" : "Expected"}</span>
      <Marked value={want} other={got} testId="expected" />
      <CopyControl text={want} label={typed ? "the sha256 you typed" : "the expected sha256"} compact />
    </div>
  )
}

function ArchiveMore({ facts }: { facts: Facts }) {
  if (facts.sha) {
    return (
      <>
        {facts.cause === "archive" ? <p className="text-muted">Same size as the manifest says</p> : null}
        <ShaCompare got={facts.sha.got} want={facts.sha.want} typed={facts.cause === "expected"} />
      </>
    )
  }
  return (
    <>
      {facts.wantSize !== undefined ? (
        <p className="text-muted">
          {"The manifest says "}
          <b className="font-semibold text-ink">{formatBytes(facts.wantSize)}</b>
        </p>
      ) : null}
      {facts.expected ? (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-muted">Expected</span>
          <Fingerprint value={facts.expected} label="Expected sha256" />
        </div>
      ) : null}
    </>
  )
}

function Files({ facts, trusted }: { facts: Facts; trusted: string }) {
  // Consecutive files to bring again share one closed red shape and, when they share it, one state.
  const groups: { bad: boolean; rows: { row: FileRow; index: number }[] }[] = []
  facts.files.forEach((row, index) => {
    const bad = BAD.has(row.state)
    const last = groups[groups.length - 1]
    if (last && last.bad && bad) last.rows.push({ row, index })
    else groups.push({ bad, rows: [{ row, index }] })
  })
  const line = (row: FileRow, index: number, chip: boolean) => (
    <FileLine key={row.name} row={row} index={index} chip={chip}>
      {index === 0 && (facts.cause === "archive" || facts.cause === "expected") ? <ArchiveMore facts={facts} /> : null}
    </FileLine>
  )
  return (
    <section className="mt-7">
      <h4 className="mb-2.5 text-[15px] font-semibold text-ink">Files</h4>
      <div className="overflow-hidden rounded-xl border border-rule">
        {facts.cause === "signature" && HEX.test(trusted) ? (
          <div data-testid="named-key" className="grid gap-2 border-b border-rule px-4 py-3">
            <p className="inline-flex items-center gap-2 text-[13px] text-ink-2">
              <KeyRound aria-hidden="true" className="size-4 flex-none text-muted" />
              <span>
                <span className="font-mono">manifest.json.sig</span> names the key trusted here
              </span>
            </p>
            <Fingerprint value={trusted} label="Key named in manifest.json.sig" />
          </div>
        ) : null}
        <div role="list" aria-label="Files" className="grid gap-1 p-1.5">
          {groups.map((group) => {
            if (!group.bad) return group.rows.map(({ row, index }) => line(row, index, true))
            const shared = group.rows.length > 1 && group.rows.every(({ row }) => row.state === group.rows[0].row.state)
            return (
              <div key={group.rows[0].row.name} data-testid="bring-again" className="tinted-bad grid grid-cols-[minmax(0,1fr)_auto] items-center !rounded-lg">
                <div className="min-w-0">{group.rows.map(({ row, index }) => line(row, index, !shared))}</div>
                {shared ? (
                  <span className="pr-4">
                    <Chip state={group.rows[0].row.state} hidden />
                  </span>
                ) : null}
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}

function Keys({ signer, trusted }: { signer?: string; trusted: string }) {
  const [compare, setCompare] = useState(false)
  const differ = signer ? [...signer].filter((c, i) => c !== trusted[i]).length : undefined
  return (
    <section className="mt-7">
      <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-[15px] font-semibold text-ink">Keys</h4>
        {differ !== undefined ? (
          <p className="inline-flex items-center gap-1.5 text-[13px] text-bad">
            <CircleX aria-hidden="true" className="size-4" />
            <span>
              <b className="font-semibold">{`${differ} of 64`}</b> characters differ
            </span>
          </p>
        ) : null}
      </div>
      <div className="rounded-xl border border-rule">
        <div className="grid gap-3 px-4 py-3">
          <div className="grid gap-1.5">
            <span className="text-[13px] text-ink-2">Signed with</span>
            {signer ? <Fingerprint value={signer} label="Signed with" /> : <p className="text-[13px] text-muted">Not named in manifest.json.sig</p>}
          </div>
          <div className="grid gap-1.5">
            <span className="text-[13px] text-ink-2">Trusted here</span>
            <Fingerprint value={trusted} label="Trusted here" />
          </div>
          <FingerprintCompare trusted={trusted} open={compare} />
        </div>
        <div className="flex justify-end border-t border-rule px-3 py-2">
          <Button type="button" variant="outline" size="sm" aria-expanded={compare} onClick={() => setCompare((c) => !c)}>
            <GitCompareArrows aria-hidden="true" />
            Compare
          </Button>
        </div>
      </div>
    </section>
  )
}

const ABSOLUTE = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" })
const HOUR = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false })
const absolute = (at: Date) => `${ABSOLUTE.format(at)} at ${HOUR.format(at)}`

/** The details as plain text, for the developer to carry to the connected side. */
function detailsText(facts: Facts, trusted: string, sides: { online: string; offline: string }, now: Date): string {
  const lines = [`Refused archive on ${sides.offline}, ${absolute(now)}`, `Folder: ${facts.path}`, `Reason: ${facts.lead.charAt(0).toLowerCase()}${facts.lead.slice(1)}`]
  lines.push(facts.stop ? `Nothing reached Nexus. Stopped at the ${facts.stop} check.` : "Nothing reached Nexus.")
  if (facts.cause === "signature") lines.push(`Key named in manifest.json.sig: sha256 ${trusted} (the key trusted here)`)
  if (facts.cause === "key") {
    lines.push(`Signed with: ${facts.signer ? `sha256 ${facts.signer}` : "not named in manifest.json.sig"}`, `Trusted here: sha256 ${trusted}`)
    if (facts.modified) lines.push(`Uploaded: ${absolute(new Date(facts.modified))}`)
    return lines.join("\n")
  }
  if (facts.wantSize !== undefined) lines.push(`The manifest says: ${formatBytes(facts.wantSize)}`)
  if (facts.sha) lines.push(`sha256 in MinIO: ${facts.sha.got}`, `${facts.cause === "expected" ? "Typed" : "Expected"} sha256: ${facts.sha.want}`)
  else if (facts.expected) lines.push(`Expected sha256: ${facts.expected}`)
  const nameWidth = Math.max(...facts.files.map((f) => f.name.length))
  const sizes = facts.files.map((f) => (f.size !== undefined ? formatBytes(f.size) : ""))
  const sizeWidth = Math.max(...sizes.map((s) => s.length))
  lines.push("Files:")
  facts.files.forEach((f, i) => {
    const when = f.modified ? `uploaded ${absolute(new Date(f.modified))}` : f.state === "missing" ? "not in the folder" : "upload time not listed"
    lines.push(`  ${f.name.padEnd(nameWidth)}  ${sizes[i].padEnd(sizeWidth)}  ${when}  ${WORD[f.state].toLowerCase()}`)
  })
  const again = facts.files.filter((f) => BAD.has(f.state)).map((f) => f.name)
  if (again.length > 0) lines.push(`Download again from ${sides.online}: ${again.join(", ")}`)
  return lines.join("\n")
}

function CopyDetails({ text }: { text: () => string }) {
  const [state, setState] = useState<"idle" | "copied" | "select">("idle")
  const [shown, setShown] = useState("")
  async function copy() {
    const value = text()
    try {
      if (!navigator.clipboard?.writeText) throw new Error("no clipboard")
      await navigator.clipboard.writeText(value)
      setState("copied")
    } catch {
      setShown(value)
      setState("select")
    }
  }
  const copied = state === "copied"
  return (
    <>
      <Button type="button" size="page" onClick={() => void copy()}>
        {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        <span className="grid">
          <span className="col-start-1 row-start-1">{copied ? "Copied" : "Copy details"}</span>
          <span aria-hidden="true" className="invisible col-start-1 row-start-1">
            {copied ? "Copy details" : "Copied"}
          </span>
        </span>
      </Button>
      <span role="status" className="sr-only">
        {copied ? "Copied" : null}
      </span>
      {state === "select" ? (
        <div className="basis-full">
          <p className="text-sm text-muted">The clipboard is not available on this page. The text is selected: press Ctrl+C, or Command+C on a Mac, to copy it.</p>
          <textarea
            readOnly
            autoFocus
            onFocus={(e) => e.currentTarget.select()}
            rows={8}
            value={shown}
            aria-label="Text of the details"
            className="mt-2 w-full rounded-md border border-line bg-background p-2 font-mono text-xs [overflow-wrap:anywhere]"
          />
        </div>
      ) : null}
    </>
  )
}

function WhatToDo({ facts }: { facts: Facts }) {
  const { online } = useBrand()
  const bad = facts.files.filter((f) => BAD.has(f.state))
  const words = [...new Set(bad.map((f) => WORD[f.state]))]
  if (facts.cause === "key") return <p className="text-sm text-ink-2">Send your administrators the details, then remove the three files from your folder.</p>
  if (facts.cause === "expected") return <p className="text-sm text-ink-2">Check the value you copied from the Sealed page.</p>
  if (bad.length > 0) {
    return (
      <p className="text-sm text-ink-2">
        {`Download the ${bad.length === 1 ? "file" : "files"} marked `}
        {words.map((w, i) => (
          <Fragment key={w}>
            {i > 0 ? " or " : null}
            <b className="font-semibold text-ink">{w}</b>
          </Fragment>
        ))}
        {` again from ${online}.`}
      </p>
    )
  }
  if (facts.cause === "folder") {
    const target = facts.path.startsWith(FOLDERS[0]) ? FOLDERS[1] : FOLDERS[0]
    return (
      <p className="text-sm text-ink-2">
        {"Move the three files into a folder under "}
        <span className="font-mono">{target}</span>.
      </p>
    )
  }
  return <p className="text-sm text-ink-2">Keep one archive with its manifest.json and manifest.json.sig in its folder.</p>
}

interface RefusedDetailsProps {
  archive?: Archive
  imp?: Import
  /** The sha256 of the key this side trusts. */
  trusted: string
  /** The row's name, as the home shows it; else the crossing once the signature verifies, or the folder. */
  name?: string
}

/** Why an archive was refused: the reason, that nothing reached Nexus, the folder's files or both keys, what to do, Copy details and the contact. */
export function RefusedDetails({ archive, imp, trusted, name }: RefusedDetailsProps) {
  const brand = useBrand()
  const facts = factsOf(archive, imp, name)
  const mono = !name && !(archive?.signature === "verified" && archive.crossing?.project) && !(imp && latestAttempt(imp).report.crossing?.project)
  const present = facts.files.filter((f) => f.size !== undefined || f.modified).length
  return (
    <div>
      <h3 className={cn("text-[22px] leading-tight font-bold tracking-tight text-ink [overflow-wrap:anywhere]", mono && "font-mono text-xl")}>{facts.name}</h3>
      <p className="mt-1.5 text-[13px] text-muted [overflow-wrap:anywhere]">
        {facts.modified ? `${sentence(uploaded(facts.modified, new Date())).slice(0, -1)} · ` : null}
        <span className="font-mono">{facts.path}</span>
        {present > 0 ? (
          <>
            {" · "}
            <b className="font-semibold text-ink">{`${present} ${present === 1 ? "file" : "files"}`}</b>
          </>
        ) : null}
      </p>
      <p className="mt-5 text-[17px] font-semibold text-ink [overflow-wrap:anywhere]">{facts.lead}</p>
      <p className="mt-2 inline-flex items-start gap-2 text-sm text-ink-2">
        <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 flex-none text-ok" />
        <span>
          <b className="font-semibold text-ink">Nothing reached Nexus.</b>
          {facts.stop ? ` Stopped at the ${facts.stop} check.` : null}
        </span>
      </p>
      {facts.cause === "key" ? <Keys signer={facts.signer} trusted={trusted} /> : <Files facts={facts} trusted={trusted} />}
      <section className="mt-7">
        <h4 className="mb-1.5 text-[15px] font-semibold text-ink">What to do</h4>
        <WhatToDo facts={facts} />
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <CopyDetails text={() => detailsText(facts, trusted, brand, new Date())} />
        </div>
        <ContactCard caption={facts.cause === "key" ? "To trust another key" : "If the new copy is refused too"} />
      </section>
    </div>
  )
}

interface RefusedPanelProps {
  archive: Archive
  trusted: string
  open: boolean
  onClose: () => void
  returnFocus?: HTMLElement | null
  /** The row's name, so the panel reads as the row it opened from. */
  name?: string
}

/** A refused archive of the home, from the right: the Refused band, then its details. */
export function RefusedPanel({ archive, trusted, open, onClose, returnFocus, name }: RefusedPanelProps) {
  return (
    <Panel open={open} onClose={onClose} tone="bad" heading="Refused" icon={CircleX} returnFocus={returnFocus}>
      <RefusedDetails archive={archive} trusted={trusted} name={name} />
    </Panel>
  )
}
