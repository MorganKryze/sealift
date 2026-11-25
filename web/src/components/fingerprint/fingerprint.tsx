import { ChevronDown, CircleCheck, CircleX } from "lucide-react"
import { Fragment, useId, useState } from "react"

import { CopyControl } from "@/components/copy-control"
import { cn } from "@/lib/utils"

const groupsOf8 = (value: string) => value.match(/.{1,8}/g) ?? []

/** A sha256 as one bordered button with its ends; a press opens it in place to the whole value, a copy control beside it. */
export function Fingerprint({ value, label }: { value: string; label: string }) {
  const [open, setOpen] = useState(false)
  const first = value.slice(0, 8)
  const last = value.slice(-8)
  const groups = groupsOf8(value)
  return (
    <span className="inline-flex max-w-full min-w-0 items-start gap-1">
      <button
        type="button"
        aria-expanded={open}
        // Fixed across open and closed, and holding the closed text, so the name never drifts from what shows.
        aria-label={`${label} ${first}…${last}`}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "inline-flex min-h-8 max-w-full min-w-0 items-center gap-2 rounded-lg border border-field bg-bg py-1.5 pr-2 pl-2.5 text-left font-mono text-xs leading-5 text-ink transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover",
          open && "items-start border-ink-2",
        )}
      >
        {open ? (
          <span className="flex min-w-0 flex-wrap gap-x-[1ch] gap-y-0.5 font-semibold">
            {groups.map((group, index) => (
              <Fragment key={index}>
                {index > 0 ? " " : null}
                <span className="whitespace-nowrap">{group}</span>
              </Fragment>
            ))}
          </span>
        ) : (
          <span className="inline-flex gap-[1ch] whitespace-nowrap">
            <span className="font-semibold">{first}</span>
            <span aria-hidden="true" className="text-muted">
              …
            </span>
            <span className="font-semibold">{last}</span>
          </span>
        )}
        <ChevronDown aria-hidden="true" className={cn("mt-0.5 size-3.5 flex-none text-muted", open && "rotate-180")} />
      </button>
      <CopyControl text={value} label={label} />
    </span>
  )
}

/** Reads a pasted sha256 the way people carry it: with or without a "sha256:" prefix, colons, spaces, in any case. */
export function normalizeFingerprint(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^sha256:/, "")
    .replace(/[:\s]/g, "")
}

/** Compares a pasted value with the trusted one, character by character: a match needs all 64 equal. */
export function compareFingerprint(trusted: string, pasted: string): { state: "empty" | "partial" | "match" | "differs"; typed: number; differs: number[] } {
  const value = normalizeFingerprint(pasted)
  if (value === "") return { state: "empty", typed: 0, differs: [] }
  const differs: number[] = []
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== trusted[i]) differs.push(i)
  }
  if (differs.length > 0) return { state: "differs", typed: value.length, differs }
  return { state: value.length === trusted.length ? "match" : "partial", typed: value.length, differs }
}

function Groups({ value, marked, testId }: { value: string; marked: Set<number>; testId: string }) {
  return (
    <span data-testid={testId} className="flex min-w-0 flex-wrap gap-x-[1ch] gap-y-0.5 font-mono text-xs leading-5">
      {groupsOf8(value).map((group, g) => (
        <span key={g} className="whitespace-nowrap">
          {[...group].map((char, c) => {
            const at = g * 8 + c
            return marked.has(at) ? (
              <mark key={c} className="rounded-sm bg-bad-tint font-semibold text-bad underline decoration-2 underline-offset-2">
                {char}
              </mark>
            ) : (
              char
            )
          })}
        </span>
      ))}
    </span>
  )
}

function says(result: ReturnType<typeof compareFingerprint>): string {
  if (result.state === "match") return "Matches the trusted key"
  if (result.state !== "differs") return ""
  const n = result.differs.length
  const first = result.differs[0] + 1
  return n === 1 ? `Does not match: 1 character differs, at position ${first}` : `Does not match: ${n} characters differ, the first at position ${first}`
}

/** A field beside the trusted key: the browser compares what is pasted with it and sends nothing. */
export function FingerprintCompare({ trusted, open }: { trusted: string; open: boolean }) {
  const [pasted, setPasted] = useState("")
  const id = useId()
  if (!open) return null

  const result = compareFingerprint(trusted, pasted)
  const value = normalizeFingerprint(pasted)
  const marked = new Set(result.differs)
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <label htmlFor={id} className="text-[13px] font-semibold text-ink">
        sha256 from the connected side
      </label>
      <span className="relative block">
        <input
          id={id}
          type="text"
          spellCheck={false}
          autoComplete="off"
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          className={cn(
            "h-10 w-full rounded-lg border bg-bg pr-10 pl-3 font-mono text-xs text-ink",
            result.state === "match" ? "border-ok" : result.state === "differs" ? "border-bad" : "border-field",
          )}
        />
        {result.state === "match" ? <CircleCheck aria-hidden="true" className="absolute top-1/2 right-3 size-4.5 -translate-y-1/2 text-ok" /> : null}
        {result.state === "differs" ? <CircleX aria-hidden="true" className="absolute top-1/2 right-3 size-4.5 -translate-y-1/2 text-bad" /> : null}
      </span>
      {result.state === "partial" ? <p className="text-sm text-muted">{`${result.typed} of ${trusted.length}`}</p> : null}
      {result.state === "differs" ? (
        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-4 gap-y-1">
          <span className="text-[13px] text-muted">Trusted</span>
          <Groups value={trusted} marked={marked} testId="trusted-groups" />
          <span className="text-[13px] text-muted">Pasted</span>
          <Groups value={value} marked={marked} testId="pasted-groups" />
        </div>
      ) : null}
      <div role="status" className="sr-only">
        {says(result) || null}
      </div>
    </div>
  )
}
