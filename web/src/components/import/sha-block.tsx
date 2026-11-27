import { CircleCheck, CircleX, GitCompareArrows, ShieldCheck } from "lucide-react"
import { Fragment, useId, useState, type ReactNode } from "react"

import { compareFingerprint, Fingerprint, normalizeFingerprint } from "@/components/fingerprint/fingerprint"
import { Button } from "@/components/ui/button"
import { Term } from "@/components/ui/term"
import { cn } from "@/lib/utils"

const COUNT = new Intl.NumberFormat("en-US")

interface ChecksProps {
  /** The signing key's sha256 the attempt checked with; absent from a report of sealift 0.4. */
  publicKeySha256?: string
  /** The archive's sha256 the signed manifest names. */
  archiveSha256: string
  /** The packages whose sha512 matched the manifest, of all it lists. */
  packages: { checked: number; total: number }
}

type Candidate = { id: "key" | "archive"; name: string; value: string }

/** The pasted value against each fingerprint: the one it matches, else the closest, with the characters that differ. */
function compareAll(candidates: Candidate[], pasted: string) {
  const results = candidates.map((c) => ({ ...c, result: compareFingerprint(c.value, pasted) }))
  const matched = results.find((r) => r.result.state === "match")
  if (matched) return matched
  return results.reduce<(typeof results)[number] | undefined>((best, r) => (!best || r.result.differs.length < best.result.differs.length ? r : best), undefined)
}

function Marked({ value, marked }: { value: string; marked: Set<number> }) {
  return (
    <span data-testid="pasted-groups" className="flex min-w-0 flex-wrap gap-x-[1ch] gap-y-0.5 font-mono text-xs leading-5 text-ink">
      {(value.match(/.{1,8}/g) ?? []).map((group, g) => (
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
  )
}

function Row({ name, children }: { name: string; children: ReactNode }) {
  return (
    <li className="flex min-h-13 flex-wrap items-center gap-x-4 gap-y-2 border-t border-rule px-4 py-2.5">
      <CircleCheck aria-hidden="true" className="size-4 flex-none text-ok" />
      <span className="w-20 flex-none font-semibold text-ink">{name}</span>
      {children}
    </li>
  )
}

/**
 * The three checks a complete import passed, each with the value it rests on, and one Compare field that answers for the archive's
 * sha256 and the signing key's: the browser compares what is pasted and sends nothing.
 */
export function Checks({ publicKeySha256, archiveSha256, packages }: ChecksProps) {
  const [open, setOpen] = useState(false)
  const [pasted, setPasted] = useState("")
  const fieldId = useId()
  const candidates: Candidate[] = [
    ...(publicKeySha256 ? [{ id: "key" as const, name: "the signing key's sha256", value: publicKeySha256 }] : []),
    { id: "archive", name: "the archive's sha256", value: archiveSha256 },
  ]
  const best = open ? compareAll(candidates, pasted) : undefined
  const state = best?.result.state ?? "empty"
  const matched = state === "match" ? best?.id : undefined
  const said =
    state === "match"
      ? `Matches ${best?.name}`
      : state === "differs" && best
        ? best.result.differs.length === 1
          ? `Does not match: 1 character differs, at position ${best.result.differs[0] + 1}`
          : `Does not match: ${best.result.differs.length} characters differ, the first at position ${best.result.differs[0] + 1}`
        : ""
  const print = (c: Candidate | undefined, label: string) =>
    c ? (
      <span data-matched={matched === c.id || undefined} className={cn("ml-auto inline-flex max-w-full min-w-0", matched === c.id && "[&>span>button:first-child]:border-ok [&>span>button:first-child]:ring-1 [&>span>button:first-child]:ring-ok")}>
        <Fingerprint value={c.value} label={label} />
      </span>
    ) : (
      <span className="ml-auto text-sm text-muted">Not recorded</span>
    )
  return (
    <section aria-labelledby={`${fieldId}-checks`}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-2 border-t border-rule bg-canvas px-4 py-2">
        <ShieldCheck aria-hidden="true" className="size-4 flex-none text-ink-2" />
        <h2 id={`${fieldId}-checks`} className="text-sm font-semibold text-ink">
          Checks <span className="font-normal text-muted">· 3 passed</span>
        </h2>
        <Term id="checks" />
        <Button type="button" variant="outline" size="sm" className="ml-auto" aria-expanded={open} aria-controls={fieldId} onClick={() => setOpen((was) => !was)}>
          <GitCompareArrows aria-hidden="true" />
          Compare
        </Button>
      </div>
      {open ? (
        <div className="grid gap-2 border-t border-rule px-4 py-3">
          <label htmlFor={fieldId} className="text-[13px] font-semibold text-ink">
            Compare with the connected side
          </label>
          <span className="relative block">
            <input
              id={fieldId}
              type="text"
              spellCheck={false}
              autoComplete="off"
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              className={cn("h-10 w-full rounded-lg border bg-bg pr-10 pl-3 font-mono text-xs text-ink", state === "match" ? "border-ok" : state === "differs" ? "border-bad" : "border-field")}
            />
            {state === "match" ? <CircleCheck aria-hidden="true" className="absolute top-1/2 right-3 size-4.5 -translate-y-1/2 text-ok" /> : null}
            {state === "differs" ? <CircleX aria-hidden="true" className="absolute top-1/2 right-3 size-4.5 -translate-y-1/2 text-bad" /> : null}
          </span>
          {state === "differs" && best ? <Marked value={normalizeFingerprint(pasted)} marked={new Set(best.result.differs)} /> : null}
          <div role="status" className="sr-only">
            {said || null}
          </div>
        </div>
      ) : null}
      <ul>
        <Row name="Signature">
          <span className="text-sm text-ink-2">the key trusted here</span>
          {print(candidates.find((c) => c.id === "key"), "signing key's sha256")}
        </Row>
        <Row name="Archive">
          <span className="text-sm text-ink-2">sha256 in the manifest</span>
          {print(candidates.find((c) => c.id === "archive"), "archive's sha256")}
        </Row>
        <Row name="Packages">
          <span className="text-sm text-ink-2">
            <b className="font-semibold text-ink tabular-nums">{`${COUNT.format(packages.checked)} of ${COUNT.format(packages.total)}`}</b> sha512 in the manifest
          </span>
        </Row>
      </ul>
    </section>
  )
}
