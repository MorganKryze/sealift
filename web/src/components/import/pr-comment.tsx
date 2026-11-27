import { ChevronDown, Copy, GitPullRequest } from "lucide-react"
import { useId, useRef, useState } from "react"

import { useBrand } from "@/components/frame/brand"
import { Button } from "@/components/ui/button"
import type { components } from "@/import/api/schema"
import { cn } from "@/lib/utils"

export type CrossingReview = components["schemas"]["CrossingReview"]

const COUNT = new Intl.NumberFormat("en-US")
const NOT_CARRIED = "not carried by this archive"
const sum = (values: number[]) => values.reduce((total, n) => total + n, 0)

/**
 * The comment a developer pastes in the review of the change that brought these packages: a Markdown table headed by the instance
 * and the crossing. Every row but the first is read from the signed manifest; a manifest with no review says so in its rows.
 */
export function prComment(input: { instance: string; crossing: string; inNexus: number; review?: CrossingReview; archiveSha256: string }): string {
  const { review } = input
  const cves = review ? `${COUNT.format(sum(review.cvesBefore))} → ${review.cvesAfter ? COUNT.format(sum(review.cvesAfter)) : "not checked together"}` : NOT_CARRIED
  const rows: [string, string][] = [
    [input.instance, input.crossing],
    ["Packages in Nexus", COUNT.format(input.inNexus)],
    ["Packages updated", review ? COUNT.format(review.updated) : NOT_CARRIED],
    ["Known CVEs", cves],
    ["Carried with a reason", review ? COUNT.format(review.carried) : NOT_CARRIED],
    ["Major jumps", review ? COUNT.format(review.jumps) : NOT_CARRIED],
    ["Archive sha256", input.archiveSha256],
  ]
  // A pipe in a name would open a column; the instance and the crossing come from deploy settings and a signed manifest.
  const cell = (text: string) => text.replace(/\|/g, "\\|")
  const left = Math.max(...rows.map(([label]) => cell(label).length))
  const right = Math.max(...rows.map(([, value]) => cell(value).length))
  const line = (a: string, b: string) => `| ${cell(a).padEnd(left)} | ${cell(b).padEnd(right)} |`
  const [head, ...body] = rows
  return [line(...head), `| ${"-".repeat(left)} | ${"-".repeat(right)} |`, ...body.map(([a, b]) => line(a, b))].join("\n")
}

type State = "idle" | "copied" | "select"

/** The comment folded under its instruction, Preview opening it in place, Copy as the page's primary. */
export function PrComment({ markdown }: { markdown: string }) {
  const brand = useBrand()
  const [open, setOpen] = useState(false)
  const [state, setState] = useState<State>("idle")
  const previewId = useId()
  const pre = useRef<HTMLPreElement>(null)

  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("no clipboard")
      await navigator.clipboard.writeText(markdown)
      setState("copied")
    } catch {
      // A page served over plain http has no clipboard: the comment opens selected, for the keyboard to copy.
      setOpen(true)
      setState("select")
      requestAnimationFrame(() => {
        if (pre.current) window.getSelection()?.selectAllChildren(pre.current)
      })
    }
  }

  return (
    <section aria-labelledby={`${previewId}-title`} className="mt-3 rounded-xl border border-rule-2 bg-bg">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
        <GitPullRequest aria-hidden="true" className="size-4 flex-none text-ink-2" />
        <h2 id={`${previewId}-title`} className="mr-auto text-sm font-semibold text-ink">
          {`Add this comment to your ${brand.reviewWord}`}
        </h2>
        <Button type="button" variant="ghost" size="sm" aria-expanded={open} aria-controls={previewId} onClick={() => setOpen((was) => !was)}>
          Preview
          <ChevronDown aria-hidden="true" className={cn("transition-transform duration-200", open && "rotate-180")} />
        </Button>
        <Button type="button" size="page" aria-label="Copy the comment" onClick={copy}>
          <Copy aria-hidden="true" />
          Copy
        </Button>
        <span aria-live="polite" className={state === "select" ? "basis-full text-sm text-muted" : "text-sm text-muted"}>
          {state === "copied" ? "Copied" : null}
          {state === "select" ? "The clipboard is not available on this page. The comment is selected: press Ctrl+C, or Command+C on a Mac, to copy it." : null}
        </span>
      </div>
      {open ? (
        <pre ref={pre} id={previewId} data-testid="pr-comment" role="region" aria-label="The comment" tabIndex={0} className="overflow-x-auto border-t border-rule px-4 py-3 font-mono text-xs leading-5 text-ink">
          {markdown}
        </pre>
      ) : (
        <span id={previewId} hidden />
      )}
    </section>
  )
}
