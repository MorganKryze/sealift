import { useId } from "react"

import { Card } from "@/components/ui/card"
import { reasonKey, reasonProblem, type NeededReason } from "@/lib/requiredReasons"
import { cn } from "@/lib/utils"

interface ReasonsBlockProps {
  needed: NeededReason[]
  reasons: Record<string, string>
  onChange: (key: string, text: string) => void
  /** The server's words when it refused the export for its reasons. */
  refusal?: string
}

const KIND_WORDS: Record<NeededReason["kind"], string> = {
  "major-jump": "Leaves its line",
  "cve-without-fix": "Keeps a CVE with no known fix",
}

/** One text field per reason the selection needs, then the server's refusal, if any. */
export function ReasonsBlock({ needed, reasons, onChange, refusal }: ReasonsBlockProps) {
  const id = useId()
  if (needed.length === 0 && !refusal) {
    return null
  }

  return (
    <section aria-labelledby={`${id}-title`} className="mt-7">
      <h2 id={`${id}-title`} className="text-lg font-semibold text-ink">
        Reasons
      </h2>
      <p className="mt-1 mb-2.5 max-w-[70ch] text-sm text-muted">
        This selection takes a dependency out of its line, or keeps a CVE that no version fixes. Write why for each, on one line: the
        signed manifest carries the reasons to the other side.
      </p>
      {needed.length > 0 ? (
        <Card>
          {needed.map((reason, index) => {
            const key = reasonKey(reason)
            const field = `${id}-${index}`
            const text = reasons[key] ?? ""
            const problem = reasonProblem(text)
            return (
              <div key={key} className={cn("flex flex-col gap-1.5 px-4.5 py-3.5", index > 0 && "border-t border-line")}>
                <label htmlFor={field} className="flex flex-wrap items-baseline gap-x-2 text-sm">
                  <span className="font-mono font-semibold text-ink [overflow-wrap:anywhere]">{reason.label}</span>
                  <span className="text-muted">{KIND_WORDS[reason.kind]}</span>
                </label>
                <p id={`${field}-detail`} className="font-mono text-xs text-muted [overflow-wrap:anywhere]">
                  {reason.detail}
                </p>
                <textarea
                  id={field}
                  rows={2}
                  value={text}
                  spellCheck
                  aria-invalid={problem !== undefined}
                  aria-describedby={problem ? `${field}-detail ${field}-problem` : `${field}-detail`}
                  // A reason is one line: Enter adds nothing, and a pasted line break shows its problem below.
                  onKeyDown={(event) => {
                    if (event.key === "Enter") event.preventDefault()
                  }}
                  onChange={(event) => onChange(key, event.target.value)}
                  className={cn(
                    "min-h-16 w-full resize-y rounded-md border bg-background px-3 py-2 text-sm text-ink outline-none transition-colors",
                    "focus:border-accent focus:ring-3 focus:ring-accent/20",
                    problem ? "border-severity-critical" : "border-line",
                  )}
                />
                {problem ? (
                  <p id={`${field}-problem`} className="text-xs text-severity-critical-fg">
                    {problem}
                  </p>
                ) : null}
              </div>
            )
          })}
        </Card>
      ) : null}
      {refusal ? (
        <div role="alert" className="mt-3 rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-4 text-sm text-ink">
          <p className="font-medium">The server refused the export for its reasons</p>
          <p className="text-muted [overflow-wrap:anywhere]">{refusal}</p>
        </div>
      ) : null}
    </section>
  )
}
