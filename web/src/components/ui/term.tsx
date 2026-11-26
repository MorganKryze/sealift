import { Info } from "lucide-react"
import { useEffect, useId, useRef, useState } from "react"

import { cn } from "@/lib/utils"

export type TermId = "cve" | "severity" | "major-jump"

// Matches the popover's w-72 class.
const POPOVER_WIDTH = 288

const DOCS = "https://github.com/MorganKryze/sealift/blob/main/docs/how-sealift-chooses.md"

/** Where each term's section of the docs lives: fixed addresses, so no link is built from data. */
export const TERM_DOCS: Record<TermId, string> = {
  cve: `${DOCS}#known-cves`,
  severity: `${DOCS}#severity`,
  "major-jump": `${DOCS}#major-jump`,
}

const TERMS: Record<TermId, { name: string; text: string }> = {
  cve: {
    name: "What a CVE is",
    text: "A CVE is a publicly listed security flaw, named by an id such as CVE-2024-4068. Known CVEs counts the ones the scan found in these versions.",
  },
  severity: {
    name: "What a severity is",
    text: "Each CVE is rated critical, high, medium or low by the harm it can do, or unknown when it has no rating. Versions are ranked by these counts, the most serious first.",
  },
  "major-jump": {
    name: "What a major jump is",
    text: "A major jump moves a package to a new major version, such as 4.x to 5.x. It may break your code, so it needs a reason.",
  },
}

/**
 * An info button beside a term, opening two sentences and a link to its docs section. A disclosure, not a
 * dialog: the focus stays on the button until Tab moves into the link. Escape, a second press or a press
 * outside closes it and gives the focus back to the button.
 */
export function Term({ id }: { id: TermId }) {
  const term = TERMS[id]
  const [open, setOpen] = useState(false)
  // How far left the popover moves from its button so it ends 16 px inside the window, as a panel puts a
  // term near the right edge.
  const [shift, setShift] = useState(0)
  const popoverId = useId()
  const wrapper = useRef<HTMLSpanElement>(null)
  const button = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: PointerEvent) => {
      if (wrapper.current?.contains(event.target as Node)) return
      setOpen(false)
      button.current?.focus()
    }
    document.addEventListener("pointerdown", onPointerDown)
    return () => document.removeEventListener("pointerdown", onPointerDown)
  }, [open])

  return (
    <span
      ref={wrapper}
      data-term-open={open || undefined}
      className="relative inline-flex align-middle"
      onKeyDown={(event) => {
        if (open && event.key === "Escape") {
          event.stopPropagation()
          setOpen(false)
          button.current?.focus()
        }
      }}
    >
      <button
        ref={button}
        type="button"
        aria-label={term.name}
        aria-expanded={open}
        aria-controls={popoverId}
        onClick={() => {
          if (!open && button.current) {
            const width = Math.min(POPOVER_WIDTH, window.innerWidth - 32)
            const left = button.current.getBoundingClientRect().left
            setShift(Math.max(16 - left, Math.min(0, window.innerWidth - 16 - width - left)))
          }
          setOpen(!open)
        }}
        className={cn(
          "inline-grid size-8 flex-none place-items-center rounded-lg text-muted transition-colors duration-150 max-sm:size-11",
          "[@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink",
          open && "bg-hover text-ink",
        )}
      >
        <Info aria-hidden="true" className="size-4" />
      </button>
      <span
        id={popoverId}
        hidden={!open}
        data-align={shift < 0 ? "end" : "start"}
        style={{ left: shift }}
        className="animate-fade absolute top-full z-30 mt-1 w-72 max-w-[calc(100vw-2rem)] rounded-xl border border-rule-2 bg-bg p-3.5 text-left text-[13px] leading-normal font-normal text-ink-2 shadow-[0_8px_24px_rgba(var(--shadow),0.12)] motion-reduce:animate-none"
      >
        {open ? (
          <>
            <span className="block">{term.text}</span>
            <a href={TERM_DOCS[id]} target="_blank" rel="noopener noreferrer" className="mt-1 inline-flex min-h-8 items-center font-medium text-ink underline">
              Read more
            </a>
          </>
        ) : null}
      </span>
    </span>
  )
}
