import { Info } from "lucide-react"
import { useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties } from "react"
import { createPortal } from "react-dom"

import { cn } from "@/lib/utils"

export type TermId = "cve" | "severity" | "major-jump" | "checks" | "sha512"

// Matches the popover's w-72 class.
const POPOVER_WIDTH = 288

// About the tallest popover at 288 px wide: two sentences and the Read more link, with its gap.
const POPOVER_HEIGHT = 180

/**
 * Which side of its button a popover opens on: the preferred side when the window has room there, the other
 * one otherwise. A term in a block's head prefers above, so its popover leaves the first row below readable.
 */
export function termSide(prefer: "above" | "below", button: { top: number; bottom: number }, windowHeight: number): "above" | "below" {
  const roomAbove = button.top >= POPOVER_HEIGHT
  const roomBelow = windowHeight - button.bottom >= POPOVER_HEIGHT
  if (prefer === "above") return roomAbove || !roomBelow ? "above" : "below"
  return roomBelow || !roomAbove ? "below" : "above"
}

const DOCS = "https://github.com/MorganKryze/sealift/blob/main/docs/how-sealift-chooses.md"

/**
 * Where each term's section of the docs lives: fixed addresses, so no link is built from data. The import side's terms have
 * none, as its network reaches no public docs.
 */
export const TERM_DOCS: Record<Exclude<TermId, "checks" | "sha512">, string> = {
  cve: `${DOCS}#known-cves`,
  severity: `${DOCS}#severity`,
  "major-jump": `${DOCS}#major-jump`,
}

const SHA512 = "Each package's own fingerprint, listed in the manifest."

const TERMS: Record<TermId, { name: string; text: string | { term: string; text: string }[] }> = {
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
  checks: {
    name: "What these checks mean",
    text: [
      { term: "Signature", text: "The connected side signed the manifest. This side checked it with the key its administrators trust." },
      { term: "sha256", text: "A fingerprint of the file. One changed byte gives another one." },
      { term: "sha512", text: SHA512 },
    ],
  },
  sha512: { name: "What a sha512 is", text: SHA512 },
}

/**
 * An info button beside a term, opening two sentences, or a short list of definitions, and a link to its docs section when it has one. A disclosure, not a
 * dialog: the focus stays on the button until Tab moves into the link. Escape, a second press or a press
 * outside closes it and gives the focus back to the button. The popover renders at the end of its dialog, or
 * of the body outside one, placed from the button, so no block that clips its overflow cuts it.
 */
export function Term({ id, prefer = "below" }: { id: TermId; prefer?: "above" | "below" }) {
  const term = TERMS[id]
  const docs = id in TERM_DOCS ? TERM_DOCS[id as keyof typeof TERM_DOCS] : undefined
  const [open, setOpen] = useState(false)
  const [side, setSide] = useState<"above" | "below">("below")
  const [align, setAlign] = useState<"start" | "end">("start")
  const [place, setPlace] = useState<CSSProperties>({ left: 0, top: 0, visibility: "hidden" })
  const popoverId = useId()
  const wrapper = useRef<HTMLSpanElement>(null)
  const button = useRef<HTMLButtonElement>(null)
  const popover = useRef<HTMLDivElement>(null)
  const link = useRef<HTMLAnchorElement>(null)
  // Inside a dialog the popover stays in it, so the dialog's focus trap and outside press keep working.
  const [host, setHost] = useState<HTMLElement | null>(null)

  useLayoutEffect(() => {
    if (!open) return
    const position = () => {
      const node = popover.current
      if (!button.current || !node) return
      const rect = button.current.getBoundingClientRect()
      const width = Math.min(POPOVER_WIDTH, window.innerWidth - 32)
      const shift = Math.max(16 - rect.left, Math.min(0, window.innerWidth - 16 - width - rect.left))
      const where = termSide(prefer, rect, window.innerHeight)
      // A transformed host, such as a sliding panel, moves where fixed positions start: measure its origin.
      const box = node.getBoundingClientRect()
      const origin = { left: box.left - (parseFloat(node.style.left) || 0), top: box.top - (parseFloat(node.style.top) || 0) }
      const top = where === "above" ? rect.top - 4 - node.offsetHeight : rect.bottom + 4
      setSide(where)
      setAlign(shift < 0 ? "end" : "start")
      setPlace({ left: rect.left + shift - origin.left, top: top - origin.top })
    }
    position()
    window.addEventListener("resize", position)
    window.addEventListener("scroll", position, true)
    return () => {
      window.removeEventListener("resize", position)
      window.removeEventListener("scroll", position, true)
    }
  }, [open, prefer])

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node
      if (wrapper.current?.contains(target) || popover.current?.contains(target)) return
      setOpen(false)
      button.current?.focus()
    }
    document.addEventListener("pointerdown", onPointerDown)
    return () => document.removeEventListener("pointerdown", onPointerDown)
  }, [open])

  // The popover sits away from its button in the page, so Tab is carried by hand: the button to Read more,
  // Read more to whatever follows the button, Shift+Tab back to the button.
  const after = () => {
    const root = host ?? document.body
    const all = [...root.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])')]
    const order = all.filter((el) => !popover.current?.contains(el) && el.offsetParent !== null)
    return order[order.indexOf(button.current as HTMLElement) + 1]
  }

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
            setHost(button.current.closest<HTMLElement>("[role=dialog]"))
            setPlace({ left: 0, top: 0, visibility: "hidden" })
          }
          setOpen(!open)
        }}
        onKeyDown={(event) => {
          if (open && event.key === "Tab" && !event.shiftKey && link.current) {
            event.preventDefault()
            link.current.focus()
          }
        }}
        className={cn(
          "inline-grid size-8 flex-none place-items-center rounded-lg text-muted transition-colors duration-150 max-sm:size-11",
          "[@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink",
          open && "bg-hover text-ink",
        )}
      >
        <Info aria-hidden="true" className="size-4" />
      </button>
      {open ? (
        createPortal(
          <div
            ref={popover}
            id={popoverId}
            data-align={align}
            data-side={side}
            style={{ position: "fixed", ...place }}
            className="animate-fade z-60 block w-72 max-w-[calc(100vw-2rem)] rounded-xl border border-rule-2 bg-bg p-3.5 text-left text-[13px] leading-normal font-normal text-ink-2 shadow-[0_8px_24px_rgba(var(--shadow),0.12)] motion-reduce:animate-none"
          >
            {typeof term.text === "string" ? (
              <span className="block">{term.text}</span>
            ) : (
              <dl className="grid gap-2">
                {term.text.map((d) => (
                  <div key={d.term}>
                    <dt className="font-semibold text-ink">{d.term}</dt>
                    <dd>{d.text}</dd>
                  </div>
                ))}
              </dl>
            )}
            {docs ? (
              <a
                ref={link}
                href={docs}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-1 inline-flex min-h-8 items-center font-medium text-ink underline"
                onKeyDown={(event) => {
                  if (event.key !== "Tab") return
                  const next = event.shiftKey ? button.current : after()
                  if (!next) return
                  event.preventDefault()
                  next.focus()
                }}
              >
                Read more
              </a>
            ) : null}
          </div>,
          host ?? document.body,
        )
      ) : (
        <span id={popoverId} hidden />
      )}
    </span>
  )
}
