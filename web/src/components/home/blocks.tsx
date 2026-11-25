import { Link } from "@tanstack/react-router"
import { ChevronDown, ChevronRight, CircleDashed, type LucideIcon } from "lucide-react"
import { type Ref, useId, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

/** A path the home starts; the lead one takes the deployment's accent as its outline. */
export function PathCard({ to, icon: Icon, title, detail, lead }: { to: string; icon: LucideIcon; title: string; detail: string; lead?: boolean }) {
  return (
    <Link
      to={to}
      data-path-card=""
      className={cn(
        "flex min-h-20 items-center gap-4 rounded-xl border bg-bg px-4.5 py-4 text-ink transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover",
        lead ? "border-brand shadow-sm" : "border-rule-2",
      )}
    >
      <span className="grid size-10 flex-none place-items-center rounded-lg bg-hover text-ink-2">
        <Icon aria-hidden="true" className="size-5" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-lg font-semibold">{title}</span> <span className="block text-sm text-muted">{detail}</span>
      </span>
      <ChevronRight aria-hidden="true" className="size-4 flex-none text-muted" />
    </Link>
  )
}

export type Tone = "ok" | "warn" | "bad" | "info"

export interface HomeRow {
  key: string
  icon: LucideIcon
  name: string
  detail: string
  /** The row's state in words; a row with none, such as an archive waiting for its import, draws its icon on a neutral box. */
  state?: { label: string; tone: Tone }
  action: { label: string; to: string; search?: Record<string, string>; primary?: boolean }
}

// A failed row is tinted red itself, so its icon box and chip sit on the page colour to stand out.
const BOX: Record<Tone, string> = {
  ok: "tinted-ok text-ok",
  warn: "tinted-warn text-warn",
  bad: "tinted-bad bg-bg text-bad",
  info: "tinted-info text-info",
}

/** A group shows this many rows before its Show all. */
export const GROUP_ROWS = 10

function Row({ row, actionRef }: { row: HomeRow; actionRef?: Ref<HTMLAnchorElement> }) {
  const { icon: Icon, state, action } = row
  const failed = state?.tone === "bad"
  return (
    <li className={cn("flex flex-wrap items-center gap-x-3 gap-y-2 py-3", failed ? "tinted-bad -mx-3 my-1 px-3" : "border-b border-rule")}>
      <span className={cn("grid size-8 flex-none place-items-center rounded-lg", state ? BOX[state.tone] : "bg-hover text-ink-2")}>
        <Icon aria-hidden="true" className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <p data-row-name="" className="font-semibold text-ink [overflow-wrap:anywhere]">
          {row.name}
        </p>
        <p className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm text-muted [overflow-wrap:anywhere]">
          {state ? <span className={cn("inline-flex w-fit items-center !rounded-full px-2 text-[13px] font-medium", BOX[state.tone])}>{state.label}</span> : null}
          {row.detail}
        </p>
      </div>
      <Button asChild variant={action.primary ? "default" : "outline"} className="max-sm:h-11">
        <Link to={action.to} search={action.search} aria-label={`${action.label} ${row.name}`} ref={actionRef}>
          {action.label}
        </Link>
      </Button>
    </li>
  )
}

/** A titled group of home rows, newest first as given: the first 10, then a control that shows the rest in place. Renders nothing when empty. */
export function RowGroup({ title, rows, noun, limit = GROUP_ROWS, onShowAll }: { title: string; rows: HomeRow[]; noun: [string, string]; limit?: number; onShowAll?: () => void }) {
  const id = useId()
  const [all, setAll] = useState(false)
  // The control that showed the rest leaves the page, so focus moves to the first row it showed.
  const moveFocus = useRef(false)
  if (rows.length === 0) return null
  const shown = all ? rows : rows.slice(0, limit)
  return (
    <section aria-labelledby={id} className="mt-10">
      <h2 id={id} className="border-b border-rule pb-2 text-sm font-medium text-ink-2">
        {title}
      </h2>
      <ul className="flex flex-col">
        {shown.map((row, index) => (
          <Row
            key={row.key}
            row={row}
            actionRef={
              index === limit
                ? (el: HTMLAnchorElement | null) => {
                    if (el && moveFocus.current) {
                      moveFocus.current = false
                      el.focus()
                    }
                  }
                : undefined
            }
          />
        ))}
      </ul>
      {shown.length < rows.length ? (
        <Button
          variant="outline"
          className="mt-4"
          onClick={() => {
            moveFocus.current = true
            setAll(true)
            onShowAll?.()
          }}
        >
          <ChevronDown aria-hidden="true" />
          {`Show all ${rows.length} ${rows.length === 1 ? noun[0] : noun[1]}`}
        </Button>
      ) : null}
    </section>
  )
}

/** A group kept on the page with nothing in it, its empty state said in words. */
export function EmptyGroup({ title, text }: { title: string; text: string }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="mt-10">
      <h2 id={id} className="border-b border-rule pb-2 text-sm font-medium text-ink-2">
        {title}
      </h2>
      <p className="flex items-center gap-3 border-b border-rule py-3.5 text-muted">
        <CircleDashed aria-hidden="true" className="size-5 flex-none" />
        {text}
      </p>
    </section>
  )
}
