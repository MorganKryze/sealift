import { ChevronDown, ChevronRight, DoorOpen, Hourglass, X } from "lucide-react"
import { useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties, type KeyboardEvent, type ReactNode } from "react"

import { CopyControl } from "@/components/copy-control"
import { Button } from "@/components/ui/button"
import type { LogLine } from "@/lib/analysisEvents"
import { cn } from "@/lib/utils"

const COUNT = new Intl.NumberFormat("en-GB")

/** "1 line", "2,014 lines". */
export function lineCount(n: number): string {
  return `${COUNT.format(n)} ${n === 1 ? "line" : "lines"}`
}

/** What a cancel loses and keeps, and the words of its buttons. */
export interface CancelWords {
  label: string
  confirm: string
  lost: string
  keep: string
  onConfirm: () => Promise<unknown>
}

interface JobProgressProps {
  title: string
  /** What is counted under the title, or the step in words before anything is counted. */
  counted?: ReactNode
  progress?: { done: number; total: number }
  /** No estimate yet: a still striped track takes the bar's place. */
  estimating?: boolean
  log: LogLine[]
  logCount: number
  live: boolean
  note?: string
  cancel: CancelWords
  /** What sits between the bar and the log, such as the archive being read. */
  aside?: ReactNode
}

// Still on purpose: a moving stripe would read as progress the server never reported.
const STRIPES: CSSProperties = {
  backgroundImage: "repeating-linear-gradient(-45deg, color-mix(in srgb, var(--info) 65%, transparent) 0 6px, transparent 6px 12px)",
}

/**
 * A running job: the time left as a polite live title, what is counted under it, the bar or the still
 * track, the log open with its count, and Cancel with its in-place confirm. Every node stays mounted
 * for the whole run, so a screen reader hears the title change and the log keeps its scroll.
 */
export function JobProgress({ title, counted, progress, estimating = false, log, logCount, live, note, cancel, aside }: JobProgressProps) {
  const titleId = useId()
  const share = progress && progress.total > 0 ? Math.min(1, progress.done / progress.total) : 0

  return (
    <div>
      <h1 id={titleId} aria-live="polite" className="text-[34px] leading-tight font-bold tracking-tight text-ink">
        {title}
      </h1>
      {counted ? <p className="mt-1.5 text-[15px] text-muted">{counted}</p> : null}
      <div
        role="progressbar"
        aria-labelledby={titleId}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={estimating ? undefined : Math.round(share * 100)}
        data-estimating={estimating ? "" : undefined}
        className={cn("mt-6 h-2 w-full overflow-hidden rounded-full", estimating ? "bg-info-tint" : "bg-rule")}
        style={estimating ? STRIPES : undefined}
      >
        <div
          className={cn("h-full origin-left rounded-full bg-info", !estimating && "transition-transform duration-200 ease-linear")}
          style={{ transform: `scaleX(${estimating ? 0 : share})` }}
        />
      </div>
      {aside}
      <LogBlock className={aside ? "mt-3" : "mt-6"} lines={log} count={logCount} live={live} defaultOpen />
      <CancelRow note={note} cancel={cancel} />
    </div>
  )
}

interface LogBlockProps {
  lines: LogLine[]
  /** Every line received; above the lines kept, the first ones are left out. */
  count?: number
  live?: boolean
  defaultOpen?: boolean
  /** Said beside the title when the lines are not there: loading, or not loaded. */
  status?: string
  /** The text Copy takes, else the lines shown. */
  copyText?: string
  className?: string
}

/** The log: a folding header with its count, Live while the job runs and Copy, then the lines, newest last. */
export function LogBlock({ lines, count, live = false, defaultOpen = false, status, copyText, className }: LogBlockProps) {
  const [open, setOpen] = useState(defaultOpen)
  const bodyId = useId()
  const body = useRef<HTMLDivElement>(null)
  // Follows new lines while the reader is at the bottom; a reader scrolled up keeps their place.
  const atBottom = useRef(true)
  const total = count ?? lines.length
  const leftOut = total - lines.length

  useLayoutEffect(() => {
    if (open && atBottom.current && body.current) body.current.scrollTop = body.current.scrollHeight
  }, [open, lines])

  const text = copyText ?? lines.map((line) => [line.at, line.step, line.text].filter(Boolean).join(" ")).join("\n")

  return (
    <div className={cn("overflow-hidden rounded-xl border border-rule", className)}>
      <div className="flex min-h-12 flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen((was) => !was)}
          className="inline-flex min-h-8 items-center gap-1.5 rounded-lg px-1.5 text-sm [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover"
        >
          {open ? <ChevronDown aria-hidden="true" className="size-4 text-muted" /> : <ChevronRight aria-hidden="true" className="size-4 text-muted" />}
          <span className="font-semibold text-ink">Log</span>
          {status === undefined ? (
            <>
              {" "}
              <span className="text-[13px] text-muted">{lineCount(total)}</span>
            </>
          ) : null}
        </button>
        {status ? <span className="text-[13px] text-muted">{status}</span> : null}
        <span className="ml-auto inline-flex items-center gap-3">
          {live ? (
            <span className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-ok">
              <span aria-hidden="true" className="size-2 rounded-full bg-ok" />
              Live
            </span>
          ) : null}
          {text ? <CopyControl text={text} label="the log" compact /> : null}
        </span>
      </div>
      {open ? (
        <div
          ref={body}
          id={bodyId}
          role="region"
          aria-label="Log"
          // A scrolling region the keyboard can reach.
          tabIndex={0}
          onScroll={(event) => {
            const el = event.currentTarget
            atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 8
          }}
          className="max-h-80 overflow-auto border-t border-rule bg-canvas px-4 py-3 font-mono text-xs leading-[1.7] text-ink-2"
        >
          {leftOut > 0 ? <p className="text-faint">{`The first ${lineCount(leftOut)} are left out here.`}</p> : null}
          {lines.length === 0 && leftOut <= 0 ? <p className="text-faint">{status ?? "No line yet."}</p> : null}
          {lines.map((line, index) => (
            <div key={index} className={line.at || line.step ? "grid grid-cols-[8ch_9ch_minmax(0,1fr)] gap-x-3" : undefined}>
              {line.at || line.step ? (
                <>
                  <span className="text-faint">{line.at}</span>
                  <span className="font-semibold text-ink [overflow-wrap:anywhere]">{line.step}</span>
                </>
              ) : null}
              <span
                className={cn(
                  "whitespace-pre-wrap [overflow-wrap:anywhere]",
                  line.tone === "ok" && "text-ok",
                  line.tone === "warn" && "text-warn",
                  line.tone === "bad" && "text-bad",
                )}
              >
                {line.text}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

type Phase = "idle" | "confirm" | "cancelling"

/**
 * The action row of a running or queued job: a note on what leaving does, then a tinted Cancel. Cancel
 * asks in place what is lost and moves the focus to the safe choice; only the confirm cancels, and the
 * button then reads Cancelling at the width it had.
 */
export function CancelRow({ note, cancel }: { note?: string; cancel: CancelWords }) {
  const [phase, setPhase] = useState<Phase>("idle")
  const row = useRef<HTMLDivElement>(null)
  const focusNext = useRef<"keep" | "cancel" | null>(null)

  useEffect(() => {
    const target = focusNext.current
    focusNext.current = null
    if (target) row.current?.querySelector<HTMLElement>(`[data-focus=${target}]`)?.focus()
  }, [phase])

  function keep() {
    focusNext.current = "cancel"
    setPhase("idle")
  }

  async function confirm() {
    setPhase("cancelling")
    try {
      await cancel.onConfirm()
    } catch {
      setPhase("idle")
    }
  }

  function onKeyDown(event: KeyboardEvent) {
    if (event.key === "Escape" && phase === "confirm") keep()
  }

  const cancelling = phase === "cancelling"

  return (
    <div ref={row} onKeyDown={onKeyDown} className="mt-7 flex flex-wrap items-center justify-end gap-x-3 gap-y-3">
      {phase === "confirm" ? (
        <>
          <p className="mr-1 text-[13px] text-ink-2">{cancel.lost}</p>
          <Button type="button" variant="outline" size="page" data-focus="keep" onClick={keep}>
            {cancel.keep}
          </Button>
          <Button type="button" variant="outline" size="page" onClick={() => void confirm()} className="border-bad-line bg-bad-tint text-bad hover:bg-bad-tint">
            <X aria-hidden="true" />
            {cancel.confirm}
          </Button>
        </>
      ) : (
        <>
          {note && !cancelling ? (
            <p className="mr-auto inline-flex items-center gap-2 text-[13px] text-muted">
              <DoorOpen aria-hidden="true" className="size-4 flex-none" />
              {note}
            </p>
          ) : null}
          <Button
            type="button"
            variant="tinted"
            size="page"
            data-focus="cancel"
            aria-disabled={cancelling ? true : undefined}
            onClick={() => {
              if (phase !== "idle") return
              focusNext.current = "keep"
              setPhase("confirm")
            }}
          >
            {cancelling ? <Hourglass aria-hidden="true" /> : <X aria-hidden="true" />}
            <span className="grid">
              <span className="col-start-1 row-start-1">{cancelling ? "Cancelling" : cancel.label}</span>
              <span aria-hidden="true" className="invisible col-start-1 row-start-1">
                {cancelling ? cancel.label : "Cancelling"}
              </span>
            </span>
          </Button>
        </>
      )}
    </div>
  )
}
