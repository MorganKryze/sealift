import { Check, X } from "lucide-react"

import { cn } from "@/lib/utils"

export type StepId = "drop" | "analysis" | "review" | "export"

/**
 * What a step's work has come to. "available" is reachable but not done
 * yet (Review before any export); which step is on screen is a separate
 * flag, so a failed analysis still reads as failed while it is shown.
 */
export type StepStatus = "upcoming" | "available" | "running" | "done" | "failed"

export interface StepBarStep {
  id: StepId
  label: string
  sub: string
  status: StepStatus
  /** The step on screen. */
  current: boolean
  /** Present only when the step can be navigated to. */
  onNavigate?: () => void
}

interface StepBarProps {
  steps: StepBarStep[]
}

const STEP_LABELS: Record<StepId, { label: string; sub: string }> = {
  drop: { label: "Drop", sub: "package.json" },
  analysis: { label: "Analyse", sub: "scan and rank" },
  review: { label: "Review", sub: "proposal" },
  export: { label: "Export", sub: "archive" },
}

/** Fills in label/sub from the step id, so callers only pass status and onNavigate. */
export function stepBarStep(id: StepId, status: StepStatus, current: boolean, onNavigate?: () => void): StepBarStep {
  return { id, ...STEP_LABELS[id], status, current, onNavigate }
}

/**
 * The session's step indicator: numbered circles with one word each, the line after a step filling once it is done.
 * Presentational only: callers compute status and navigation from the project and analysis state, since what counts
 * as reachable differs before a session exists (the drop screen) and after.
 */
export function StepBar({ steps }: StepBarProps) {
  return (
    <nav aria-label="Session steps" className="mb-7">
      <div className="flex items-center gap-2">
        {steps.map((step, index) => {
          const circle = (
            <span
              className={cn(
                "grid size-6 flex-none place-items-center rounded-full border text-xs font-semibold transition-colors duration-200",
                step.status === "done" && "border-ok-line bg-ok-tint text-ok",
                step.status === "failed" && "border-bad-line bg-bad-tint text-bad",
                step.status === "running" && "border-info bg-info-tint text-info",
                step.status === "available" && "border-field text-ink",
                step.status === "upcoming" && "border-rule-2 text-muted",
                step.current && step.status !== "failed" && step.status !== "done" && "border-ink bg-ink text-bg",
              )}
            >
              {step.status === "done" ? (
                <Check aria-hidden="true" className="size-3.5" strokeWidth={3} />
              ) : step.status === "failed" ? (
                <X aria-hidden="true" className="size-3.5" strokeWidth={3} />
              ) : (
                index + 1
              )}
            </span>
          )
          const content = (
            <>
              {circle}
              <span className={cn(step.current ? "font-semibold text-ink" : step.status === "upcoming" ? "text-muted" : "text-ink")}>{step.label}</span>
              {step.status === "failed" ? <span className="sr-only">, failed</span> : null}
              {step.status === "running" ? <span className="sr-only">, running</span> : null}
            </>
          )
          const className = "inline-flex min-h-8 flex-none items-center gap-2 rounded-lg px-1 text-sm"
          const last = index === steps.length - 1
          return (
            <div key={step.id} data-step className={cn("flex items-center gap-2", !last && "flex-1")}>
              {step.onNavigate ? (
                <button
                  type="button"
                  onClick={step.onNavigate}
                  aria-current={step.current ? "step" : undefined}
                  className={cn(className, "[@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover")}
                >
                  {content}
                </button>
              ) : (
                <span aria-disabled={step.current ? undefined : "true"} aria-current={step.current ? "step" : undefined} className={className}>
                  {content}
                </span>
              )}
              {last ? null : (
                <span aria-hidden="true" className="relative h-0.5 min-w-4 flex-1 overflow-hidden rounded-full bg-rule-2">
                  <span
                    data-step-fill
                    className="absolute inset-0 origin-left bg-ok transition-transform duration-[240ms] ease-out motion-reduce:transition-none"
                    style={{ transform: `scaleX(${step.status === "done" ? 1 : 0})` }}
                  />
                </span>
              )}
            </div>
          )
        })}
      </div>
    </nav>
  )
}
