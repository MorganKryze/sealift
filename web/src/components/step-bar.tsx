import { Check, X } from "lucide-react"

import { cn } from "@/lib/utils"

export type StepId = "drop" | "analysis" | "review" | "export"

export type StepStatus = "upcoming" | "current" | "done" | "failed"

export interface StepBarStep {
  id: StepId
  label: string
  sub: string
  status: StepStatus
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
export function stepBarStep(id: StepId, status: StepStatus, onNavigate?: () => void): StepBarStep {
  return { id, ...STEP_LABELS[id], status, onNavigate }
}

/**
 * The session's step bar. Presentational only: callers compute status and
 * navigation from the project and analysis state, since what counts as
 * "reachable" differs before a session exists (the drop screen) and after.
 */
export function StepBar({ steps }: StepBarProps) {
  return (
    <nav aria-label="Session steps" className="mb-7 flex flex-wrap gap-2">
      {steps.map((step, index) => {
        const dot =
          step.status === "failed" ? (
            <X className="size-3.5" strokeWidth={3} />
          ) : step.status === "done" ? (
            <Check className="size-3.5" strokeWidth={3} />
          ) : (
            index + 1
          )

        const content = (
          <>
            <span
              className={cn(
                "grid size-6 flex-none place-items-center rounded-full border text-xs font-semibold",
                step.status === "done" && "border-accent bg-accent text-background",
                step.status === "current" && "border-accent text-accent",
                step.status === "failed" && "border-severity-critical bg-severity-critical text-white",
                step.status === "upcoming" && "border-line text-muted",
              )}
            >
              {dot}
            </span>
            <span>
              {step.label}
              <span className="block text-xs font-normal text-muted">{step.sub}</span>
            </span>
          </>
        )

        const className = cn(
          "flex flex-1 basis-[120px] items-center gap-2.5 rounded-lg border px-3 py-2.5 text-left text-sm transition-colors",
          step.status === "current" && "border-accent bg-card font-semibold text-ink",
          step.status === "done" && "border-line text-ink hover:border-accent",
          step.status === "failed" && "border-severity-critical/40 text-ink",
          step.status === "upcoming" && "cursor-not-allowed border-line text-muted opacity-70",
        )

        if (step.onNavigate) {
          return (
            <button
              key={step.id}
              type="button"
              onClick={step.onNavigate}
              aria-current={step.status === "current" ? "step" : undefined}
              className={className}
            >
              {content}
            </button>
          )
        }

        return (
          <span key={step.id} aria-disabled="true" aria-current={step.status === "current" ? "step" : undefined} className={className}>
            {content}
          </span>
        )
      })}
    </nav>
  )
}
