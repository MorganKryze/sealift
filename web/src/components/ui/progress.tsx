import { cn } from "@/lib/utils"

interface ProgressProps {
  /** Percent complete, 0 to 100. */
  value: number
  className?: string
  label?: string
}

/**
 * A plain percentage bar, not Radix's Progress: the analysis and export
 * screens update `value` on every event tick, and this element must stay
 * the same node throughout a run rather than remount.
 */
function Progress({ value, className, label }: ProgressProps) {
  const clamped = Math.min(100, Math.max(0, value))
  return (
    <div
      role="progressbar"
      aria-valuenow={Math.round(clamped)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-card", className)}
    >
      <div
        className="h-full rounded-full bg-accent transition-[width] duration-300 ease-out"
        style={{ width: `${clamped}%` }}
      />
    </div>
  )
}

export { Progress }
