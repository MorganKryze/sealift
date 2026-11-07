import { cn } from "@/lib/utils"
import { outcomeWords } from "@/import/lib/outcome"

const iconTone = {
  waiting: "text-muted",
  progress: "text-accent motion-safe:animate-spin",
  done: "text-severity-resolved-fg",
  failure: "text-severity-high",
}

/** An outcome in words with an icon, so its meaning never rests on colour. */
export function OutcomeBadge({ outcome }: { outcome: string }) {
  const { label, icon: Icon, tone } = outcomeWords(outcome)
  return (
    <span className={cn("inline-flex h-6 items-center gap-1.5 rounded-full border border-line bg-card px-2.5 text-xs font-medium text-ink", tone === "progress" && "border-accent")}>
      <Icon aria-hidden className={cn("size-3.5 shrink-0", iconTone[tone])} />
      {label}
    </span>
  )
}
