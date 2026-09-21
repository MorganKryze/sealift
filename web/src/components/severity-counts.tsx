import { cn } from "@/lib/utils"

// Vector: "CVE counts by severity, critical to unknown" (schema.d.ts).
const SEVERITIES = [
  { key: "critical", dot: "bg-severity-critical" },
  { key: "high", dot: "bg-severity-high" },
  { key: "medium", dot: "bg-severity-medium" },
  { key: "low", dot: "bg-severity-low" },
  { key: "unknown", dot: "bg-severity-unknown" },
] as const

interface SeverityCountsProps {
  vector: number[]
  className?: string
}

export function SeverityCounts({ vector, className }: SeverityCountsProps) {
  const entries = SEVERITIES.map((severity, index) => ({ ...severity, count: vector[index] ?? 0 })).filter(
    (entry) => entry.count > 0,
  )

  if (entries.length === 0) {
    return <span className={cn("text-sm text-severity-resolved", className)}>No known CVEs</span>
  }

  return (
    <span className={cn("inline-flex flex-wrap items-center gap-x-3 gap-y-1", className)}>
      {entries.map((entry) => (
        <span key={entry.key} className="inline-flex items-center gap-1.5 text-sm text-ink">
          <span aria-hidden className={cn("size-2 rounded-full", entry.dot)} />
          {entry.count} {entry.key}
        </span>
      ))}
    </span>
  )
}
