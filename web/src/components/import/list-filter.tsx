import { cn } from "@/lib/utils"

type Filter = "all" | "importable"

interface ListFilterProps {
  value: Filter
  onChange: (v: Filter) => void
  counts: { all: number; importable: number }
}

const choice = "inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-accent"

/** Two choices as a segmented control. */
export function ListFilter({ value, onChange, counts }: ListFilterProps) {
  const options: { id: Filter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "importable", label: "Importable" },
  ]
  return (
    <div role="group" aria-label="Show archives" className="inline-flex gap-0.5 rounded-lg border border-line bg-card p-0.5">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          aria-pressed={value === o.id}
          onClick={() => onChange(o.id)}
          className={cn(choice, value === o.id ? "bg-background font-medium text-ink shadow-sm" : "text-muted hover:text-ink")}
        >
          {o.label}{" "}
          <span className="font-mono text-xs">{counts[o.id]}</span>
        </button>
      ))}
    </div>
  )
}
