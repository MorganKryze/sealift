import type { Analysis, Export } from "@/api/projects"

interface ProjectHistoryProps {
  analyses: Analysis[]
  exports: Export[]
}

interface HistoryRow {
  key: string
  kind: "Analysis" | "Export"
  createdAt: string
  state: Analysis["state"]
}

function formatDateTime(value: string) {
  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export function ProjectHistory({ analyses, exports }: ProjectHistoryProps) {
  const rows: HistoryRow[] = [
    ...analyses.map((a) => ({ key: `a-${a.id}`, kind: "Analysis" as const, createdAt: a.createdAt, state: a.state })),
    ...exports.map((e) => ({ key: `e-${e.id}`, kind: "Export" as const, createdAt: e.createdAt, state: e.state })),
  ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())

  if (rows.length === 0) {
    return <p className="p-8 text-muted">No history yet.</p>
  }

  return (
    <table className="w-full border-collapse text-left text-sm">
      <thead>
        <tr className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <th className="px-8 py-2 pr-4 font-medium">Kind</th>
          <th className="py-2 pr-4 font-medium">Date</th>
          <th className="py-2 pr-4 font-medium">State</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key} className="border-b border-line last:border-0">
            <td className="px-8 py-2 pr-4 text-ink">{row.kind}</td>
            <td className="py-2 pr-4 text-muted">{formatDateTime(row.createdAt)}</td>
            <td className="py-2 pr-4 text-ink">{row.state}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
