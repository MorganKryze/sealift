import type { ProjectSummary } from "@/api/projects"
import { cn } from "@/lib/utils"

interface ProjectsTableProps {
  projects: ProjectSummary[]
}

const STALE_DAYS = 7
// Vector: "CVE counts by severity, critical to unknown" (schema.d.ts).
const CRITICAL_INDEX = 0
const HIGH_INDEX = 1

function formatDate(value: string | undefined) {
  if (!value) {
    return "Never"
  }
  return new Date(value).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
}

function isStale(createdAt: string | undefined) {
  if (!createdAt) {
    return false
  }
  const ageMs = Date.now() - new Date(createdAt).getTime()
  return ageMs > STALE_DAYS * 24 * 60 * 60 * 1000
}

export function ProjectsTable({ projects }: ProjectsTableProps) {
  return (
    <table className="w-full border-collapse text-left text-sm">
      <thead>
        <tr className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <th className="py-2 pr-4 font-medium">Name</th>
          <th className="py-2 pr-4 font-medium">Last analysis</th>
          <th className="py-2 pr-4 font-medium">Critical</th>
          <th className="py-2 pr-4 font-medium">High</th>
          <th className="py-2 pr-4 font-medium">Last export</th>
        </tr>
      </thead>
      <tbody>
        {projects.map((project) => {
          const vector = project.lastAnalysis?.result?.before
          const stale = isStale(project.lastAnalysis?.createdAt)
          return (
            <tr key={project.id} className="border-b border-line last:border-0">
              <td className="py-2 pr-4 font-medium text-ink">{project.name}</td>
              <td className="py-2 pr-4 text-muted">
                {formatDate(project.lastAnalysis?.createdAt)}
                {stale ? (
                  <span className="ml-2 rounded-full bg-card px-2 py-0.5 text-xs text-muted">rerun</span>
                ) : null}
              </td>
              <td className="py-2 pr-4">
                <SeverityCount count={vector?.[CRITICAL_INDEX]} tone="critical" />
              </td>
              <td className="py-2 pr-4">
                <SeverityCount count={vector?.[HIGH_INDEX]} tone="high" />
              </td>
              <td className="py-2 pr-4 text-muted">{formatDate(project.lastExport?.createdAt)}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function SeverityCount({ count, tone }: { count: number | undefined; tone: "critical" | "high" }) {
  if (count === undefined) {
    return <span className="text-muted">Not measured</span>
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-ink">
      <span
        aria-hidden
        className={cn("size-2 rounded-full", tone === "critical" ? "bg-severity-critical" : "bg-severity-high")}
      />
      {count} {tone}
    </span>
  )
}
