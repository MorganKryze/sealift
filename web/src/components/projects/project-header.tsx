import type { Analysis, Export, Project } from "@/api/projects"
import { cn } from "@/lib/utils"

const STEPS = ["Upload", "Analyze", "Choose", "Export"] as const

/**
 * The step is inferred from the last analysis and export state: nothing in
 * the schema names the current step directly.
 */
function currentStepIndex(lastAnalysis?: Analysis, lastExport?: Export): number {
  if (!lastAnalysis || lastAnalysis.state !== "done") {
    return 1
  }
  if (!lastExport) {
    return 2
  }
  return lastExport.state === "queued" || lastExport.state === "running" || lastExport.state === "done" ? 3 : 2
}

interface ProjectHeaderProps {
  project: Project
  lastAnalysis?: Analysis
  lastExport?: Export
}

export function ProjectHeader({ project, lastAnalysis, lastExport }: ProjectHeaderProps) {
  const step = currentStepIndex(lastAnalysis, lastExport)
  const { target } = project

  return (
    <header className="flex flex-col gap-4 border-b border-line p-8 pb-6">
      <div>
        <h1 className="text-xl font-semibold text-ink">{project.name}</h1>
        <p className="mt-1 text-sm text-muted">
          {target.os}/{target.cpu} · {target.libc} · Node {target.node} · pnpm {target.pnpmVer}
        </p>
      </div>
      <ol className="flex items-center gap-2 text-sm">
        {STEPS.map((label, index) => (
          <li key={label} className="flex items-center gap-2">
            {index > 0 ? (
              <span aria-hidden className="text-muted">
                →
              </span>
            ) : null}
            <span
              aria-current={index === step ? "step" : undefined}
              className={cn(
                "rounded-full px-3 py-1",
                index === step ? "bg-accent font-medium text-background" : index < step ? "text-ink" : "text-muted",
              )}
            >
              {label}
            </span>
          </li>
        ))}
      </ol>
    </header>
  )
}
