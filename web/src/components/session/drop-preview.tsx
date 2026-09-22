import type { ProjectUploadError, Target } from "@/api/projects"
import { ProblemNotice } from "@/components/problem-notice"
import { stepBarStep, StepBar, type StepBarStep } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import type { ManifestPreview } from "@/lib/manifestPreview"
import { cn } from "@/lib/utils"

interface DropPreviewProps {
  manifest: ManifestPreview
  target?: Target
  onAnalyse: () => void
  onChangeFile: () => void
  analysing: boolean
  error: ProjectUploadError | null
}

const STEPS: StepBarStep[] = [
  stepBarStep("drop", "available", true),
  stepBarStep("analysis", "upcoming", false),
  stepBarStep("review", "upcoming", false),
  stepBarStep("export", "upcoming", false),
]

/**
 * The parsed manifest, shown before it is uploaded. Analysing calls
 * POST /projects, which the server queues an analysis for immediately, so
 * there is no separate "create" step once this button is pressed.
 */
export function DropPreview({ manifest, target, onAnalyse, onChangeFile, analysing, error }: DropPreviewProps) {
  const prod = manifest.dependencies.filter((dep) => dep.kind === "prod")
  const dev = manifest.dependencies.filter((dep) => dep.kind === "dev")
  const shown = manifest.dependencies.slice(0, 18)
  const extra = manifest.dependencies.length - shown.length

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <StepBar steps={STEPS} />
      <Card>
        <CardContent className="grid grid-cols-[auto_1fr] gap-4">
          <div className="grid h-13 w-11 place-items-center rounded-lg border border-line bg-card font-mono text-[11px] text-muted">
            JSON
          </div>
          <div>
            <h2 className="text-lg font-semibold text-ink">
              {manifest.name} <span className="font-mono text-sm font-normal text-muted">package.json</span>
            </h2>
            <dl className="mt-3.5 grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-x-6 gap-y-2.5">
              <div>
                <dt className="text-xs text-muted">Dependencies</dt>
                <dd className="font-semibold text-ink tabular-nums">
                  {prod.length} prod · {dev.length} dev
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Pinning</dt>
                <dd className={cn("font-semibold", manifest.allPinned ? "text-severity-resolved-fg" : "text-severity-high")}>
                  {manifest.allPinned ? "All exact" : "Some not pinned"}
                </dd>
              </div>
              {target ? (
                <div>
                  <dt className="text-xs text-muted">Target</dt>
                  <dd className="font-semibold text-ink">
                    {target.os}/{target.cpu} · {target.libc} · Node {target.node}
                  </dd>
                </div>
              ) : null}
            </dl>
            <div className="mt-3.5 flex flex-wrap gap-1.5">
              {shown.map((dep) => (
                <span
                  key={dep.name}
                  className={cn("rounded-md border border-line bg-card px-2 py-0.5 font-mono text-xs", dep.kind === "dev" && "text-muted")}
                >
                  {dep.name}@{dep.version}
                </span>
              ))}
              {extra > 0 ? (
                <span className="rounded-md border border-line bg-card px-2 py-0.5 font-mono text-xs text-muted">+{extra} more</span>
              ) : null}
            </div>
          </div>
        </CardContent>
      </Card>

      {error ? <ProblemNotice status={error.status} problem={error.problem} className="mt-5" /> : null}

      <div className="mt-5 flex flex-wrap gap-3">
        <Button size="lg" disabled={analysing} onClick={onAnalyse}>
          {analysing ? "Starting…" : `Analyse ${manifest.dependencies.length} dependencies`}
        </Button>
        <Button variant="ghost" onClick={onChangeFile} disabled={analysing}>
          Choose another file
        </Button>
      </div>
    </div>
  )
}
