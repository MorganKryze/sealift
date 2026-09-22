import { useQuery } from "@tanstack/react-query"

import { getProjectManifest, type Analysis, type Project } from "@/api/projects"
import { StepBar, type StepBarStep } from "@/components/step-bar"
import { Card, CardContent } from "@/components/ui/card"
import { parseManifestPreview } from "@/lib/manifestPreview"

interface DropSummaryProps {
  project: Project
  analysis?: Analysis
  steps: StepBarStep[]
}

/**
 * The Drop step's read-only view once a session already exists: the
 * package.json as uploaded, read back from the server, so a session whose
 * analysis failed still shows what it was given.
 */
export function DropSummary({ project, analysis, steps }: DropSummaryProps) {
  const manifestQuery = useQuery({ queryKey: ["manifest", project.id], queryFn: () => getProjectManifest(project.id) })
  const uploaded = (() => {
    try {
      return manifestQuery.data ? parseManifestPreview(manifestQuery.data, project.name).dependencies : undefined
    } catch {
      return undefined
    }
  })()
  const dependencies = (uploaded ?? analysis?.result?.dependencies.map((d) => ({ name: d.name, version: d.current })) ?? []).map(
    (d) => ({ name: d.name, version: d.version }),
  )
  const shown = dependencies.slice(0, 18)
  const extra = dependencies.length - shown.length

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <StepBar steps={steps} />
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">{project.name}</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          {manifestQuery.isPending
            ? "Reading the uploaded package.json…"
            : dependencies.length > 0
              ? "The package.json this session was started from."
              : "sealift could not read back the package.json of this session."}
        </p>
      </div>
      <Card>
        <CardContent className="grid grid-cols-[auto_1fr] gap-4">
          <div className="grid h-13 w-11 place-items-center rounded-lg border border-line bg-card font-mono text-[11px] text-muted">
            JSON
          </div>
          <div>
            <dl className="grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-x-6 gap-y-2.5">
              <div>
                <dt className="text-xs text-muted">Dependencies</dt>
                <dd className="font-semibold text-ink tabular-nums">{dependencies.length > 0 ? dependencies.length : "Unknown"}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Target</dt>
                <dd className="font-semibold text-ink">
                  {project.target.os}/{project.target.cpu} · {project.target.libc} · Node {project.target.node}
                </dd>
              </div>
            </dl>
            {dependencies.length > 0 ? (
              <div className="mt-3.5 flex flex-wrap gap-1.5">
                {shown.map((dependency) => (
                  <span key={dependency.name} className="rounded-md border border-line bg-card px-2 py-0.5 font-mono text-xs">
                    {dependency.name}@{dependency.version}
                  </span>
                ))}
                {extra > 0 ? (
                  <span className="rounded-md border border-line bg-card px-2 py-0.5 font-mono text-xs text-muted">
                    +{extra} more
                  </span>
                ) : null}
              </div>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
