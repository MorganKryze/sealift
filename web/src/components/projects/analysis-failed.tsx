import { useMutation, useQueryClient } from "@tanstack/react-query"

import { queueAnalysis, type Analysis } from "@/api/projects"
import { Button } from "@/components/ui/button"

interface AnalysisFailedProps {
  projectId: string
  analysis: Analysis
}

const REASON: Record<string, string> = {
  failed: "The analysis failed.",
  cancelled: "The analysis was cancelled.",
  interrupted: "The analysis was interrupted, most likely by a server restart.",
}

// The schema carries no per-step failure detail for a terminal analysis
// fetched fresh (only the running job's events replay, and the stream ends
// with that job); warnings is the only place a reason beyond the state can
// come from.
export function AnalysisFailed({ projectId, analysis }: AnalysisFailedProps) {
  const queryClient = useQueryClient()
  const rerunMutation = useMutation({
    mutationFn: () => queueAnalysis(projectId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["project", projectId] })
    },
  })

  const warnings = analysis.result?.warnings ?? []

  return (
    <div className="flex flex-col gap-4 p-8">
      <p className="text-ink">{REASON[analysis.state] ?? `Analysis ${analysis.state}.`}</p>
      {warnings.length > 0 ? (
        <ul className="list-disc pl-5 text-sm text-muted">
          {warnings.map((warning, index) => (
            <li key={index}>{warning}</li>
          ))}
        </ul>
      ) : null}
      <Button onClick={() => rerunMutation.mutate()} disabled={rerunMutation.isPending} className="self-start">
        Rerun analysis
      </Button>
    </div>
  )
}
