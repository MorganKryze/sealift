import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { CircleX, FlaskConical, LoaderCircle } from "lucide-react"

import { queueAnalysis } from "@/api/projects"
import { Button } from "@/components/ui/button"

/** Analyse for a project left with no analysis, such as one whose queued analysis was cancelled: it analyses the files the project holds, then opens the crossing. */
export function StartAnalysis({ projectId }: { projectId: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const start = useMutation({
    mutationFn: () => queueAnalysis(projectId),
    onSuccess: (analysis) => {
      void queryClient.invalidateQueries({ queryKey: ["project", projectId] })
      void navigate({ to: "/crossings/$projectId", params: { projectId }, search: { analysis: analysis.id } })
    },
  })
  return (
    <div className="mt-5 grid justify-items-end gap-3">
      <Button
        type="button"
        size="page"
        aria-busy={start.isPending ? true : undefined}
        onClick={() => {
          if (!start.isPending) start.mutate()
        }}
      >
        {start.isPending ? <LoaderCircle aria-hidden="true" className="motion-safe:animate-spin" /> : <FlaskConical aria-hidden="true" />}
        {start.isPending ? "Starting" : "Analyse"}
      </Button>
      {start.isError ? (
        <p role="alert" className="tinted-bad inline-flex items-center gap-2 justify-self-stretch px-4 py-3 text-ink">
          <CircleX aria-hidden="true" className="size-5 flex-none text-bad" />
          Analysis did not start. Try again in a moment.
        </p>
      ) : null}
    </div>
  )
}
