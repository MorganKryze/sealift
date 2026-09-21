import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, useNavigate } from "@tanstack/react-router"
import { useState } from "react"

import { createProject, listProjects, ProjectUploadError } from "@/api/projects"
import { ProjectsView } from "@/components/projects/projects-view"
import { UploadError } from "@/components/projects/upload-error"

export const Route = createFileRoute("/projects/")({
  component: ProjectsScreen,
})

function ProjectsScreen() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [invalidFileMessage, setInvalidFileMessage] = useState<string | null>(null)

  const projectsQuery = useQuery({ queryKey: ["projects"], queryFn: listProjects })

  const uploadMutation = useMutation({
    mutationFn: createProject,
    onSuccess: (project) => {
      queryClient.setQueryData(["project", project.id], project)
      void queryClient.invalidateQueries({ queryKey: ["projects"] })
      void navigate({ to: "/projects/$projectId", params: { projectId: project.id } })
    },
  })

  function handleFile(file: File) {
    setInvalidFileMessage(null)
    uploadMutation.mutate(file)
  }

  function handleInvalidFile(message: string) {
    uploadMutation.reset()
    setInvalidFileMessage(message)
  }

  const uploadError = uploadMutation.error instanceof ProjectUploadError ? uploadMutation.error : null

  return (
    <ProjectsView
      status={projectsQuery.status}
      projects={projectsQuery.data}
      error={projectsQuery.error}
      onRetry={() => void projectsQuery.refetch()}
      onFile={handleFile}
      onInvalidFile={handleInvalidFile}
    >
      {invalidFileMessage ? (
        <p role="alert" className="text-sm text-severity-critical-fg">
          {invalidFileMessage}
        </p>
      ) : null}
      {uploadError ? <UploadError error={uploadError} /> : null}
    </ProjectsView>
  )
}
