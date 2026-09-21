import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, useNavigate } from "@tanstack/react-router"
import { useState } from "react"

import { createProject, listProjects, ProjectUploadError } from "@/api/projects"
import { EmptyState } from "@/components/empty-state"
import { DropZone } from "@/components/projects/drop-zone"
import { ProjectsTable } from "@/components/projects/projects-table"
import { UploadError } from "@/components/projects/upload-error"

export const Route = createFileRoute("/projects")({
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

  const errorBlock = (
    <>
      {invalidFileMessage ? (
        <p role="alert" className="text-sm text-severity-critical">
          {invalidFileMessage}
        </p>
      ) : null}
      {uploadError ? <UploadError error={uploadError} /> : null}
    </>
  )

  const projects = projectsQuery.data ?? []

  if (projects.length === 0) {
    return (
      <EmptyState onFile={handleFile} onInvalidFile={handleInvalidFile}>
        {errorBlock}
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-1 flex-col gap-6 p-8">
      <h1 className="text-xl font-semibold text-ink">Projects</h1>
      {errorBlock}
      <ProjectsTable projects={projects} />
      <DropZone onFile={handleFile} onInvalidFile={handleInvalidFile} compact />
    </div>
  )
}
