import { createFileRoute } from "@tanstack/react-router"

import { ArchivesList } from "@/components/import/archives-list"

export const Route = createFileRoute("/")({
  component: () => (
    <>
      <h1 className="text-2xl font-bold tracking-tight">Archives</h1>
      <p className="mt-1.5 text-muted">The archives in your MinIO folder, newest first. Start an import from one that can be imported.</p>
      <ArchivesList />
    </>
  ),
})
