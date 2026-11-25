import { createFileRoute } from "@tanstack/react-router"

import { ArchivesList } from "@/components/import/archives-list"

export const Route = createFileRoute("/import")({
  validateSearch: (search: Record<string, unknown>): { start?: string } => (typeof search.start === "string" ? { start: search.start } : {}),
  component: () => (
    <>
      <h1 className="text-2xl font-bold tracking-tight">Choose an archive</h1>
      <p className="mt-1.5 text-muted">The archives in your MinIO folder, newest first. Start an import from one that can be imported.</p>
      <ArchivesList />
    </>
  ),
})
