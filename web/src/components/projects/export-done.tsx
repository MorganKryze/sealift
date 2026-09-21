import { useQuery } from "@tanstack/react-query"

import { apiFetch } from "@/api/client"
import { Mark } from "@/components/brand/Mark"
import { formatBytes } from "@/lib/utils"

// manifest.json's shape is not part of the OpenAPI schema (the download
// route types every file as an opaque octet-stream); this mirrors
// internal/report.Manifest, the job's own writer.
interface ExportManifest {
  archive: {
    sha256: string
    size: number
  }
  packages: unknown[]
}

interface ExportDoneProps {
  projectId: string
  exportId: string
  files: string[]
}

export function ExportDone({ projectId, exportId, files }: ExportDoneProps) {
  const manifestQuery = useQuery({
    queryKey: ["export-manifest", projectId, exportId],
    queryFn: () => apiFetch<ExportManifest>(`/projects/${projectId}/exports/${exportId}/files/manifest.json`),
  })

  return (
    <div className="flex flex-col gap-6 p-8">
      <div className="flex items-center gap-4 rounded-md border border-line p-4">
        <Mark size={40} />
        <div>
          <h2 className="text-lg font-semibold text-ink">Archive sealed</h2>
          {manifestQuery.isPending ? (
            <p className="text-sm text-muted">Reading the manifest…</p>
          ) : manifestQuery.isError ? (
            <p className="text-sm text-severity-critical">Could not read manifest.json.</p>
          ) : (
            <p className="text-sm text-muted">
              sha256 <span className="font-mono">{manifestQuery.data.archive.sha256}</span> ·{" "}
              {formatBytes(manifestQuery.data.archive.size)} · {manifestQuery.data.packages.length} packages
            </p>
          )}
        </div>
      </div>

      <ul className="flex flex-col gap-2">
        {files.map((name) => (
          <li key={name} className="flex items-center justify-between rounded-md border border-line p-3 text-sm">
            <span className="text-ink">{name}</span>
            <a
              href={`/api/projects/${projectId}/exports/${exportId}/files/${encodeURIComponent(name)}`}
              className="font-medium text-accent underline"
              download
            >
              Download
            </a>
          </li>
        ))}
      </ul>
    </div>
  )
}
