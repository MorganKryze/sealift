import { useQuery } from "@tanstack/react-query"

import { apiFetch } from "@/api/client"
import { Mark } from "@/components/brand/Mark"
import { formatBytes } from "@/lib/utils"

interface ExportManifestFile {
  name: string
  size: number
}

// manifest.json's shape is not part of the OpenAPI schema (the download
// route types every file as an opaque octet-stream); this is the job's
// writer contract as described in the brief, not something openapi-typescript
// can check.
interface ExportManifest {
  sha256: string
  packageCount: number
  files: ExportManifestFile[]
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

  const sizeByName = new Map((manifestQuery.data?.files ?? []).map((file) => [file.name, file.size]))

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
              sha256 <span className="font-mono">{manifestQuery.data.sha256}</span> ·{" "}
              {manifestQuery.data.packageCount} packages
            </p>
          )}
        </div>
      </div>

      <ul className="flex flex-col gap-2">
        {files.map((name) => {
          const size = sizeByName.get(name)
          return (
            <li key={name} className="flex items-center justify-between rounded-md border border-line p-3 text-sm">
              <span className="text-ink">{name}</span>
              <span className="flex items-center gap-3">
                {size !== undefined ? <span className="text-muted">{formatBytes(size)}</span> : null}
                <a
                  href={`/api/projects/${projectId}/exports/${exportId}/files/${name}`}
                  className="font-medium text-accent underline"
                  download
                >
                  Download
                </a>
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
