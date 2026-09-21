import type { ProjectUploadError } from "@/api/projects"

interface UploadErrorProps {
  error: ProjectUploadError
}

export function UploadError({ error }: UploadErrorProps) {
  const { problem, status } = error
  const details = problem?.errors

  return (
    <div
      role="alert"
      className="w-full max-w-md rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-4 text-left text-sm text-ink"
    >
      {status === 400 && details && details.length > 0 ? (
        <>
          <p className="mb-2 font-medium">package.json could not be read</p>
          <ul className="space-y-1.5">
            {details.map((entry, index) => (
              <li key={index}>
                <span className="font-mono text-xs text-muted">{entry.field}</span>
                {entry.name ? <span className="font-mono text-xs text-muted"> · {entry.name}</span> : null}
                {entry.value ? <span className="font-mono text-xs text-muted"> · {entry.value}</span> : null}
                <span>: {entry.reason}</span>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <>
          <p className="font-medium">{problem?.title ?? "Upload failed"}</p>
          {problem?.detail ? <p className="text-muted">{problem.detail}</p> : null}
        </>
      )}
    </div>
  )
}
