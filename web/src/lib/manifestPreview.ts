export interface ManifestDependency {
  name: string
  version: string
  kind: "prod" | "dev"
}

export interface ManifestPreview {
  name: string
  dependencies: ManifestDependency[]
  allPinned: boolean
}

// A loose "exact version" check for the local preview only; the server is
// the authority on whether a manifest's pins are valid.
const EXACT_VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/

/** Thrown when the dropped file's content is not readable as a manifest preview. */
export class ManifestPreviewError extends Error {}

/**
 * Parses just enough of a package.json to render the drop screen's file
 * card before it is uploaded: name, direct dependencies, whether every one
 * is pinned to an exact version. The server re-validates on upload; this is
 * a preview, not the check that gates the analysis.
 */
export function parseManifestPreview(text: string, fallbackName: string): ManifestPreview {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    throw new ManifestPreviewError("That file is not valid JSON.")
  }
  if (typeof data !== "object" || data === null) {
    throw new ManifestPreviewError("That file is not a package.json object.")
  }
  const record = data as Record<string, unknown>
  const dependencies = [...toDependencyList(record.dependencies, "prod"), ...toDependencyList(record.devDependencies, "dev")]
  const name = typeof record.name === "string" && record.name.trim() ? record.name.trim() : fallbackName

  return {
    name,
    dependencies,
    allPinned: dependencies.length > 0 && dependencies.every((dep) => EXACT_VERSION.test(dep.version)),
  }
}

function toDependencyList(value: unknown, kind: "prod" | "dev"): ManifestDependency[] {
  if (typeof value !== "object" || value === null) {
    return []
  }
  return Object.entries(value as Record<string, unknown>)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string")
    .map(([name, version]) => ({ name, version, kind }))
}
