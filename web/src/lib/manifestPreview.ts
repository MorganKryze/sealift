export interface ManifestDependency {
  name: string
  version: string
  kind: "prod" | "dev"
}

/** One reason the server would refuse the manifest, in the server's own words. */
export interface ManifestProblem {
  where: string
  reason: string
}

export interface ManifestPreview {
  name: string
  dependencies: ManifestDependency[]
  problems: ManifestProblem[]
}

// The same rules npm.Manifest.Validate applies on upload, so the drop
// screen can list every problem before anything runs. The server stays the
// authority: it validates again.
const EXACT_VERSION =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/
const SOURCE_PREFIXES = ["npm:", "git+", "git:", "github:", "file:", "link:", "workspace:", "http:", "https:"]

/** Thrown when the dropped file's content is not readable as a manifest preview. */
export class ManifestPreviewError extends Error {}

/**
 * Parses a package.json for the drop screen: name, direct dependencies,
 * and every problem that would make the server refuse it.
 */
export function parseManifestPreview(text: string, fallbackName: string): ManifestPreview {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    throw new ManifestPreviewError("That file is not valid JSON.")
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new ManifestPreviewError("That file holds JSON, but not an object like a package.json.")
  }
  const record = data as Record<string, unknown>
  const dependencies = [
    ...toDependencyList(record.dependencies, "prod"),
    ...toDependencyList(record.devDependencies, "dev"),
    ...toDependencyList(record.optionalDependencies, "dev"),
  ]
  const name = typeof record.name === "string" && record.name.trim() ? record.name.trim() : fallbackName

  const problems: ManifestProblem[] = []
  const pnpm = typeof record.pnpm === "object" && record.pnpm !== null ? (record.pnpm as Record<string, unknown>) : {}
  const unsupported: [string, unknown][] = [
    ["overrides", record.overrides],
    ["pnpm.overrides", pnpm.overrides],
    ["pnpm.patchedDependencies", pnpm.patchedDependencies],
    ["resolutions", record.resolutions],
  ]
  for (const [field, value] of unsupported) {
    if (value !== undefined && value !== null) {
      problems.push({ where: field, reason: "not supported" })
    }
  }
  if (dependencies.length === 0) {
    problems.push({ where: "dependencies", reason: "lists no dependency to update" })
  }
  for (const dep of dependencies) {
    if (SOURCE_PREFIXES.some((prefix) => dep.version.startsWith(prefix))) {
      problems.push({ where: `${dep.name} ${dep.version}`, reason: "only npm registry versions are supported" })
    } else if (!EXACT_VERSION.test(dep.version)) {
      problems.push({ where: `${dep.name} ${dep.version}`, reason: "version must be exact, such as 1.2.3" })
    }
  }

  return { name, dependencies, problems }
}

function toDependencyList(value: unknown, kind: "prod" | "dev"): ManifestDependency[] {
  if (typeof value !== "object" || value === null) {
    return []
  }
  return Object.entries(value as Record<string, unknown>)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string")
    .map(([name, version]) => ({ name, version, kind }))
}
