export interface ManifestDependency {
  name: string
  version: string
  kind: "prod" | "dev"
}

export type CheckId = "exact" | "registry" | "fields"

/** One check the server makes on upload, with its evidence and, when it fails, what to do and each entry it caught. */
export interface ManifestCheck {
  id: CheckId
  label: string
  passed: boolean
  evidence: string
  fix: string
  offenders: { name: string; value: string }[]
}

export interface ManifestPreview {
  name: string
  dependencies: ManifestDependency[]
  checks: ManifestCheck[]
}

// The same rules npm.Manifest.Validate applies on upload, so Check can name every problem before
// anything runs. The server stays the authority: it validates again.
const EXACT_VERSION =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/
const SOURCE_PREFIXES = ["npm:", "git+", "git:", "github:", "file:", "link:", "workspace:", "http:", "https:"]
const PACKAGE_NAME = /^(@[A-Za-z0-9_~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9_~-][A-Za-z0-9._~-]*$/
const MAX_NAME_LENGTH = 214
const DEPENDENCY_FIELDS = [
  ["dependencies", "prod"],
  ["devDependencies", "dev"],
  ["optionalDependencies", "dev"],
] as const

/** Thrown when the dropped file cannot be a package.json to update; `kind` says why. */
export class ManifestPreviewError extends Error {
  constructor(public readonly kind: "not-json" | "not-object" | "no-dependency") {
    super(kind === "not-json" ? "The file is not valid JSON." : kind === "not-object" ? "The file holds JSON, but not an object like a package.json." : "The file lists no dependency.")
    this.name = "ManifestPreviewError"
  }
}

const figure = (n: number) => n.toLocaleString("en-US")

/**
 * Reads a package.json in the browser: its name, its direct dependencies and the three checks the server
 * makes on upload. A file that is not a JSON object, or that lists no dependency, is refused outright.
 */
export function parseManifestPreview(text: string, fallbackName: string): ManifestPreview {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    throw new ManifestPreviewError("not-json")
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new ManifestPreviewError("not-object")
  }
  const record = data as Record<string, unknown>
  const dependencies = DEPENDENCY_FIELDS.flatMap(([field, kind]) => toDependencyList(record[field], kind))
  if (dependencies.length === 0) {
    throw new ManifestPreviewError("no-dependency")
  }
  const name = typeof record.name === "string" && record.name.trim() ? record.name.trim() : fallbackName
  const total = figure(dependencies.length)

  // A name the registry cannot hold is off npm too; the server refuses it on its own line.
  const offNpm = dependencies.filter(
    (dep) => dep.name.length > MAX_NAME_LENGTH || !PACKAGE_NAME.test(dep.name) || SOURCE_PREFIXES.some((prefix) => dep.version.startsWith(prefix)),
  )
  const ranges = dependencies.filter((dep) => !offNpm.includes(dep) && !EXACT_VERSION.test(dep.version))
  const example = ranges.map((dep) => /\d+\.\d+\.\d+/.exec(dep.version)?.[0]).find(Boolean) ?? "1.2.3"

  // The server refuses each of these fields when present, even empty or null.
  const pnpm = typeof record.pnpm === "object" && record.pnpm !== null ? (record.pnpm as Record<string, unknown>) : {}
  const unsupported = (
    [
      ["overrides", record.overrides],
      ["pnpm.overrides", pnpm.overrides],
      ["pnpm.patchedDependencies", pnpm.patchedDependencies],
      ["resolutions", record.resolutions],
    ] as const
  ).filter(([, value]) => value !== undefined)
  const listed = DEPENDENCY_FIELDS.map(([field]) => field).filter((field) => toDependencyList(record[field], "prod").length > 0)

  const checks: ManifestCheck[] = [
    {
      id: "exact",
      label: "Exact versions",
      passed: ranges.length === 0,
      evidence: ranges.length === 0 ? `${total} of ${total} pinned` : `${figure(ranges.length)} of ${total} ${ranges.length === 1 ? "is a range" : "are ranges"}`,
      fix: `Write the version you run, such as ${example}.`,
      offenders: ranges.map(({ name, version }) => ({ name, value: version })),
    },
    {
      id: "registry",
      label: "Registry only",
      passed: offNpm.length === 0,
      evidence: offNpm.length === 0 ? `${total} of ${total} on npm` : `${figure(offNpm.length)} of ${total} off npm`,
      fix: "This instance fetches from npm only; use a published version for each.",
      offenders: offNpm.map(({ name, version }) => ({ name, value: version })),
    },
    {
      id: "fields",
      label: "Supported fields",
      passed: unsupported.length === 0,
      evidence: unsupported.length === 0 ? listed.join(" · ") : `${figure(unsupported.length)} ${unsupported.length === 1 ? "field" : "fields"} not supported`,
      fix: `This instance resolves without overrides; remove ${unsupported.length === 1 ? "the field" : "these fields"}.`,
      offenders: unsupported.map(([field, value]) => ({ name: field, value: fieldValue(value) })),
    },
  ]

  return { name, dependencies, checks }
}

/** The checks that fail, in the order the block shows them. */
export function failingChecks(preview: ManifestPreview): ManifestCheck[] {
  return preview.checks.filter((check) => !check.passed)
}

// An unsupported field read back by its keys (the packages it overrides), else as written.
function fieldValue(value: unknown): string {
  const keys = typeof value === "object" && value !== null && !Array.isArray(value) ? Object.keys(value) : []
  return keys.length > 0 ? keys.join(", ") : JSON.stringify(value)
}

function toDependencyList(value: unknown, kind: "prod" | "dev"): ManifestDependency[] {
  if (typeof value !== "object" || value === null) {
    return []
  }
  return Object.entries(value as Record<string, unknown>)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string")
    .map(([name, version]) => ({ name, version, kind }))
}
