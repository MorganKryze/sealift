// Lists what one import published, for a rollback in Nexus.
// Run: node published.mjs <import.json>
// The file is the import's record under /data. The script only reads it.
import { readFileSync } from "node:fs"

const file = process.argv[2]
if (!file) {
  console.error("usage: node published.mjs <import.json>")
  process.exit(2)
}

const record = JSON.parse(readFileSync(file, "utf8"))
if (record?.formatVersion !== 1 || !Array.isArray(record.attempts)) {
  console.error(`${file} is not an import record`)
  process.exit(1)
}
// These failures happen before the upload. Any other failure may have reached
// Nexus: a read-back can fail on the import's own side (local), records from
// v0.4.0 carry no kind, and a pending package was never swept. The repository
// check runs before the upload too, whatever kind it files its failure under.
const neverUploaded = new Set(["conflict", "mismatch", "source"])
const beforeUpload = (pkg) =>
  pkg.state === "failed" && (neverUploaded.has(pkg.kind) || String(pkg.reason ?? "").startsWith("repository check failed:"))

const published = new Set()
const tried = new Map()
for (const attempt of record.attempts) {
  for (const pkg of attempt.report?.packages ?? []) {
    const id = `${pkg.name}@${pkg.version}`
    if (pkg.state === "published") {
      published.add(id)
      continue
    }
    const seen = tried.get(id) ?? { lines: [], failed: false, uploaded: false }
    const reason = pkg.reason ? JSON.stringify(pkg.reason) : "-"
    seen.lines.push(
      `  attempt ${attempt.n}: state=${pkg.state} kind=${pkg.kind || "-"} reason=${reason} started=${attempt.startedAt ?? "-"} ended=${attempt.endedAt ?? "-"}`,
    )
    if (pkg.state === "pending" || pkg.state === "failed") {
      seen.failed = true
      seen.uploaded ||= !beforeUpload(pkg)
    }
    tried.set(id, seen)
  }
}

const section = (title, uploaded) => [
  title,
  ...[...tried]
    .filter(([id, seen]) => !published.has(id) && seen.failed && seen.uploaded === uploaded)
    .flatMap(([id, seen]) => [id, ...seen.lines]),
]
const lines = [
  "Published by this import:",
  ...published,
  "",
  ...section("Possibly published, check each in Nexus first:", true),
  "",
  ...section("Never uploaded, nothing to remove:", false),
]
process.stdout.write(lines.join("\n") + "\n")
