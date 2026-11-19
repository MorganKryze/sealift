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
// v0.4.0 carry no kind, and a pending package was never swept.
const neverUploaded = new Set(["conflict", "mismatch", "source"])

const published = new Map()
const possible = new Map()
for (const attempt of record.attempts) {
  for (const pkg of attempt.report?.packages ?? []) {
    const id = `${pkg.name}@${pkg.version}`
    if (pkg.state === "published") {
      published.set(id, true)
    } else if (pkg.state === "pending" || (pkg.state === "failed" && !neverUploaded.has(pkg.kind))) {
      possible.set(id, true)
    }
  }
}
for (const id of published.keys()) possible.delete(id)

const lines = ["Published by this import:", ...published.keys(), "", "Possibly published, check each in Nexus first:", ...possible.keys()]
process.stdout.write(lines.join("\n") + "\n")
