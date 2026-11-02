// Writes a finished session into a data directory, so the browser gate can load the session routes
// without pnpm, Trivy or a registry. The shapes follow what internal/store reads back.
import { createHash } from "node:crypto"
import { mkdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"

const root = process.argv[2]
if (!root) throw new Error("usage: node seed.mjs <data-dir>")

const project = "demo"
const analysis = "20260921T101500Z"
const exported = "20260921T102000Z"
const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" }
const manifest = JSON.stringify({ name: "demo", dependencies: { express: "5.0.1", lodash: "4.17.20" } }, null, 2)

const write = (path, content) => {
  const file = join(root, "projects", project, path)
  mkdirSync(join(file, ".."), { recursive: true })
  writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content))
}
const candidate = (version, vector, signals = [], key = false) => ({
  version, vector, signals, key, resolved: true, published: "2026-06-01T12:00:00Z",
})

write("package.json", manifest)
write("project.json", {
  id: project, name: "demo", target, createdAt: "2026-09-21T10:14:00Z",
  manifestSha256: createHash("sha256").update(manifest).digest("hex"),
})
write(`analyses/${analysis}/status.json`, {
  state: "done", pnpmVersion: "12.3.4", trivyVersion: "0.74.0", trivyDbDate: "2026-09-21T06:12:00Z",
})
write(`analyses/${analysis}/ranking.json`, {
  before: [1, 4, 3, 1, 0],
  after: [0, 0, 1, 1, 0],
  warnings: [],
  target,
  dependencies: [
    {
      name: "express", current: "5.0.1", best: "5.2.1", vector: [1, 1, 0, 0, 0],
      candidates: [
        candidate("5.1.0", [0, 1, 0, 0, 0], [], true),
        candidate("5.2.0", [0, 0, 0, 0, 0], [{ name: "too-recent", evidence: "published 3 days ago; the minimum is 14 days", blocking: true }]),
        candidate("5.2.1", [0, 0, 0, 0, 0], [{ name: "publisher-changed", evidence: "published by a new maintainer", blocking: false }]),
      ],
    },
    {
      name: "lodash", current: "4.17.20", best: "4.17.21", vector: [0, 1, 1, 1, 0],
      candidates: [candidate("4.17.21", [0, 0, 1, 1, 0], [], true)],
    },
  ],
})
write(`exports/${exported}/manifest.json`, {
  analysisId: analysis, createdAt: "2026-09-21T10:20:00Z", archive: { sha256: "0".repeat(64), size: 5500000 }, packages: [],
})
write(`exports/${exported}/packages_npm.tar.gz`, "")
