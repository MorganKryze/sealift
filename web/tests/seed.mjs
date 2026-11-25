// Writes a finished session into a data directory, so the browser gate can load the session routes
// without pnpm, Trivy or a registry. The shapes follow what internal/store reads back. It also writes
// stand-ins for the tools the start prepares, laid out as internal/tools leaves them, so the instance
// is ready with no download.
import { createHash, generateKeyPairSync, sign } from "node:crypto"
import { chmodSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const root = process.argv[2]
if (!root) throw new Error("usage: node seed.mjs <data-dir>")

const project = "demo"
const analysis = "20260921T101500Z"
const exported = "20260921T102000Z"
const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" }
const manifest = JSON.stringify({ name: "demo", dependencies: { express: "5.0.1", lodash: "4.17.20" } }, null, 2)

const write = (path, content, into = project) => {
  const file = join(root, "projects", into, path)
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
  warnings: ["lodash: metadata unreachable: the registry answered 503"],
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
// A second session whose answer needs reasons: the react family and express can leave their major, and
// html-minifier keeps a CVE that no version fixes. candidates.json and ranking.json are the bytes the rank
// step wrote for this project (2-space indented, no final newline); ranking.json adds the combined check's after.
const reasons = { project: "reasons", analysis: "20261124T101500Z" }
const reasonsManifest = JSON.stringify(
  { name: "reasons", dependencies: { react: "18.2.0", "react-dom": "18.2.0", express: "4.17.1", "html-minifier": "4.0.0" }, devDependencies: { "@types/react": "18.3.12" } },
  null,
  2,
)
const published = "2025-03-31T14:00:00Z"
const zero = [0, 0, 0, 0, 0]
const stored = (version, signals = []) => ({ version, vector: zero, cves: [], signals, key: true, resolved: true, published })
const leaves = (major) => [{ name: "major-jump", evidence: `leaves major version ${major}`, blocking: false }]
const reasonsResult = (after) => ({
  target,
  before: [0, 1, 1, 0, 0],
  after,
  dependencies: [
    { name: "react", current: "18.2.0", vector: zero, cves: [], candidates: [stored("18.3.1"), stored("19.2.0", leaves(18))], jump: "19.2.0", family: "react 19" },
    { name: "react-dom", current: "18.2.0", vector: zero, cves: [], candidates: [stored("18.3.1"), stored("19.2.0", leaves(18))], jump: "19.2.0", family: "react 19" },
    { name: "@types/react", current: "18.3.12", vector: zero, cves: [], candidates: [stored("19.2.0", leaves(18))], jump: "19.2.0", family: "react 19" },
    {
      name: "express", current: "4.17.1", best: "4.21.2", vector: [0, 1, 0, 0, 0],
      cves: [{ id: "CVE-2024-29041", severity: "HIGH", package: "express@4.17.1", fixedIn: "4.19.2, 5.0.0" }],
      candidates: [stored("4.21.2"), stored("5.1.0", leaves(4))], jump: "5.1.0",
    },
    {
      name: "html-minifier", current: "4.0.0", vector: [0, 0, 1, 0, 0],
      cves: [{ id: "CVE-2022-37620", severity: "MEDIUM", package: "html-minifier@4.0.0", fixedIn: "" }], candidates: [],
    },
  ],
  warnings: [],
  families: [{ name: "react 19", members: ["@types/react", "react", "react-dom"] }],
})
write("package.json", reasonsManifest, reasons.project)
write("project.json", {
  id: reasons.project, name: "reasons", target, createdAt: "2026-11-24T10:14:00Z",
  manifestSha256: createHash("sha256").update(reasonsManifest).digest("hex"),
}, reasons.project)
write(`analyses/${reasons.analysis}/status.json`, {
  state: "done", pnpmVersion: "12.3.4", trivyVersion: "0.74.0", trivyDbDate: "2026-11-24T06:12:00Z",
}, reasons.project)
write(`analyses/${reasons.analysis}/candidates.json`, JSON.stringify(reasonsResult(null), null, 2), reasons.project)
write(`analyses/${reasons.analysis}/ranking.json`, JSON.stringify(reasonsResult([0, 0, 1, 0, 0]), null, 2), reasons.project)

// The worst case for the review's reasons: twenty dependencies keep a CVE no version fixes, one with a
// 40-character name, and a twenty-first the gate moves off its proposal, so the Export bar shows its note
// and a two-line cause.
const worst = { project: "worst", analysis: "20261124T111500Z" }
const worstNames = ["@northwind-industries/holdings-dashboard", ...Array.from({ length: 20 }, (_, i) => `keeps-cve-${i + 1}`)]
const worstManifest = JSON.stringify({ name: "worst", dependencies: Object.fromEntries(worstNames.map((n) => [n, "1.0.0"])) }, null, 2)
const worstResult = (after) => ({
  target,
  before: [0, 0, 21, 0, 0],
  after,
  dependencies: worstNames.map((name, i) => ({
    name, current: "1.0.0", vector: [0, 0, 1, 0, 0],
    cves: [{ id: `CVE-2025-${1000 + i}`, severity: "MEDIUM", package: `${name}@1.0.0`, fixedIn: "" }],
    candidates: [stored("1.0.0"), stored("1.0.1")],
  })),
  warnings: [],
})
write("package.json", worstManifest, worst.project)
write("project.json", {
  id: worst.project, name: "worst", target, createdAt: "2026-11-24T11:14:00Z",
  manifestSha256: createHash("sha256").update(worstManifest).digest("hex"),
}, worst.project)
write(`analyses/${worst.analysis}/status.json`, {
  state: "done", pnpmVersion: "12.3.4", trivyVersion: "0.74.0", trivyDbDate: "2026-11-24T06:12:00Z",
}, worst.project)
write(`analyses/${worst.analysis}/candidates.json`, JSON.stringify(worstResult(null), null, 2), worst.project)
write(`analyses/${worst.analysis}/ranking.json`, JSON.stringify(worstResult([0, 0, 21, 0, 0]), null, 2), worst.project)

// The key is made per run and written as the store writes it: PKCS#8 PEM, mode 0600, in private/ at 0700.
const { publicKey, privateKey } = generateKeyPairSync("ed25519")
mkdirSync(join(root, "private"), { recursive: true, mode: 0o700 })
chmodSync(join(root, "private"), 0o700)
writeFileSync(join(root, "private", "signing-key.pem"), privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 })
const publicKeySha256 = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")

// The signature covers the manifest's exact bytes, indented as the store writes it.
const exportManifest = JSON.stringify(
  { analysisId: analysis, createdAt: "2026-09-21T10:20:00Z", archive: { sha256: "0".repeat(64), size: 5500000 }, packages: [] },
  null,
  2,
)
write(`exports/${exported}/manifest.json`, exportManifest)
write(
  `exports/${exported}/manifest.json.sig`,
  JSON.stringify(
    { algorithm: "ed25519", publicKeySha256, signature: sign(null, Buffer.from(exportManifest), privateKey).toString("base64") },
    null,
    2,
  ) + "\n",
)
write(`exports/${exported}/packages_npm.tar.gz`, "")

// Projects and a project's crossings. web-portal holds two analyses started the same day, the earlier
// one sealed with the volume's key, the later one failed at its scan, a cancelled one and an earlier
// export signed with a key this volume no longer holds. pipeline, with a 40-character name, has that
// earlier key on its newest archive, so its page opens on the replaced-key block. Every export
// directory holds what the export job leaves there: the archive, manifest.json, its signature and the
// four reports.
const { privateKey: replacedKey, publicKey: replacedPublic } = generateKeyPairSync("ed25519")
const replacedSha256 = createHash("sha256").update(replacedPublic.export({ type: "spki", format: "der" })).digest("hex")
const crossing = (into, name) => {
  const projectManifest = JSON.stringify({ name, dependencies: { express: "5.0.1" } }, null, 2)
  write("package.json", projectManifest, into)
  write("project.json", { id: into, name, target, createdAt: "2026-11-01T09:00:00Z", manifestSha256: createHash("sha256").update(projectManifest).digest("hex") }, into)
}
const analysed = (into, id, status) => write(`analyses/${id}/status.json`, { pnpmVersion: "12.3.4", trivyVersion: "0.74.0", trivyDbDate: "2026-11-20T06:12:00Z", ...status }, into)
const sealed = (into, analysisId, id, createdAt, signer, signerSha256) => {
  // A stand-in for the archive's bytes, hashed as the export hashes the real one.
  const archive = `${into} ${id}`
  const body = JSON.stringify(
    { formatVersion: 1, toolVersion: "0.7.0", analysisId, createdAt, target, archive: { sha256: createHash("sha256").update(archive).digest("hex"), size: archive.length }, packages: [] },
    null,
    2,
  )
  write(`exports/${id}/packages_npm.tar.gz`, archive, into)
  write(`exports/${id}/manifest.json`, body, into)
  write(
    `exports/${id}/manifest.json.sig`,
    JSON.stringify({ algorithm: "ed25519", publicKeySha256: signerSha256, signature: sign(null, Buffer.from(body), signer).toString("base64") }, null, 2) + "\n",
    into,
  )
  write(`exports/${id}/summary.md`, `# ${into}\n\nKnown CVEs before 2, after 0.\n`, into)
  write(`exports/${id}/findings.csv`, "package,version,cve,severity\n", into)
  write(`exports/${id}/report.cdx.json`, JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", components: [] }, null, 2), into)
  write(`exports/${id}/report.trivy.json`, JSON.stringify({ SchemaVersion: 2, Results: [] }, null, 2), into)
}
crossing("web-portal", "web-portal")
analysed("web-portal", "20261123T091500Z", { state: "done" })
sealed("web-portal", "20261123T091500Z", "20261123T092000Z", "2026-11-23T09:20:00Z", privateKey, publicKeySha256)
analysed("web-portal", "20261123T141500Z", {
  state: "failed",
  steps: [{ name: "scan", state: "failed", error: "trivy: exit status 1: database download failed: dial tcp: lookup ghcr.io: no such host" }],
})
analysed("web-portal", "20261118T101500Z", { state: "cancelled" })
analysed("web-portal", "20261106T101500Z", { state: "done" })
sealed("web-portal", "20261106T101500Z", "20261106T102000Z", "2026-11-06T10:20:00Z", replacedKey, replacedSha256)
crossing("pipeline", "analytics-ingest-pipeline-airflow-worker")
analysed("pipeline", "20261112T101500Z", { state: "done" })
sealed("pipeline", "20261112T101500Z", "20261112T102000Z", "2026-11-12T10:20:00Z", replacedKey, replacedSha256)

// The versions the start prepares come from the Go sources, so a moved pin or default fails here loudly.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..")
const sourceValue = (file, pattern) => {
  const match = readFileSync(join(repo, file), "utf8").match(pattern)
  if (!match) throw new Error(`seed: ${pattern} matches nothing in ${file}`)
  return match[1]
}
const trivy = sourceValue("internal/tools/trivy_pin.go", /Version:\s*"([^"]+)"/)
const pnpm = sourceValue("internal/store/store.go", /PnpmVer:\s*"([^"]+)"/)
const uv = sourceValue("internal/store/types.go", /UvVer:\s*"([^"]+)"/)

const tool = (path, content, mode) => {
  const file = join(root, path)
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, content, { mode })
}
// A Trivy that exits 0, so the database refresh at start succeeds and reads the metadata below.
tool(`tools/trivy/${trivy}/trivy`, "#!/bin/sh\nexit 0\n", 0o755)
symlinkSync(trivy, join(root, "tools", "trivy", "current"))
tool(
  "trivy-cache/db/metadata.json",
  JSON.stringify({ Version: 2, NextUpdate: "2026-09-21T12:12:00Z", UpdatedAt: "2026-09-21T06:12:00Z", DownloadedAt: "2026-09-21T07:00:00Z" }),
  0o644,
)
tool(`tools/pnpm/${pnpm}/package/bin/pnpm.cjs`, "process.exit(0)\n", 0o644)
tool(`tools/uv/${uv}/uv`, "#!/bin/sh\nexit 0\n", 0o755)
