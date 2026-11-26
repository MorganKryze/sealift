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

// The review's worst case: 15 major jumps in 3 families, 15 CVEs that no version fixes in 5 packages (angular
// 1.8.3 with its 11, a long scoped name at a long version with a GHSA id), 8 updates and 127 packages that
// stay. The shapes are what the rank step writes; the gate stores the selection that takes every jump.
const worst = { project: "worst", analysis: "20261125T091500Z" }
const worstFamilies = {
  "react 19": [["react", "18.3.1", "19.2.0"], ["react-dom", "18.3.1", "19.2.0"], ["@types/react", "18.3.12", "19.2.2"], ["@types/react-dom", "18.3.1", "19.2.2"], ["react-router-dom", "6.30.1", "7.9.4"], ["@testing-library/react", "15.0.7", "16.3.0"], ["react-redux", "8.1.3", "9.2.0"]],
  "eslint 9": [["eslint", "8.57.1", "9.38.0"], ["eslint-plugin-react-hooks", "4.6.2", "5.2.0"], ["@typescript-eslint/parser", "7.18.0", "8.46.1"], ["@typescript-eslint/eslint-plugin", "7.18.0", "8.46.1"], ["eslint-config-prettier", "9.1.0", "10.1.8"]],
  "vite 7": [["vite", "5.4.20", "7.1.12"], ["@vitejs/plugin-react", "4.7.0", "5.1.0"], ["vitest", "2.1.9", "4.0.8"]],
}
const babel = "@babel/plugin-transform-async-generator-functions"
const finding = (id, severity, name, version, fixedIn) => ({ id, severity, package: `${name}@${version}`, fixedIn })
const counted = (cves) => ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => new Set(cves.filter((c) => c.severity === s).map((c) => c.id)).size)
const keeps = (name, version, ids) => {
  const cves = ids.map(([id, severity]) => finding(id, severity, name, version, ""))
  return { name, current: version, vector: counted(cves), cves, candidates: [] }
}
const updates = (name, from, to, ids) => {
  const cves = ids.map(([id, severity]) => finding(id, severity, name, from, to))
  return { name, current: from, best: to, vector: counted(cves), cves, candidates: [stored(to)] }
}
const worstDependencies = [
  ...Object.entries(worstFamilies).flatMap(([family, members]) =>
    members.map(([name, from, to]) => ({ name, current: from, vector: zero, cves: [], candidates: [stored(to, leaves(from.split(".")[0]))], jump: to, family })),
  ),
  keeps("angular", "1.8.3", [
    ["CVE-2024-21490", "HIGH"],
    ...["CVE-2025-4690", "CVE-2025-2336", "CVE-2025-0716", "CVE-2024-8373", "CVE-2024-8372", "CVE-2023-26118", "CVE-2023-26117", "CVE-2023-26116", "CVE-2022-25869", "CVE-2022-25844"].map((id) => [id, "MEDIUM"]),
  ]),
  keeps("html-minifier", "4.0.0", [["CVE-2022-37620", "HIGH"]]),
  keeps("lodash.template", "4.5.0", [["CVE-2021-23337", "HIGH"]]),
  keeps(babel, "1.0.0-beta.12+build.345", [["GHSA-2fx7-6rpj-5w4c", "HIGH"]]),
  keeps("request", "2.88.2", [["CVE-2023-28155", "MEDIUM"]]),
  updates("form-data", "4.0.0", "4.0.4", [["CVE-2025-7783", "CRITICAL"]]),
  updates("axios", "1.6.0", "1.12.2", [["CVE-2024-39338", "HIGH"], ["CVE-2025-27152", "HIGH"], ["CVE-2025-58754", "HIGH"]]),
  updates("lodash", "4.17.20", "4.17.21", [["CVE-2021-23337", "HIGH"]]),
  updates("express", "4.18.2", "4.21.2", [["CVE-2024-29041", "MEDIUM"], ["CVE-2024-43796", "MEDIUM"]]),
  updates("follow-redirects", "1.15.2", "1.15.11", [["CVE-2023-26159", "MEDIUM"], ["CVE-2024-28849", "MEDIUM"], ["CVE-2025-52999", "MEDIUM"]]),
  updates("postcss", "8.4.27", "8.5.6", [["CVE-2023-44270", "MEDIUM"], ["CVE-2025-27789", "LOW"]]),
  updates("@typescript/native-preview", "7.0.0-dev.20251001.1", "7.0.0-dev.20251101.1", [["CVE-2025-30204", "LOW"]]),
  updates("ws", "8.17.0", "8.18.3", [["CVE-2024-37890", "HIGH"]]),
  ...Array.from({ length: 127 }, (_, i) => ({ name: `kiosk-lib-${String(i + 1).padStart(3, "0")}`, current: `${1 + (i % 9)}.${i % 23}.${i % 7}`, vector: zero, cves: [], candidates: [] })),
]
const worstManifest = JSON.stringify({ name: "kiosk-ui", dependencies: Object.fromEntries(worstDependencies.map((d) => [d.name, d.current])) }, null, 2)
const worstResult = (after) => ({
  target,
  before: worstDependencies.reduce((sum, d) => sum.map((n, i) => n + d.vector[i]), [0, 0, 0, 0, 0]),
  after,
  dependencies: worstDependencies,
  warnings: [],
  families: Object.entries(worstFamilies).map(([name, members]) => ({ name, members: members.map(([n]) => n).sort() })),
})
write("package.json", worstManifest, worst.project)
write("project.json", {
  id: worst.project, name: "kiosk-ui", target, createdAt: "2026-11-25T09:14:00Z",
  manifestSha256: createHash("sha256").update(worstManifest).digest("hex"),
}, worst.project)
write(`analyses/${worst.analysis}/status.json`, {
  state: "done", pnpmVersion: "12.3.4", trivyVersion: "0.74.0", trivyDbDate: "2026-11-25T06:12:00Z",
}, worst.project)
write(`analyses/${worst.analysis}/candidates.json`, JSON.stringify(worstResult(null), null, 2), worst.project)
write(`analyses/${worst.analysis}/ranking.json`, JSON.stringify(worstResult([0, 0, 11, 0, 0]), null, 2), worst.project)

// An analysis sealift 0.7.0 wrote: no jump, no family and no families, CVEs with their id and severity only,
// and a status with no database date. Its review offers no Jump and says the fix was not recorded.
const legacy = { project: "legacy", analysis: "20261020T101500Z" }
const legacyManifest = JSON.stringify({ name: "legacy-portal", dependencies: { angular: "1.8.3", chalk: "4.1.2", lodash: "4.17.20" } }, null, 2)
const legacyCandidate = (version, vector, cves) => ({ version, vector, cves, signals: [], key: true, resolved: true, published })
const legacyResult = (after) => ({
  target,
  before: [0, 3, 1, 0, 0],
  after,
  dependencies: [
    {
      name: "angular", current: "1.8.3", vector: [0, 1, 1, 0, 0],
      cves: [{ id: "CVE-2024-21490", severity: "HIGH" }, { id: "CVE-2025-4690", severity: "MEDIUM" }],
      candidates: [legacyCandidate("2.0.0", [0, 0, 0, 0, 0], [])],
    },
    { name: "chalk", current: "4.1.2", vector: zero, cves: [], candidates: [legacyCandidate("5.3.0", zero, [])] },
    {
      name: "lodash", current: "4.17.20", best: "4.17.21", vector: [0, 2, 0, 0, 0],
      cves: [{ id: "CVE-2021-23337", severity: "HIGH" }, { id: "CVE-2020-8203", severity: "HIGH" }],
      candidates: [legacyCandidate("4.17.21", zero, [])],
    },
  ],
  warnings: [],
})
write("package.json", legacyManifest, legacy.project)
write("project.json", {
  id: legacy.project, name: "legacy-portal", target, createdAt: "2026-10-20T10:14:00Z",
  manifestSha256: createHash("sha256").update(legacyManifest).digest("hex"),
}, legacy.project)
write(`analyses/${legacy.analysis}/status.json`, { state: "done", pnpmVersion: "10.18.0", trivyVersion: "0.66.0" }, legacy.project)
write(`analyses/${legacy.analysis}/candidates.json`, JSON.stringify(legacyResult(null), null, 2), legacy.project)
write(`analyses/${legacy.analysis}/ranking.json`, JSON.stringify(legacyResult([0, 1, 1, 0, 0]), null, 2), legacy.project)

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
