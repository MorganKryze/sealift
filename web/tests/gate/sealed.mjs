// The Seal step's states. The seeded crossings of web-portal end failed, so sealing and sealed are answered
// here: GET /api/projects/web-portal is the seeded server's own answer with a done analysis and its export put
// in front, the event stream is a text/event-stream body of the events internal/jobs' export emits for that
// moment, and the sealed export's files are the seeded sealed export's, but for a manifest.json in the
// current shape, with its signed review. pipeline's sealed crossing is the seeded one, as 0.7.0 wrote it.

const PROJECT = "web-portal"
const PATH = `/sessions/${PROJECT}/export`
const ANALYSIS = "20261126T140500Z"
const EXPORT = "20261126T142000Z"
// Seeded and signed with the volume's key, so its signature names the key in use.
const SEEDED = "20261123T092000Z"
const JOB = "export-3"
const FILES = ["findings.csv", "manifest.json", "manifest.json.sig", "packages_npm.tar.gz", "report.cdx.json", "report.trivy.json", "summary.md"]
const ARCHIVE_SHA = "fca8560d2b7e4c9135d0a8e6c1f47b2903e5d8a17c64f0b2e9d3a75116b4861a"
const LONG_NAME = "customer-onboarding-portal-frontend-next"

// One frame per event, as internal/api writes them: the kind as the event name, the whole event as data.
const frame = (kind, data) => `event: ${kind}\ndata: ${JSON.stringify({ kind, job: JOB, storeId: EXPORT, data })}\n\n`
// An export reports each step as it starts and as it ends, and the download's count with its cache hits.
const SEALING = [
  frame("step", { name: "prepare", state: "running" }),
  frame("step", { name: "prepare", state: "done", durationMs: 40 }),
  frame("step", { name: "package-list", state: "running" }),
  frame("step", { name: "package-list", state: "done", durationMs: 310 }),
  frame("step", { name: "download", state: "running" }),
  frame("progress", { step: "download", done: 796, total: 1284, cacheHits: 112 }),
]

// The seeded server's answer for a path, changed by `edit` before the page reads it.
const edited = (page, pathname, edit) =>
  page.route((url) => url.pathname === pathname, async (route) => {
    if (route.request().method() !== "GET") return route.fallback()
    const response = await route.fetch()
    return route.fulfill({ response, json: edit(await response.json()) })
  })
const withExport = (page, exported, name) =>
  edited(page, `/api/projects/${PROJECT}`, (project) => ({
    ...project,
    ...(name ? { name } : {}),
    analyses: [{ id: ANALYSIS, projectId: PROJECT, state: "done", createdAt: "2026-11-26T14:05:00Z" }, ...(project.analyses ?? [])],
    exports: [{ id: EXPORT, projectId: PROJECT, analysisId: ANALYSIS, createdAt: "2026-11-26T14:20:00Z", ...exported }, ...(project.exports ?? [])],
  }))
const stream = (page, frames) =>
  page.route((url) => url.pathname === "/api/jobs/current/events", (route) => route.fulfill({ status: 200, contentType: "text/event-stream", body: frames.join("") }))

// manifest.json as internal/report.Manifest writes it, with the review the export signs.
const manifest = (packages, size) => ({
  formatVersion: 1,
  toolVersion: "0.8.0",
  analysisId: ANALYSIS,
  createdAt: "2026-11-26T14:24:00Z",
  target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
  archive: { sha256: ARCHIVE_SHA, size },
  packages: Array.from({ length: packages }, (_, i) => ({
    name: `portal-lib-${String(i).padStart(4, "0")}`,
    version: "1.0.0",
    file: `portal-lib-${String(i).padStart(4, "0")}-1.0.0.tgz`,
    originalIntegrity: `sha512-${"A".repeat(86)}==`,
    shippedSha512: "0".repeat(128),
    publishConfigStripped: false,
  })),
  review: {
    cves: { before: [0, 3, 12, 8, 2], after: [0, 0, 1, 1, 0] },
    updates: [{ name: "express", from: "4.21.2", to: "4.22.1", fixed: [0, 1, 2, 0, 0], left: [0, 0, 0, 0, 0] }],
    kept: [{ name: "react", version: "18.3.1", jump: "19.2.0" }],
    jumps: [{ family: "vite", packages: [{ name: "vite", from: "6.3.5", to: "7.1.12" }], reason: "CI and every dev machine run Node 22; Vite 7 builds the app" }],
    left: [{ dependency: "html-minifier", version: "4.0.0", id: "CVE-2022-37620", severity: "HIGH", package: "html-minifier@4.0.0", fixedIn: "", reason: "Dev dependency, runs at build time on our own HTML" }],
    unchanged: 1270,
  },
})
// The done export's files: the seeded export's bytes, but for manifest.json.
const sealedFiles = (page, body) =>
  page.route((url) => url.pathname.startsWith(`/api/projects/${PROJECT}/exports/${EXPORT}/files/`), async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith("/files/manifest.json")) return route.fulfill({ status: 200, contentType: "application/octet-stream", body: JSON.stringify(body, null, 2) })
    url.pathname = url.pathname.replace(EXPORT, SEEDED)
    return route.fulfill({ response: await route.fetch({ url: url.href }) })
  })
const ephemeral = (page) => edited(page, "/api/instance", (instance) => ({ ...instance, ephemeral: true, idleMinutes: 30 }))

const sealing = async (page) => {
  await withExport(page, { state: "running" })
  await stream(page, SEALING)
}
const sealed = ({ packages = 1284, size = 101_187_584, name, erase = false } = {}) => async (page) => {
  await withExport(page, { state: "done", files: FILES }, name)
  await sealedFiles(page, manifest(packages, size))
  if (erase) await ephemeral(page)
}

const button = (name) => ({ role: "button", name })

export const states = [
  { path: PATH, name: "sealing", before: sealing, ready: "Downloading and verifying each package" },
  { path: PATH, name: "sealed with Done disabled", before: sealed(), ready: "Opens once a download starts" },
  { path: PATH, name: "sealed after Download all", before: sealed(), open: { role: "button", name: "Download all", opens: { role: "link", name: "Done" } } },
  { path: PATH, name: "the fingerprint open", before: sealed(), click: [button(/^sha256 of packages_npm\.tar\.gz/)], ready: "2b7e4c91" },
  { path: PATH, name: "the worst case", before: sealed({ packages: 1284, size: 2_147_483_648, name: LONG_NAME, erase: true }), ready: "2.0 GB" },
  { path: PATH, name: "ephemeral", before: sealed({ erase: true }), ready: "30 minutes" },
  { path: PATH, name: "the erase confirm", before: sealed({ erase: true }), click: [button("Erase now")], ready: "Erase this project and its files now?" },
  { path: "/sessions/pipeline/export", name: "a sealed crossing 0.7.0 wrote", ready: "Signed with a key this instance has replaced" },
]
