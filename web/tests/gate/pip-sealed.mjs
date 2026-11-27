// A pip crossing's Ready to seal, Seal and Sealed. The seeded volume holds no pip project, so
// GET /api/projects/billing-api answers here in the contract's shape, its analysis' pipResult as
// pip-result.json holds it, with its export in front once one exists. The event stream carries the events
// the pip export emits (a step event as each step starts and ends, the download's count), and the done
// export's manifest.json is the one the pip export writes: format 3, every wheel with its sha256, the
// signed review on new exports and none on the one 0.7.0 wrote. manifest.json.sig is the seeded
// export's, signed with the volume's key, so its signature names the key in use.

const ID = "billing-api"
const LONG_NAME = "claims-risk-scoring-batch-pipelines-for-regional-insurers-eu"
const LONG_PACKAGE = "acme-ledger-reconciliation-opentelemetry-exporter-postgresql"
const AT = "20261126T091500Z"
const CREATED = "2026-11-26T09:15:00Z"
const EXPORT = "20261126T092000Z"
const SEEDED = "/api/projects/web-portal/exports/20261123T092000Z/files/manifest.json.sig"
const TARGET = { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" }
const PREVIOUS = { projectId: ID, projectName: ID, exportId: "20261120T102000Z", analysisId: "20261120T101500Z", sealedAt: "2026-11-20T10:20:00Z" }
const FILES = ["findings.csv", "manifest.json", "manifest.json.sig", "packages_pip.tar.gz", "report.cdx.json", "report.trivy.json", "summary.md"]
const ARCHIVE_SHA = "3b9e17c04d2a6f8e1c5b7a9d0e3f2c4b6a8d1e5f7c9b2a4d6e8f0a1c3e5b7d9f"
const SHA = (i) => i.toString(16).padStart(64, "0")

const ANY = "py3-none-any"
const M5 = "cp311-cp311-manylinux_2_5_x86_64.manylinux1_x86_64"
const M17 = "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64"
const M24 = "cp311-cp311-manylinux_2_24_x86_64"
const M28 = "cp311-cp311-manylinux_2_28_x86_64"
const NATIVE = ["numpy", "pandas", "pydantic_core", "charset_normalizer", "psycopg_binary", "grpcio", "scipy", "orjson"]

const finding = (id, severity, fixedVersions = []) => ({ id, severity, fixedVersions })
const wheelOf = (name, version, tag, size, i) => ({
  file: `${name.replace(/-/g, "_")}-${version}-${tag}.whl`,
  url: `https://files.pythonhosted.org/packages/${SHA(i).slice(0, 2)}/${name}-${version}.whl`,
  sha256: SHA(i),
  size,
  uploadedAt: "2025-03-31T14:00:00Z",
})

// `platforms` lists each tag with its wheel count and the size of each; the first `pins` packages are
// pinned in requirements.txt, the rest are dependencies. `extra` packages come first, pinned. A null
// `previous` records no previous crossing.
function setOf({ platforms, pins, extra = [], files = ["requirements.txt", "requirements-dev.txt", "constraints.txt"], previous = PREVIOUS }) {
  let i = 0
  const packages = [...extra]
  for (const [tag, count, size] of platforms) {
    for (let n = 0; n < count; n++, i++) {
      const name = tag === ANY ? `billing-lib-${String(i).padStart(4, "0")}` : `${NATIVE[n % NATIVE.length]}-${String(i).padStart(4, "0")}`
      const version = `${1 + (i % 7)}.${i % 13}.${i % 5}`
      const pinned = packages.length < pins
      packages.push({
        name,
        version,
        files: pinned ? ["requirements.txt"] : [],
        ...(pinned ? { pinnedAt: [{ file: "requirements.txt", line: packages.length + 1 }] } : {}),
        wheel: wheelOf(name, version, tag, size, 100 + i),
        cves: [],
        ...(previous ? { previous: { version, cves: [], majorJump: false } } : {}),
      })
    }
  }
  return { target: TARGET, files, packages: packages.sort((a, b) => a.name.localeCompare(b.name)), blocking: [], warnings: [], ...(previous ? { previous } : {}) }
}

const pinned = (name, version, line, more) => ({ name, version, files: ["requirements.txt"], pinnedAt: [{ file: "requirements.txt", line }], cves: [], ...more })
const kept = (version, cves) => ({ version, cves, majorJump: false })

// The frame's crossing: 212 pins in 3 files, gunicorn and Jinja2 keep a CVE a newer release fixes,
// django's major jump carries its reason; 198 pure wheels, 38 for glibc 2.17 and 7 for 2.28.
function billing() {
  const gunicorn = [finding("CVE-2024-6827", "HIGH", ["23.0.0"])]
  const jinja = [finding("CVE-2025-27516", "MEDIUM", ["3.1.6"])]
  return setOf({
    pins: 212,
    platforms: [[ANY, 195, 112_000], [M17, 36, 4_100_000], [M28, 7, 3_115_000]],
    extra: [
      pinned("django", "5.1.4", 3, { wheel: wheelOf("django", "5.1.4", ANY, 8_300_000, 1), previous: { version: "4.2.16", cves: [], majorJump: true } }),
      pinned("gunicorn", "22.0.0", 5, { wheel: wheelOf("gunicorn", "22.0.0", ANY, 85_000, 2), cves: gunicorn, previous: kept("22.0.0", gunicorn) }),
      pinned("jinja2", "3.1.5", 6, { wheel: wheelOf("jinja2", "3.1.5", ANY, 134_000, 3), cves: jinja, previous: kept("3.1.5", jinja) }),
      pinned("numpy", "2.1.3", 8, { wheel: wheelOf("numpy", "2.1.3", M17, 17_200_000, 4), previous: kept("2.1.3", []) }),
      pinned("pandas", "2.2.3", 9, { wheel: wheelOf("pandas", "2.2.3", M17, 13_700_000, 5), previous: kept("2.2.3", []) }),
    ],
  })
}
const BILLING_REASONS = { "major-jump:django": "Moved to Django 5.1 in branch django-5, all tests green" }

// The worst case: 220 pins in 3 files, 1,284 wheels on 5 platforms, 7 packages that keep a fixable CVE,
// the 60-character package with the longest wheel name, no previous crossing.
function worst() {
  const fixable = [
    ["gunicorn", "21.2.0", [finding("CVE-2024-1135", "HIGH", ["22.0.0"]), finding("CVE-2024-6827", "HIGH", ["23.0.0"])]],
    ["setuptools", "69.5.1", [finding("CVE-2024-6345", "HIGH", ["70.0.0"]), finding("CVE-2025-47273", "HIGH", ["78.1.1"])]],
    ["starlette", "0.36.3", [finding("CVE-2024-24762", "HIGH", ["0.36.2"]), finding("CVE-2024-47874", "MEDIUM", ["0.40.0"])]],
    ["jinja2", "3.1.4", [finding("CVE-2024-56201", "MEDIUM", ["3.1.5"]), finding("CVE-2024-56326", "MEDIUM", ["3.1.5"]), finding("CVE-2025-27516", "MEDIUM", ["3.1.6"])]],
    ["urllib3", "2.2.1", [finding("CVE-2024-37891", "MEDIUM", ["2.2.2"]), finding("CVE-2025-50181", "MEDIUM", ["2.5.0"]), finding("CVE-2025-50182", "MEDIUM", ["2.5.0"])]],
    ["requests", "2.31.0", [finding("CVE-2024-35195", "MEDIUM", ["2.32.0"]), finding("CVE-2024-47081", "MEDIUM", ["2.32.4"])]],
    ["idna", "3.6", [finding("CVE-2024-3651", "MEDIUM", ["3.7"])]],
  ]
  return setOf({
    pins: 220,
    previous: null,
    platforms: [[ANY, 1039, 300_000], [M5, 41, 920_000], [M17, 167, 10_700_000], [M24, 6, 3_300_000], [M28, 23, 11_000_000]],
    extra: [
      ...fixable.map(([name, version, cves], i) => pinned(name, version, 10 + i, { wheel: wheelOf(name, version, ANY, 240_000, 10 + i), cves })),
      pinned(LONG_PACKAGE, "1.4.0", 1, { wheel: wheelOf(LONG_PACKAGE, "1.4.0", `${M17}.musllinux_1_2_x86_64`, 2_200_000, 9) }),
    ],
  })
}

// The same set as pip-result.json 0.7.0 wrote it: no pin places, no previous crossing, no upload dates.
function legacy(made) {
  const packages = made.packages.map(({ pinnedAt: _p, previous: _v, wheel: { uploadedAt: _u, ...wheel }, ...pkg }) => ({ ...pkg, wheel }))
  return { target: made.target, files: made.files, packages, blocking: [], warnings: [] }
}

const analysis = (pipResult) => ({ id: AT, projectId: ID, state: "done", createdAt: CREATED, uvVersion: "0.13.7", trivyVersion: "0.76.2", trivyDbDate: "2026-11-26T06:12:00Z", pipResult })
const exported = (state, files) => ({ id: EXPORT, projectId: ID, analysisId: AT, state, createdAt: "2026-11-26T09:20:00Z", ...(files ? { files } : {}) })
const answer = (page, project) => page.route((url) => url.pathname === `/api/projects/${ID}`, (route) => route.fulfill({ json: project }))
const projectWith = (pipResult, exports = [], name = ID) => ({ id: ID, name, ecosystem: "pip", pipTarget: TARGET, analyses: [analysis(pipResult)], exports })
const stored = (page, reasons) => page.addInitScript(([key, value]) => sessionStorage.setItem(key, JSON.stringify(value)), [`sealift:reasons:${AT}`, reasons])

const ready = (made, reasons, name) => async (page) => {
  await answer(page, projectWith(made, [], name))
  if (reasons) await stored(page, reasons)
}
// Seal answered as internal/api answers a set under a refuse rule.
const refused = async (page) => {
  await ready(billing(), BILLING_REASONS)(page)
  await page.route(
    (url) => url.pathname === `/api/projects/${ID}/analyses/${AT}/exports`,
    (route) =>
      route.fulfill({
        status: 409,
        contentType: "application/problem+json",
        body: JSON.stringify({ type: "about:blank", title: "queue export", status: 409, detail: "jobs: review.majorJump is refuse: django 4.2.16 to 5.1.4 is a major jump and cannot cross" }),
      }),
  )
}

// One frame per event, as internal/api writes them: the kind as the event name, the whole event as data.
const frame = (kind, data) => `event: ${kind}\ndata: ${JSON.stringify({ kind, job: "export-4", storeId: EXPORT, data })}\n\n`
const SEALING = [
  frame("step", { name: "prepare", state: "running" }),
  frame("step", { name: "prepare", state: "done", durationMs: 40 }),
  frame("step", { name: "package-list", state: "running" }),
  frame("step", { name: "package-list", state: "done", durationMs: 120 }),
  frame("step", { name: "download", state: "running" }),
  frame("progress", { step: "download", done: 118, total: 243, cacheHits: 0 }),
]
const sealing = async (page) => {
  await answer(page, projectWith(billing(), [exported("running")]))
  await stored(page, BILLING_REASONS)
  await page.route((url) => url.pathname === "/api/jobs/current/events", (route) => route.fulfill({ status: 200, contentType: "text/event-stream", body: SEALING.join("") }))
}

// manifest.json as the pip export writes it; 0.7.0 wrote the same with no review.
const manifest = (made, size, review) => ({
  formatVersion: 3,
  ecosystem: "pip",
  toolVersion: review ? "0.8.0" : "0.7.0",
  analysisId: AT,
  createdAt: "2026-11-26T09:24:00Z",
  target: TARGET,
  archive: { sha256: ARCHIVE_SHA, size },
  packages: made.packages.map((pkg, i) => ({ name: pkg.name.toLowerCase(), version: pkg.version, file: pkg.wheel.file, sha256: pkg.wheel.sha256, shippedSha512: SHA(i).repeat(2) })),
  ...(review ? { review } : {}),
})
const REVIEW = {
  cves: { before: [0, 1, 2, 0, 0], after: [0, 1, 1, 0, 0] },
  updates: [],
  jumps: [{ family: "django", packages: [{ name: "django", from: "4.2.16", to: "5.1.4" }], reason: BILLING_REASONS["major-jump:django"] }],
  left: [],
  unchanged: 242,
}
// A null review is a manifest.json with none, as 0.7.0 wrote it.
const sealed = ({ made = billing(), size = 195_454_566, review = REVIEW, name } = {}) => async (page) => {
  await answer(page, projectWith(made, [exported("done", FILES)], name))
  await page.route(
    (url) => url.pathname.startsWith(`/api/projects/${ID}/exports/${EXPORT}/files/`),
    async (route) => {
      const url = new URL(route.request().url())
      if (url.pathname.endsWith("/files/manifest.json")) return route.fulfill({ status: 200, contentType: "application/octet-stream", body: JSON.stringify(manifest(made, size, review), null, 2) })
      if (url.pathname.endsWith("/files/manifest.json.sig")) return route.fulfill({ response: await route.fetch({ url: new URL(SEEDED, url).href }) })
      return route.fulfill({ status: 200, contentType: "application/octet-stream", body: "" })
    },
  )
}

const PATH = `/crossings/${ID}`
const button = (name) => ({ role: "button", name })
const CVE_TEXT = "A CVE is a publicly listed security flaw, named by an id such as CVE-2024-4068. Known CVEs counts the ones the scan found in these versions."
const WHEEL_TEXT = "A wheel is a package built ahead for one Python version and platform, which pip installs without running any of its code. A source distribution must be built during the install, so none crosses."

export const states = [
  { path: PATH, name: "ready to seal", before: ready(billing(), BILLING_REASONS), ready: "what Seal downloads" },
  { path: PATH, name: "ready with the CVE explanation open", before: ready(billing(), BILLING_REASONS), click: [button("What a CVE is")], ready: CVE_TEXT },
  { path: PATH, name: "ready with the wheel explanation open", before: ready(billing(), BILLING_REASONS), click: [button("What a wheel is")], ready: WHEEL_TEXT },
  { path: PATH, name: "ready with a platform open", before: ready(billing(), BILLING_REASONS), click: [button(/^Linux x86_64, glibc 2\.17 and later/)], ready: "Show all 38 wheels" },
  { path: PATH, name: "ready, the worst case", before: ready(worst(), undefined, LONG_NAME), click: [button(/^Linux x86_64, glibc 2\.17 and later/)], ready: "Show all 168 wheels" },
  { path: PATH, name: "seal refused under a refuse rule", before: refused, click: [button("Seal")], ready: "This instance refuses every major jump" },
  { path: PATH, name: "sealing", before: sealing, ready: "Downloading and verifying each wheel" },
  { path: PATH, name: "sealed with Done disabled", before: sealed(), ready: "Opens once a download starts" },
  { path: PATH, name: "sealed after Download all", before: sealed(), open: { role: "button", name: "Download all", opens: { role: "link", name: "Done" } } },
  { path: PATH, name: "sealed, the worst case", before: sealed({ made: worst(), size: 2_480_343_613, name: LONG_NAME }), ready: "2.3 GB" },
  { path: PATH, name: "a sealed pip crossing 0.7.0 wrote", before: sealed({ made: legacy(billing()), review: null }), ready: "Sealed" },
]
