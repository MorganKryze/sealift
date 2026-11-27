// Fixtures for the import role in the browser gate: a realm's key set, a fake MinIO, a settings file,
// a token per user and the import records of every state the screens draw. The server under test is
// the shipped binary with its token check on; nothing here switches that check off.
import { createHash, createSign, generateKeyPairSync, sign } from "node:crypto"
import { chmodSync, mkdirSync, writeFileSync } from "node:fs"
import { createServer } from "node:http"
import { join } from "node:path"

const KEY_SET_PORT = 18091
const MINIO_PORT = 18092
const ISSUER = `http://127.0.0.1:${KEY_SET_PORT}/realms/gate`
const AUDIENCE = "sealift-import"
const KID = "gate-key"

const FOLDER = "packages/npm/"
const ARCHIVE = "packages_npm.tar.gz"
const PIP_FOLDER = "packages/pip/"
const PIP_ARCHIVE = "packages_pip.tar.gz"

// Ten minutes before the run, or local midnight when that falls yesterday, so the home counts the
// import that ends then as done today.
const todayStamp = () => {
  const midnight = new Date()
  midnight.setHours(0, 0, 0, 0)
  const at = new Date(Math.max(Date.now() - 10 * 60_000, midnight.getTime()))
  return at.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")
}

// The worst case's project names, 40 characters with their last letter.
const WORST = "procurement-supplier-onboarding-portal-"

// One id per state alice's records show. The gate's routes name them.
export const IDS = {
  completeToday: `${todayStamp()}-a100000e`,
  queued: "20261106T093000Z-a1000001",
  running: "20261106T091000Z-a1000002",
  completeRemoved: "20261105T161200Z-a1000003",
  completeKept: "20261105T110000Z-a1000004",
  completePending: "20261105T090000Z-a1000005",
  incomplete: "20261104T142000Z-a1000006",
  refusedDigests: "20261103T101500Z-a1000007",
  interrupted: "20261102T090500Z-a1000008",
  refusedLong: "20261101T120000Z-a1000009",
  refusedSignature: "20261031T100000Z-a100000c",
  legacy: "20261030T080000Z-a100000a",
  longKey: "20261020T170000Z-a100000b",
  pipComplete: "20261020T090000Z-a100000d",
  cancelled: "20261107T090000Z-a100000f",
}

// The live states: the server ends every queued or running attempt it finds at its start, so the page's
// read of a seeded record is answered with the server's own answer, changed as the store writes that state.
const live = (id, change) => async (page) => {
  await page.route((url) => url.pathname === `/api/imports/${id}`, async (route) => {
    const response = await route.fetch()
    const body = await response.json()
    change(body, body.attempts[body.attempts.length - 1])
    await route.fulfill({ response, json: body })
  })
}
const checking = live(IDS.running, (_, a) => {
  a.report.archiveChecked = false
  a.report.packages = a.report.packages.map((p) => ({ ...p, state: "pending", reason: "", note: "" }))
})
const ranked = live(IDS.queued, (imp) => {
  imp.queueAhead = 1
})
// The worst case of publishing: pip, 4,206 packages, 2,015 ended, 3 failed on the way, one Nexus answer of 600 characters.
const NUMPY = "numpy-2.1.3-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
const worstPublishing = live(IDS.running, (imp, a) => {
  imp.archive.key = "packages/pip/analytics-ingest-pipeline-airflow-worker-2026-11-25/packages_pip.tar.gz"
  imp.archive.size = 4_090_000_000
  a.report.ecosystem = "pip"
  a.report.packages = Array.from({ length: 4206 }, (_, i) => {
    const name = i === 7 ? "numpy" : `package-${String(i).padStart(4, "0")}`
    const file = i === 7 ? NUMPY : `${name}-1.0.0-py3-none-any.whl`
    const failed = i === 3 || i === 900 || i === 2010
    const state = i >= 2015 ? "pending" : failed ? "failed" : i % 5 === 0 ? "present" : "published"
    const reason = failed ? `502 from the gateway in front of Nexus, 3 attempts: ${"<html><body>Bad gateway ".repeat(30)}`.slice(0, 600) : ""
    return { name, version: i === 7 ? "2.1.3" : "1.0.0", file, state, reason, note: "", ...(failed ? { kind: "nexus" } : {}) }
  })
})

// The import role: the shipped import-server behind a real token check. A route names the user whose
// token the page sends as the gateway does, an optional control to press once the page has its
// content (`open`; a `pressed` control is waited on pressed, one with `opens` waits for that role and name, any other opens a dialog), an optional API path to hold until the checks are done so the loading state
// shows (`hold`), and the text that proves the data arrived (`ready`).
export const IMPORT = {
  baseURL: "http://127.0.0.1:18090",
  routes: [
    // The home: alice has archives to import, refusals, failed imports, a running one and one done today.
    { path: "/", user: "alice", ready: "Done today" },
    { path: "/", user: "alice", open: { role: "button", name: "Show all", exact: false, opens: { role: "link", name: "Open 2026-10-31-regenerated" } }, ready: "Done today" },
    // One compliant archive, its chip open on its checks.
    { path: "/", user: "gina", open: { role: "button", name: "Compliant", opens: { role: "list", name: "3 checks passed" } }, ready: "Needs you" },
    // The worst case: 16 crossings with 40-character names, closed, then all shown.
    { path: "/", user: "erin", ready: "Needs you" },
    { path: "/", user: "erin", open: { role: "button", name: "Show all", exact: false, opens: { role: "link", name: `Import ${WORST}a` } }, ready: "Needs you" },
    { path: "/", user: "bob", ready: "No archive in user-bob/packages/npm/ or packages/pip/" },
    { path: "/", user: "dave", ready: "Imports already started go on." },
    { path: "/", user: "alice", hold: "/api/archives", ready: "Reading your folders in MinIO: user-alice/packages/npm/ and packages/pip/" },
    { path: "/import", user: "alice", ready: "Not imported yet" },
    { path: "/import", user: "alice", open: { role: "button", name: "Importable", exact: false, pressed: true }, ready: "Not imported yet" },
    { path: "/import", user: "alice", open: { role: "button", name: "Start import of 2026-11-06-new-export/packages_npm.tar.gz", opens: { role: "region", name: "Start the import of 2026-11-06-new-export/packages_npm.tar.gz" } }, ready: "Not imported yet" },
    { path: "/import?start=packages/npm/2026-11-06-new-export/packages_npm.tar.gz", user: "alice", ready: "Start the import" },
    { path: "/import", user: "bob", ready: "No archive in your folder" },
    { path: "/import", user: "carol", ready: "MinIO has no bucket user-carol yet: nothing to list" },
    { path: "/import", user: "dave", ready: "The archives could not be listed" },
    { path: "/import", user: "alice", hold: "/api/archives", ready: "Reading your folders in MinIO: user-alice/packages/npm/ and packages/pip/" },
    { path: "/imports", user: "alice", ready: "Waiting its turn" },
    { path: `/imports/${IDS.completeRemoved}`, user: "alice", ready: "Archive removed from MinIO" },
    { path: `/imports/${IDS.completeKept}`, user: "alice", ready: "Archive kept in MinIO" },
    { path: `/imports/${IDS.completePending}`, user: "alice", ready: "Checking the archive's removal" },
    { path: `/imports/${IDS.incomplete}`, user: "alice", ready: "3 of 101 packages are not in Nexus" },
    { path: `/imports/${IDS.refusedDigests}`, user: "alice", ready: "Nothing reached Nexus." },
    { path: `/imports/${IDS.refusedLong}`, user: "alice", ready: "Nothing reached Nexus." },
    { path: `/imports/${IDS.refusedSignature}`, user: "alice", ready: "Nothing reached Nexus." },
    { path: `/imports/${IDS.interrupted}`, user: "alice", ready: "45 of 101 packages are not in Nexus" },
    // Queued, checking, publishing and its cancel confirm, then cancelled.
    { path: `/imports/${IDS.queued}`, user: "alice", ready: "Waiting its turn" },
    { path: `/imports/${IDS.queued}`, user: "alice", before: ranked, name: "ranked", ready: "import ahead of this one" },
    { path: `/imports/${IDS.running}`, user: "alice", before: checking, name: "checking", ready: "Checking the archive" },
    { path: `/imports/${IDS.running}`, user: "alice", ready: "Estimating time left" },
    { path: `/imports/${IDS.running}`, user: "alice", ready: "Estimating time left", open: { role: "button", name: "Compliant", opens: { role: "list", name: "3 checks passed" } } },
    { path: `/imports/${IDS.running}`, user: "alice", ready: "Estimating time left", open: { role: "button", name: "Cancel", opens: { role: "button", name: "Keep running" } } },
    { path: `/imports/${IDS.running}`, user: "alice", before: worstPublishing, name: "worst pip", ready: "3 packages failed" },
    { path: `/imports/${IDS.cancelled}`, user: "alice", ready: "Import cancelled" },
    {
      path: `/imports/${IDS.running}`, user: "alice", ready: "Estimating time left",
      open: { role: "button", name: "Earlier attempts (1)", opens: { role: "list", name: "Earlier attempts" } },
    },
    // The refused panel, one per cause the folder holds: another key, a signature that does not match, an archive
    // whose size differs, no manifest, two archives in one folder.
    ...["2026-10-31-regenerated", "2026-11-01-portal", "2026-11-05-reports", "2026-10-27-no-manifest"].map((folder) => ({
      path: `/?refused=${encodeURIComponent(`${FOLDER}${folder}/${ARCHIVE}`)}`, user: "alice", ready: "Nothing reached Nexus.",
    })),
    { path: `/?refused=${encodeURIComponent(`${FOLDER}2026-10-28-two-archives/first.tar.gz`)}`, user: "alice", ready: "Nothing reached Nexus." },
    {
      path: `/?refused=${encodeURIComponent(`${FOLDER}2026-10-31-regenerated/${ARCHIVE}`)}`, user: "alice", ready: "Nothing reached Nexus.",
      open: { role: "button", name: "Compare", opens: { role: "textbox", name: "sha256 from the connected side" } },
    },
    { path: `/imports/${IDS.legacy}`, user: "alice", ready: "Archive sha256 check" },
    { path: `/imports/${IDS.longKey}`, user: "alice", ready: "Archive sha256 check" },
    { path: `/imports/${IDS.pipComplete}`, user: "alice", ready: "Python" },
    { path: "/imports/missing-import", user: "alice", ready: "No such import" },
    { path: "/imports", user: "bob", ready: "No import yet" },
    { path: "/imports", user: "frank", ready: "Your archives in MinIO are untouched." },
    { path: "/imports", user: "alice", hold: "/api/imports", ready: "Loading your imports" },
    { path: "/instance", user: "alice", ready: "user-alice" },
    { path: "/instance", user: "alice", open: { role: "button", name: "Compare", opens: { role: "textbox", name: "sha256 from the connected side" } }, ready: "user-alice" },
  ],
}

// The trusted key and its sha256, set once the run's key is generated: the reports the store writes
// carry the sha256, and the listed manifests are signed with the key.
let trustedKeySha = ""
let trustedKey
let otherKey
const sha = (text) => createHash("sha256").update(text).digest("hex")
const iso = (id) => {
  const [stamp] = id.split("-")
  return `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`
}
const later = (time, minutes) => new Date(Date.parse(time) + minutes * 60_000).toISOString().replace(".000Z", "Z")

function pkg(i, state, extra = {}) {
  const name = `package-${String(i).padStart(3, "0")}`
  return { name, version: "1.0.0", file: `npm/${name}/-/${name}-1.0.0.tgz`, state, reason: "", note: "", ...extra }
}

function packages(total, published, present, failures = []) {
  const out = []
  for (let i = 0; i < published; i++) out.push(pkg(i, "published"))
  for (let i = 0; i < present; i++) out.push(pkg(published + i, "present", { note: "Nexus already holds these bytes" }))
  for (const f of failures) out.push(pkg(out.length, f.state ?? "failed", f))
  while (out.length < total) out.push(pkg(out.length, "pending"))
  return out
}

function counted(list) {
  const n = (state) => list.filter((p) => p.state === state).length
  return { published: n("published"), present: n("present"), failed: n("failed") }
}

function report(outcome, list, over = {}) {
  return {
    outcome, reason: "", unencrypted: true, importVersion: "0.5.0",
    archive: { file: ARCHIVE, sha256: sha(`archive-${list.length}-${outcome}`), size: 5_500_000 },
    toolVersion: "0.4.0", analysisId: "20261101T090000Z",
    target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" },
    nexus: { url: "http://127.0.0.1:18093", repository: "npm-gate" },
    counts: counted(list), packages: list, archiveChecked: true, publicKeySha256: trustedKeySha, ...over,
  }
}

// The report the store writes for an attempt that waits: every field at its zero value, no archiveChecked.
const queuedReport = () => ({
  outcome: "", reason: "", unencrypted: false, importVersion: "",
  archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
  target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" },
  nexus: { url: "", repository: "" }, counts: { published: 0, present: 0, failed: 0 }, packages: [],
})

function ended(n, createdAt, outcome, list, over = {}, removal) {
  const queuedAt = later(createdAt, n === 1 ? 0 : 60)
  const attempt = {
    n, status: "ended", queuedAt, startedAt: later(queuedAt, 1), endedAt: later(queuedAt, 9),
    outcome, report: report(outcome, list, over),
  }
  if (removal) attempt.removal = removal
  return attempt
}

function record(id, folder, attempts, over = {}) {
  const root = over.root ?? FOLDER
  // npm records keep the ETags they had before the pip folder joined.
  const tag = over.root ? root + folder : folder
  const archiveKey = over.archiveKey ?? `${root}${folder}${over.archive ?? ARCHIVE}`
  return {
    formatVersion: 1, id, user: "alice", createdAt: iso(id),
    archive: { key: archiveKey, etag: `"${sha(archiveKey).slice(0, 32)}"`, size: 5_500_000 },
    manifest: { key: `${root}${folder}manifest.json`, etag: `"${sha(tag).slice(0, 32)}"`, size: 1_200 },
    // A record written by v0.4.0 holds no signature: its folder has none either.
    signature: over.unsigned ? undefined : { key: `${root}${folder}manifest.json.sig`, etag: `"${sha(`${tag}sig`).slice(0, 32)}"`, size: 400 },
    expectedSha256: over.expectedSha256 ?? "", attempts,
  }
}

// A complete pip import as the import writes it: the ecosystem, the Python target, no npm field.
function pipRecord() {
  const createdAt = iso(IDS.pipComplete)
  const wheel = (name, version, file, state) => ({ name, version, file, state, reason: "", note: state === "present" ? "Nexus already holds these bytes" : "" })
  const wheels = [
    wheel("six", "1.16.0", "six-1.16.0-py2.py3-none-any.whl", "published"),
    wheel("idna", "3.10", "idna-3.10-py3-none-any.whl", "present"),
    wheel("markupsafe", "2.1.5", "MarkupSafe-2.1.5-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "published"),
  ]
  const over = {
    archive: { file: PIP_ARCHIVE, sha256: sha("pip-archive"), size: 81_920 },
    toolVersion: "0.7.0", analysisId: "20261020T083000Z", ecosystem: "pip",
    target: { os: "linux", cpu: "x86_64", libc: "", node: "", pnpmVer: "", python: "3.11.2", glibc: "2.28" },
    nexus: { url: "http://127.0.0.1:18093", repository: "pypi-gate" },
  }
  return record(IDS.pipComplete, "2026-10-20-data-tools/", [ended(1, createdAt, "complete", wheels, over, { removed: true, reason: "" })], { root: PIP_FOLDER, archive: PIP_ARCHIVE })
}

const longReason = (lead) => `${lead} ${"nexus said no ".repeat(40)}${"x".repeat(1000)}`.slice(0, 1000)

// Alice's records, newest first. Each state the mockups draw has one.
function aliceRecords() {
  const queuedAt = iso(IDS.queued)
  const runningAt = iso(IDS.running)
  const removed = { removed: true, reason: "" }
  const kept = { removed: false, reason: "the archive's ETag changed after the import read it" }
  const digestReason = `the archive's sha256 is ${sha("changed")} but the expected sha256 is ${sha("expected")}`
  const signatureReason = `the manifest is signed by another key, public key sha256 ${sha("other key")}; this import trusts ${trustedKeySha}. If the connected side regenerated its key, carry its new public key here; otherwise export the archive again`
  const longFolder = "k".repeat(1024 - FOLDER.length - 1 - ARCHIVE.length)
  const longKey = `${FOLDER}${longFolder}/${ARCHIVE}`
  if (longKey.length !== 1024) throw new Error(`the long key holds ${longKey.length} bytes, not 1024`)

  const failures = [
    { kind: "conflict", reason: "Nexus holds package-100@1.0.0 with other bytes" },
    { kind: "nexus", reason: longReason("Nexus answered 500 for package-101@1.0.0:") },
    { kind: "source", reason: "MinIO cut the read of the archive" },
  ]
  return [
    record(IDS.completeToday, "kiosk-ui-today/", [ended(1, iso(IDS.completeToday), "complete", packages(120, 100, 20), {}, removed)]),
    record(IDS.queued, "2026-11-06-intranet-portal/", [
      { n: 1, status: "queued", queuedAt, outcome: "", report: queuedReport() },
    ]),
    record(IDS.running, "2026-11-06-billing-api/", [
      ended(1, runningAt, "incomplete", packages(101, 60, 30, [{ kind: "nexus", reason: "Nexus answered 503" }])),
      { n: 2, status: "running", queuedAt: later(runningAt, 60), startedAt: later(runningAt, 61), outcome: "", report: report("", packages(101, 37, 0)) },
    ]),
    record(IDS.completeRemoved, "2026-11-05-hr-forms/", [ended(1, iso(IDS.completeRemoved), "complete", packages(101, 80, 21), {}, removed)]),
    record(IDS.completeKept, "2026-11-05-kiosk-ui/", [ended(1, iso(IDS.completeKept), "complete", packages(60, 50, 10), {}, kept)]),
    record(IDS.completePending, "2026-11-05-reports/", [ended(1, iso(IDS.completePending), "complete", packages(40, 30, 10))]),
    record(IDS.incomplete, "2026-11-04-maps-viewer/", [
      ended(1, iso(IDS.incomplete), "incomplete", packages(101, 40, 58, failures), { reason: "3 packages failed" }),
    ]),
    record(IDS.refusedDigests, "2026-11-03-docs-site/", [
      ended(1, iso(IDS.refusedDigests), "refused", [], { reason: digestReason, archiveChecked: false }),
    ], { expectedSha256: sha("expected") }),
    record(IDS.interrupted, "2026-11-02-payments/", [
      ended(1, iso(IDS.interrupted), "interrupted", packages(101, 52, 4, Array.from({ length: 45 }, () => ({ kind: "interrupted", reason: "interrupted" }))), { reason: "interrupted" }),
    ]),
    record(IDS.refusedLong, "2026-11-01-portal/", [
      ended(1, iso(IDS.refusedLong), "refused", [], { reason: longReason("the manifest refused the archive:"), archiveChecked: false }),
    ]),
    record(IDS.legacy, "2026-10-30-legacy-site/", [
      // A record written by v0.4.0: no kind on a failed package, no archiveChecked, no public key sha256.
      ended(1, iso(IDS.legacy), "incomplete", packages(12, 8, 2, [{ reason: "Nexus answered 500" }, { reason: "interrupted" }]), { archiveChecked: undefined, publicKeySha256: undefined }),
    ], { unsigned: true }),
    record(IDS.refusedSignature, "2026-10-31-regenerated/", [
      ended(1, iso(IDS.refusedSignature), "refused", [], { reason: signatureReason, archiveChecked: false }),
    ]),
    record(IDS.longKey, `${longFolder}/`, [ended(1, iso(IDS.longKey), "complete", packages(30, 20, 10))], { archiveKey: longKey }),
    pipRecord(),
    record(IDS.cancelled, "2026-11-07-search-indexer/", [
      { ...ended(1, iso(IDS.cancelled), "cancelled", packages(101, 40, 20, Array.from({ length: 41 }, () => ({ kind: "interrupted", reason: "cancelled before it was published" })))), outcome: "cancelled" },
    ]),
  ]
}

const xml = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

function listing(bucket, prefix, objects, truncated = false) {
  const items = objects
    .map((o) => `<Contents><Key>${xml(o.key)}</Key><LastModified>${o.modified ?? "2026-11-06T08:00:00.000Z"}</LastModified><ETag>${xml(o.etag)}</ETag><Size>${o.size}</Size></Contents>`)
    .join("")
  return `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>${bucket}</Name><Prefix>${xml(prefix)}</Prefix><KeyCount>${objects.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>${truncated}</IsTruncated>${items}</ListBucketResult>`
}

const tag = (body) => `"${sha(body).slice(0, 32)}"`

// A manifest as the connected side seals it: an archive of size bytes, three packages, and a review
// naming project when one is given (a 0.7.0 export carries none).
function manifestFor(eco, size, createdAt, project) {
  const packages = [0, 1, 2].map((i) => {
    const name = `package-${i}`
    const digest = createHash("sha512").update(name).digest()
    return eco === "pip"
      ? { name, version: "1.0.0", file: `${name.replace("-", "_")}-1.0.0-py3-none-any.whl`, sha256: sha(name), shippedSha512: digest.toString("hex") }
      : { name, version: "1.0.0", file: `${name}-1.0.0.tgz`, originalIntegrity: `sha512-${digest.toString("base64")}`, shippedSha512: digest.toString("hex"), publishConfigStripped: false }
  })
  const target = eco === "pip" ? { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.9.2" } : { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" }
  const doc = { formatVersion: eco === "pip" ? 3 : 2, ...(eco === "pip" ? { ecosystem: "pip" } : {}), toolVersion: "0.8.0", analysisId: "20261125T085500Z", createdAt, target, archive: { sha256: sha(`archive${size}`), size }, packages }
  if (project) doc.review = { project, cves: { before: [0, 1, 0, 0, 0] } }
  return Buffer.from(JSON.stringify(doc))
}

const signatureFile = (signed, key, keySha) => Buffer.from(`${JSON.stringify({ algorithm: "ed25519", publicKeySha256: keySha, signature: sign(null, signed, key.privateKey).toString("base64") }, null, 2)}\n`)

// Gives each listed manifest and signature its bytes, sealed as the connected side does: the usual
// archive names its project, and a few folders keep each way a check fails.
function seal(objects) {
  for (const m of objects.filter((o) => o.key.endsWith("/manifest.json"))) {
    const folder = m.key.slice(0, -"manifest.json".length)
    const archive = objects.find((o) => o.key.startsWith(folder) && o.key.endsWith(".tar.gz") && !o.key.slice(folder.length).includes("/"))
    const sig = objects.find((o) => o.key === `${folder}manifest.json.sig`)
    const name = folder.split("/").at(-2)
    const project = name.replace(/^\d{4}-\d{2}-\d{2}-/, "").slice(0, 40)
    const eco = folder.startsWith(PIP_FOLDER) ? "pip" : "npm"
    const at = m.modified ?? "2026-11-06T08:00:00.000Z"
    // A 0.7.0 export carries no review; another folder states a size its archive does not have.
    const body = manifestFor(eco, (archive?.size ?? 1) + (name === "2026-11-05-reports" ? 1 : 0), at, name === "2026-11-02-payments" ? "" : project)
    Object.assign(m, { body, size: body.length, etag: tag(body) })
    if (!sig) continue
    // Signed by a regenerated key, or signed over other bytes.
    const sigBody = name === "2026-10-31-regenerated" ? signatureFile(body, otherKey, otherKey.sha) : signatureFile(name === "2026-11-01-portal" ? Buffer.concat([body, Buffer.from(" ")]) : body, trustedKey, trustedKeySha)
    Object.assign(sig, { body: sigBody, size: sigBody.length, etag: tag(sigBody) })
  }
  return objects
}

// Sixteen crossings of one user, two of them the same project on the same day.
function worstObjects() {
  const objects = []
  for (let i = 0; i < 16; i++) {
    const project = `${WORST}${String.fromCharCode(97 + Math.min(i, 14))}`
    const day = String(Math.min(5 + i, 19)).padStart(2, "0")
    // The last folder repeats the project before it; its name is cut back to the same 40 characters.
    const folder = `${FOLDER}2026-11-${day}-${project}${i === 15 ? "-again" : ""}/`
    const modified = `2026-11-${day}T${i === 15 ? "15" : "09"}:00:00.000Z`
    objects.push({ key: `${folder}${ARCHIVE}`, etag: tag(folder), size: 4_000_000 + i * 1000, modified })
    objects.push({ key: `${folder}manifest.json`, modified }, { key: `${folder}manifest.json.sig`, modified })
  }
  return seal(objects)
}

const s3Error = (code, message) => `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`

// What alice's bucket holds, its manifests and signatures with their bytes.
function aliceObjects() {
  const objects = aliceRecords()
    .filter((r) => r.id !== IDS.completeRemoved && r.id !== IDS.pipComplete && r.id !== IDS.completeToday)
    .flatMap((r) => [r.archive, r.manifest, r.signature].filter(Boolean).map((o) => ({ ...o, modified: `${iso(r.id).slice(0, -1)}.000Z` })))
  const upload = (folder, name, size, modified = "2026-11-06T08:00:00.000Z") => objects.push({ key: `${FOLDER}${folder}${name}`, etag: `"${sha(folder + name).slice(0, 32)}"`, size, modified })
  // Archives the service cannot import, one for each rule, and a 200-character folder.
  upload("2026-11-06-new-export/", ARCHIVE, 4_200_000)
  upload("2026-11-06-new-export/", "manifest.json", 1_100)
  upload("2026-11-06-new-export/", "manifest.json.sig", 400)
  upload("2026-10-28-two-archives/", "first.tar.gz", 3_000_000, "2026-10-28T08:00:00.000Z")
  upload("2026-10-28-two-archives/", "second.tar.gz", 3_100_000, "2026-10-28T08:01:00.000Z")
  upload("2026-10-28-two-archives/", "manifest.json", 900, "2026-10-28T08:02:00.000Z")
  upload("2026-10-28-two-archives/", "manifest.json.sig", 400, "2026-10-28T08:02:00.000Z")
  upload("2026-10-27-no-manifest/", ARCHIVE, 2_900_000, "2026-10-27T08:00:00.000Z")
  upload("2026-10-26/too/deep/", ARCHIVE, 2_800_000, "2026-10-26T08:00:00.000Z")
  const wide = `${"w".repeat(200)}/`
  upload(wide, ARCHIVE, 2_700_000, "2026-10-25T08:00:00.000Z")
  upload(wide, "manifest.json", 800, "2026-10-25T08:00:00.000Z")
  upload(wide, "manifest.json.sig", 400, "2026-10-25T08:00:00.000Z")
  // A pip export not imported yet: its archive, its manifest and its signature.
  const pip = (name, size) => objects.push({ key: `${PIP_FOLDER}2026-11-20-data-tools/${name}`, etag: `"${sha(`pip${name}`).slice(0, 32)}"`, size, modified: "2026-11-20T08:00:00.000Z" })
  pip(PIP_ARCHIVE, 81_920)
  pip("manifest.json", 1_342)
  pip("manifest.json.sig", 214)
  return seal(objects)
}

// Each user's objects, for the reads of one object.
const objectsOf = (bucket) => ({ "user-alice": aliceObjects, "user-erin": worstObjects, "user-gina": () => worstObjects().slice(0, 3) })[bucket]?.() ?? []

// What each user's bucket answers for a prefix: alice lists her archives in both folders, bob empty
// folders, carol has no bucket, dave's MinIO fails, frank lists nothing.
function minioAnswer(bucket, prefix) {
  switch (bucket) {
    case "user-alice": {
      const objects = aliceObjects()
      const mine = objects.filter((o) => o.key.startsWith(prefix))
      return [200, listing(bucket, prefix, mine, prefix === FOLDER)]
    }
    case "user-erin":
    case "user-gina":
      return [200, listing(bucket, prefix, objectsOf(bucket).filter((o) => o.key.startsWith(prefix)))]
    case "user-bob":
    case "user-frank":
      return [200, listing(bucket, prefix, [])]
    case "user-dave":
      return [500, s3Error("InternalError", "We encountered an internal error. Please try again.")]
    default:
      return [404, s3Error("NoSuchBucket", "The specified bucket does not exist")]
  }
}

const listen = (server, port) =>
  new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(port, "127.0.0.1", () => resolve())
  })

const b64 = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url")

/**
 * Starts the key set and the fake MinIO, writes the settings file under dir and returns the handles
 * the gate needs. seed() writes the records once the server answers, because the server's start
 * ends every queued or running attempt it finds as interrupted.
 */
export async function startImportFixtures(dir) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" }

  const keySet = createServer((req, res) => {
    if (req.url === "/certs") {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ keys: [jwk] }))
      return
    }
    res.writeHead(404).end()
  })
  const minio = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1")
    const bucket = url.pathname.replace(/^\//, "").split("/")[0]
    const key = decodeURIComponent(url.pathname.replace(/^\/[^/]+\//, ""))
    const object = req.method === "GET" && !url.search ? objectsOf(bucket).find((o) => o.key === key && o.body) : undefined
    if (object) {
      if (req.headers["if-match"] !== undefined && req.headers["if-match"] !== object.etag) {
        res.writeHead(412, { "Content-Type": "application/xml" }).end(s3Error("PreconditionFailed", "At least one of the pre-conditions you specified did not hold"))
        return
      }
      res.writeHead(200, { "Content-Length": object.body.length, ETag: object.etag, "Last-Modified": new Date(object.modified).toUTCString() }).end(object.body)
      return
    }
    if (req.method !== "GET" || url.searchParams.get("list-type") !== "2") {
      res.writeHead(405, { "Content-Type": "application/xml" }).end(s3Error("MethodNotAllowed", "only listings are served"))
      return
    }
    const [status, body] = minioAnswer(bucket, url.searchParams.get("prefix") ?? "")
    res.writeHead(status, { "Content-Type": "application/xml" }).end(body)
  })
  await listen(keySet, KEY_SET_PORT)
  await listen(minio, MINIO_PORT)

  const files = { "nexus-password": "gate-nexus-password", "minio-access": "gate-access", "minio-secret": "gate-secret" }
  mkdirSync(dir, { recursive: true })
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), `${text}\n`)
  // The trusted key is generated per run: the gate holds no fixed key.
  trustedKey = generateKeyPairSync("ed25519")
  const trusted = trustedKey.publicKey
  trustedKeySha = sha(trusted.export({ type: "spki", format: "der" }))
  otherKey = generateKeyPairSync("ed25519")
  otherKey.sha = sha(otherKey.publicKey.export({ type: "spki", format: "der" }))
  writeFileSync(join(dir, "public-key.pem"), trusted.export({ type: "spki", format: "pem" }))
  const settings = join(dir, "settings.yaml")
  writeFileSync(
    settings,
    [
      "nexus:",
      "  url: http://127.0.0.1:18093",
      "  repository: npm-gate",
      "  user: importer",
      "  passwordFile: nexus-password",
      "  pip:",
      "    repository: pypi-gate",
      "publicKeyFile: public-key.pem",
      "token:",
      `  keySetUrl: http://127.0.0.1:${KEY_SET_PORT}/certs`,
      `  issuer: ${ISSUER}`,
      `  audience: ${AUDIENCE}`,
      "minio:",
      `  url: http://127.0.0.1:${MINIO_PORT}`,
      "  region: us-east-1",
      "  accessKeyFile: minio-access",
      "  secretKeyFile: minio-secret",
      "",
    ].join("\n"),
  )
  const data = join(dir, "data")
  mkdirSync(data, { recursive: true })

  const folderOf = (user) => join(data, "imports", user)
  return {
    settings,
    data,
    token(user) {
      const head = b64({ alg: "RS256", kid: KID, typ: "JWT" })
      const claims = b64({ iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 3600, preferred_username: user })
      const sign = createSign("RSA-SHA256").update(`${head}.${claims}`)
      return `${head}.${claims}.${sign.sign(privateKey).toString("base64url")}`
    },
    async seed() {
      for (const rec of aliceRecords()) {
        const folder = join(folderOf("alice"), rec.id)
        mkdirSync(folder, { recursive: true })
        // A field set to undefined is left out of the JSON, as an old record lacks it.
        writeFileSync(join(folder, "import.json"), `${JSON.stringify(rec, null, 2)}\n`)
      }
      // The folder exists but cannot be listed, so the list answers 500.
      mkdirSync(folderOf("frank"), { recursive: true })
      chmodSync(folderOf("frank"), 0o000)
    },
    async close() {
      // The folder must be readable again for the directory to be removed.
      try {
        chmodSync(folderOf("frank"), 0o700)
      } catch {}
      await Promise.all([keySet, minio].map((s) => new Promise((done) => (s.closeAllConnections(), s.close(done)))))
    },
  }
}
