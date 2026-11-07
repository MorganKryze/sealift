// Fixtures for the import role in the browser gate: a realm's key set, a fake MinIO, a settings file,
// a token per user and the import records of every state the screens draw. The server under test is
// the shipped binary with its token check on; nothing here switches that check off.
import { createHash, createSign, generateKeyPairSync } from "node:crypto"
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

// One id per state alice's records show. The gate's routes name them.
export const IDS = {
  queued: "20261106T093000Z-a1000001",
  running: "20261106T091000Z-a1000002",
  completeRemoved: "20261105T161200Z-a1000003",
  completeKept: "20261105T110000Z-a1000004",
  completePending: "20261105T090000Z-a1000005",
  incomplete: "20261104T142000Z-a1000006",
  refusedDigests: "20261103T101500Z-a1000007",
  interrupted: "20261102T090500Z-a1000008",
  refusedLong: "20261101T120000Z-a1000009",
  legacy: "20261030T080000Z-a100000a",
  longKey: "20261020T170000Z-a100000b",
}

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
    counts: counted(list), packages: list, archiveChecked: true, ...over,
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
  const archiveKey = over.archiveKey ?? `${FOLDER}${folder}${ARCHIVE}`
  return {
    formatVersion: 1, id, user: "alice", createdAt: iso(id),
    archive: { key: archiveKey, etag: `"${sha(archiveKey).slice(0, 32)}"`, size: 5_500_000 },
    manifest: { key: `${FOLDER}${folder}manifest.json`, etag: `"${sha(folder).slice(0, 32)}"`, size: 1_200 },
    expectedSha256: over.expectedSha256 ?? "", attempts,
  }
}

const longReason = (lead) => `${lead} ${"nexus said no ".repeat(40)}${"x".repeat(1000)}`.slice(0, 1000)

// Alice's records, newest first. Each state the mockups draw has one.
function aliceRecords() {
  const queuedAt = iso(IDS.queued)
  const runningAt = iso(IDS.running)
  const removed = { removed: true, reason: "" }
  const kept = { removed: false, reason: "the archive's ETag changed after the import read it" }
  const digestReason = `the archive's sha256 is ${sha("changed")} but the expected sha256 is ${sha("expected")}`
  const longFolder = "k".repeat(1024 - FOLDER.length - 1 - ARCHIVE.length)
  const longKey = `${FOLDER}${longFolder}/${ARCHIVE}`
  if (longKey.length !== 1024) throw new Error(`the long key holds ${longKey.length} bytes, not 1024`)

  const failures = [
    { kind: "conflict", reason: "Nexus holds package-100@1.0.0 with other bytes" },
    { kind: "nexus", reason: longReason("Nexus answered 500 for package-101@1.0.0:") },
    { kind: "source", reason: "MinIO cut the read of the archive" },
  ]
  return [
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
      // A record written by v0.4.0: no kind on a failed package, no archiveChecked.
      ended(1, iso(IDS.legacy), "incomplete", packages(12, 8, 2, [{ reason: "Nexus answered 500" }, { reason: "interrupted" }]), { archiveChecked: undefined }),
    ]),
    record(IDS.longKey, `${longFolder}/`, [ended(1, iso(IDS.longKey), "complete", packages(30, 20, 10))], { archiveKey: longKey }),
  ]
}

const xml = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

function listing(bucket, objects, truncated = false) {
  const items = objects
    .map((o) => `<Contents><Key>${xml(o.key)}</Key><LastModified>${o.modified ?? "2026-11-06T08:00:00.000Z"}</LastModified><ETag>${xml(o.etag)}</ETag><Size>${o.size}</Size></Contents>`)
    .join("")
  return `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>${bucket}</Name><Prefix>${FOLDER}</Prefix><KeyCount>${objects.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>${truncated}</IsTruncated>${items}</ListBucketResult>`
}

const s3Error = (code, message) => `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`

// What each user's bucket answers: alice lists her archives, bob an empty folder, carol has no bucket,
// dave's MinIO fails, frank lists nothing.
function minioAnswer(bucket) {
  switch (bucket) {
    case "user-alice": {
      const objects = aliceRecords()
        .filter((r) => r.id !== IDS.completeRemoved)
        .flatMap((r) => [{ ...r.archive, modified: `${iso(r.id).slice(0, -1)}.000Z` }, { ...r.manifest, modified: `${iso(r.id).slice(0, -1)}.000Z` }])
      const upload = (folder, name, size, modified = "2026-11-06T08:00:00.000Z") => objects.push({ key: `${FOLDER}${folder}${name}`, etag: `"${sha(folder + name).slice(0, 32)}"`, size, modified })
      // Archives the service cannot import, one for each rule, and a 200-character folder.
      upload("2026-11-06-new-export/", ARCHIVE, 4_200_000)
      upload("2026-11-06-new-export/", "manifest.json", 1_100)
      upload("2026-10-28-two-archives/", "first.tar.gz", 3_000_000, "2026-10-28T08:00:00.000Z")
      upload("2026-10-28-two-archives/", "second.tar.gz", 3_100_000, "2026-10-28T08:01:00.000Z")
      upload("2026-10-28-two-archives/", "manifest.json", 900, "2026-10-28T08:02:00.000Z")
      upload("2026-10-27-no-manifest/", ARCHIVE, 2_900_000, "2026-10-27T08:00:00.000Z")
      upload("2026-10-26/too/deep/", ARCHIVE, 2_800_000, "2026-10-26T08:00:00.000Z")
      const wide = `${"w".repeat(200)}/`
      upload(wide, ARCHIVE, 2_700_000, "2026-10-25T08:00:00.000Z")
      upload(wide, "manifest.json", 800, "2026-10-25T08:00:00.000Z")
      return [200, listing(bucket, objects, true)]
    }
    case "user-bob":
    case "user-frank":
      return [200, listing(bucket, [])]
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
    if (req.method !== "GET" || url.searchParams.get("list-type") !== "2") {
      res.writeHead(405, { "Content-Type": "application/xml" }).end(s3Error("MethodNotAllowed", "only listings are served"))
      return
    }
    const [status, body] = minioAnswer(bucket)
    res.writeHead(status, { "Content-Type": "application/xml" }).end(body)
  })
  await listen(keySet, KEY_SET_PORT)
  await listen(minio, MINIO_PORT)

  const files = { "nexus-password": "gate-nexus-password", "signature.key": "gate-signature-key", "minio-access": "gate-access", "minio-secret": "gate-secret" }
  mkdirSync(dir, { recursive: true })
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), `${text}\n`)
  const settings = join(dir, "settings.yaml")
  writeFileSync(
    settings,
    [
      "nexus:",
      "  url: http://127.0.0.1:18093",
      "  repository: npm-gate",
      "  user: importer",
      "  passwordFile: nexus-password",
      "signatureKeyFile: signature.key",
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
