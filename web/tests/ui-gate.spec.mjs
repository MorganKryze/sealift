// UI gate: every route at every width, in light and dark, checked for serious or critical axe
// findings, horizontal page overflow, visible controls under the target size, and a dark theme that
// differs from the light one. Each failure names the route, width, theme and selector.
// Needs @playwright/test and @axe-core/playwright (dev dependencies). The run builds the web and one
// sealift binary, then starts both roles from it: the collection through `start` when nothing answers
// at baseURL, and the import server with its token check on (see import-fixtures.mjs). No start
// command, or a missing package, fails the run: it never skips. No screenshot diff, no clock, no
// random input. Fill the blocks below; `exceptions` take a selector, the check they lift and the reason.
// With UI_CAPTURES set to a folder, each page is saved there once checked, as
// <role>-<route slug>-<width>-<theme>.png, for a reader to compare with the drawn screens.
// Each module of tests/gate/ may export `routes`, `states`, `sessions` and `answers`, appended to UI's
// lists below, so the states of one screen live in their own file.

// GET /api/instance as the collection server answered it on an empty volume, with its stand-in upstream
// answering 404 to everything: Trivy, pnpm and uv failed once and wait for their next try. Captured once
// from the real server; the seeded volume is ready, so the gate shows this state through `answers`.
const PREPARING = {
  "brand": {
    "logo": false,
    "name": "sealift",
    "offline": "Offline",
    "online": "Online",
    "reviewWord": "PR"
  },
  "ephemeral": false,
  "policy": {
    "downloadParallelism": 16,
    "minReleaseAgeDays": 14,
    "pipTarget": {
      "cpu": "x86_64",
      "glibc": "2.28",
      "os": "linux",
      "python": "3.11.2",
      "uvVer": "0.13.7"
    },
    "resolveParallelism": 4,
    "review": {
      "cveWithoutFix": "reason",
      "majorJump": "reason",
      "proposeOtherMajors": false
    },
    "target": {
      "cpu": "x64",
      "libc": "glibc",
      "node": "22.17.1",
      "os": "linux",
      "pnpmVer": "10.34.5"
    }
  },
  "preparing": [
    {
      "name": "trivy",
      "nextTry": "2026-11-24T12:09:45.79156+01:00",
      "reason": "could not reach GitHub to look up Trivy releases: release 0.76.2: GET http://127.0.0.1:56403/repos/aquasecurity/trivy/releases/tags/v0.76.2: 404 Not Found",
      "state": "failed",
      "version": "0.76.2"
    },
    {
      "name": "trivy-db",
      "state": "preparing"
    },
    {
      "name": "signing-key",
      "state": "ready",
      "version": "ef1bea90874fe11f644bbcad4acda3214dce976a0908b6b7f0b395b1673d46f8"
    },
    {
      "name": "pnpm",
      "nextTry": "2026-11-24T12:09:45.793535+01:00",
      "reason": "pnpm packument: packument pnpm: not found in registry",
      "state": "failed",
      "version": "10.34.5"
    },
    {
      "name": "uv",
      "nextTry": "2026-11-24T12:09:45.792933+01:00",
      "reason": "uv 0.13.7: pip: not found on the index",
      "state": "failed",
      "version": "0.13.7"
    }
  ],
  "ready": false,
  "tools": {
    "pnpm": [],
    "trivy": "0.76.2",
    "uv": []
  }
}

// The failed items' next try, moved 42 s past the moment the page asks, so the page shows the delay as it would live.
const preparingNow = () => ({
  ...PREPARING,
  preparing: PREPARING.preparing.map((item) => (item.nextTry ? { ...item, nextTry: new Date(Date.now() + 42_000).toISOString() } : item)),
})

// Ready with a warning, as the preparer answers when a refresh fails on an existing database
// (internal/tools/ready.go): every item ready, the database at its older date.
const READY_WITH_WARNING = {
  ...PREPARING,
  ready: true,
  warning: "could not refresh the vulnerability database: dial tcp: lookup ghcr.io: no such host; using the database from 2026-11-22",
  preparing: PREPARING.preparing.map(({ reason, nextTry, ...item }) => ({
    ...item,
    state: "ready",
    ...(item.name === "trivy-db" ? { version: "2026-11-22T06:12:00Z" } : {}),
  })),
}

// The package.json files the Check step's states drop, written under test-results/ before the run. Real
// names where the design rules' worst cases name them; the rest numbered, since only their count matters.
const FILES = resolve("test-results", "gate", "files")
const fileAt = (name) => join(FILES, name)
const pinned = (count, prefix, from = 0) =>
  Object.fromEntries(Array.from({ length: count }, (_, i) => [`${prefix}-${String(i + from).padStart(3, "0")}`, `${1 + (i % 9)}.${i % 23}.${i % 7}`]))
const WORST_PACKAGES = {
  "@babel/plugin-transform-async-generator-functions": "1.0.0-beta.12+build.345",
  "@typescript-eslint/eslint-plugin": "8.18.0",
  "@typescript-eslint/parser": "8.18.0",
  "@storybook/addon-interactions": "8.4.7",
  "@testing-library/react-hooks": "8.0.1",
  typescript: "0.0.0-insiders.20251101",
}
const CHECK_FILES = {
  "web-portal/package.json": { name: "web-portal", version: "2.4.0", dependencies: pinned(139, "portal-lib"), devDependencies: pinned(11, "portal-tool") },
  "billing-api/package.json": {
    name: "billing-api",
    dependencies: {
      ...pinned(76, "billing-lib"),
      express: "^4.18.2",
      lodash: "~4.17.21",
      pino: ">=9.0.0",
      "@billing/shared-schemas": "git+ssh://git@gitlab.example.com/billing/shared-schemas.git#v3.2.0",
      "pdf-templates": "file:../pdf-templates",
    },
    devDependencies: pinned(3, "billing-tool"),
    pnpm: { overrides: { semver: "7.5.4", "tough-cookie": "4.1.3", ws: "8.17.1" } },
  },
  "kiosk-ui/package.json": { name: "kiosk-ui", dependencies: Object.fromEntries(Object.entries(pinned(150, "kiosk-lib")).map(([name, version]) => [name, `^${version}`])) },
  "long-name/package.json": {
    name: "customer-onboarding-portal-frontend-next",
    dependencies: { ...WORST_PACKAGES, ...pinned(134, "onboarding-lib") },
    devDependencies: pinned(10, "onboarding-tool"),
  },
}
const writeCheckFiles = () => {
  for (const [name, body] of Object.entries(CHECK_FILES)) {
    mkdirSync(dirname(fileAt(name)), { recursive: true })
    writeFileSync(fileAt(name), `${JSON.stringify(body, null, 2)}\n`)
  }
  writeFileSync(fileAt("kiosk-ui-export.zip"), "PK\u0003\u0004")
}

// POST /api/projects held until the page closes, so the page stays on Starting.
const holdStart = (page) =>
  page.route((url) => url.pathname === "/api/projects", (route) =>
    route.request().method() === "POST" ? new Promise((done) => page.once("close", done)).then(() => route.abort().catch(() => {})) : route.fallback())
// POST /api/projects answered 503 with the contract's Problem body, as a proxy in front of a stopped server would.
const refuseStart = (page) =>
  page.route((url) => url.pathname === "/api/projects", (route) =>
    route.request().method() === "POST"
      ? route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({ type: "about:blank", title: "Service Unavailable", status: 503 }) })
      : route.fallback())

const CHECK_STATES = [
  { path: "/update", name: "a wrong file", file: fileAt("kiosk-ui-export.zip"), ready: "Drop the package.json at your project's root; nothing was sent." },
  { path: "/update", name: "compliant", file: fileAt("web-portal/package.json"), ready: "Compliant" },
  {
    path: "/update",
    name: "compliant open",
    file: fileAt("web-portal/package.json"),
    click: [{ role: "button", name: "Compliant" }, { role: "button", name: /^150 packages/ }],
    ready: "3 checks passed",
  },
  { path: "/update", name: "issues", file: fileAt("billing-api/package.json"), ready: "3 checks to fix first" },
  { path: "/update", name: "150 ranges", file: fileAt("kiosk-ui/package.json"), click: [{ role: "button", name: "Show all 150 packages" }], ready: "1 check to fix first" },
  {
    path: "/update",
    name: "a 40-character name with 150 packages",
    file: fileAt("long-name/package.json"),
    click: [{ role: "button", name: "Compliant" }, { role: "button", name: /^150 packages/ }, { role: "button", name: "Show all 150 packages" }],
    ready: "3 checks passed",
  },
  { path: "/update", name: "starting", before: holdStart, file: fileAt("web-portal/package.json"), click: [{ role: "button", name: "Analyse" }], ready: "Starting" },
  { path: "/update", name: "a failed start", before: refuseStart, file: fileAt("web-portal/package.json"), click: [{ role: "button", name: "Analyse" }], ready: "Analysis did not start" },
]

// The review's states. A selection and its reasons are written to sessionStorage before the page loads,
// as the review keeps them there.
const stored = (storage) => (page) =>
  page.addInitScript((entries) => {
    for (const [key, value] of Object.entries(entries)) sessionStorage.setItem(key, JSON.stringify(value))
  }, storage)
const WORST_SELECTION = {
  react: ["19.2.0"], "react-dom": ["19.2.0"], "@types/react": ["19.2.2"], "@types/react-dom": ["19.2.2"], "react-router-dom": ["7.9.4"],
  "@testing-library/react": ["16.3.0"], "react-redux": ["9.2.0"], eslint: ["9.38.0"], "eslint-plugin-react-hooks": ["5.2.0"],
  "@typescript-eslint/parser": ["8.46.1"], "@typescript-eslint/eslint-plugin": ["8.46.1"], "eslint-config-prettier": ["10.1.8"],
  vite: ["7.1.12"], "@vitejs/plugin-react": ["5.1.0"], vitest: ["4.0.8"],
}
const worstReview = stored({
  "sealift:selection:20261125T091500Z": WORST_SELECTION,
  "sealift:reasons:20261125T091500Z": {
    "major-jump:react 19": "Moved to React 19 in branch react-19, all tests green",
    "major-jump:eslint 9": "Flat config done in PR #412, lint passes on main",
    "major-jump:vite 7": "CI and every dev machine run Node 22; Vite 7 builds the app",
    "cve-without-fix:html-minifier": "Dev dependency, runs at build time on our own HTML",
    "cve-without-fix:lodash.template": "Templates are our own files, never user input",
  },
})
const WORST_WAITS = "Opens once angular, @babel/plugin-transform-async-generator-functions and request have a reason."
const CVE_TEXT = "A CVE is a publicly listed security flaw, named by an id such as CVE-2024-4068. Known CVEs counts the ones the scan found in these versions."
const JUMP_TEXT = "A major jump moves a package to a new major version, such as 4.x to 5.x. It may break your code, so it needs a reason."
const button = (name) => ({ role: "button", name })

const REVIEW_STATES = [
  { path: "/sessions/reasons/review", name: "one reason missing with a group open", click: [button(/^1 package updated/)], ready: "Opens once html-minifier has a reason." },
  { path: "/sessions/worst/review", name: "the worst case", before: worstReview, click: [button("7 packages of react 19"), button(/^8 packages updated/)], ready: WORST_WAITS },
  { path: "/sessions/worst/review", name: "angular's CVEs open", before: worstReview, click: [button("11 CVEs of angular")], ready: "CVE-2022-25844" },
  { path: "/sessions/reasons/review", name: "the CVE explanation open", click: [button("What a CVE is")], ready: CVE_TEXT },
  { path: "/sessions/reasons/review", name: "Decide open", click: [button("Decide html-minifier")], ready: "Signed with the archive and read at import." },
  { path: "/sessions/reasons/review", name: "Decide with its explanation open", click: [button("Decide html-minifier"), button("What a CVE is")], ready: CVE_TEXT },
  { path: "/sessions/reasons/review", name: "Jump open", click: [button(/kept on their major/), button("Jump react")], ready: "3 packages that move together" },
  { path: "/sessions/reasons/review", name: "Jump with its explanation open", click: [button(/kept on their major/), button("Jump react"), button("What a major jump is")], ready: JUMP_TEXT },
  { path: "/sessions/legacy/review", name: "an analysis 0.7.0 wrote", click: [button(/packages? updated/), button("2 CVEs of angular")], ready: "fix not recorded" },
]

export const UI = {
  baseURL: "http://127.0.0.1:18080",
  // Runs from web/ with $SEALIFT set to the binary built from the embedded web build.
  start: `data="$(mktemp -d)" && node tests/seed.mjs "$data" && exec "$SEALIFT" -addr 127.0.0.1:18080 -data "$data"`,
  routes: [
    "/",
    "/update",
    "/instance",
    // The settings sheet's old address lands on Instance.
    "/settings",
    "/sessions/demo/drop",
    "/sessions/demo/analysis",
    "/sessions/demo/review",
    "/sessions/demo/export",
    "/sessions/missing/review",
    "/projects",
    "/projects/web-portal",
    "/projects/pipeline",
  ],
  // A page brought to a state before it is checked as a route is. In order: `before(page)` runs before
  // the page loads (for page.route fakes), `file` is set on the page's file input, each `click` step
  // ({ role, name }) is pressed, `open` is pressed and must bring up its `opens`, and `ready` is the
  // text that proves the state arrived. `name` tells states of one path apart.
  states: [
    { path: "/instance", open: { role: "button", name: "How to regenerate", opens: { role: "button", name: "Copy command" } } },
    ...CHECK_STATES,
    ...REVIEW_STATES,
  ],
  // A session route with sessionStorage written before the page loads, as the review screen keeps the
  // selection and the reasons there; `ready` is the text that proves the analysis arrived.
  sessions: [],
  // A page whose API answer is replaced by a fixed body, for a state the seeded server never reaches.
  // `ready` is the text that proves the page drew that answer; `body` may be a function, called per
  // request. `focus` names a control focused next and what it must bring up.
  answers: [
    { path: "/", api: "/api/instance", body: preparingNow, ready: "Preparing this instance" },
    {
      path: "/",
      api: "/api/instance",
      name: "ready with a warning",
      body: READY_WITH_WARNING,
      ready: "Instance",
      focus: { role: "link", name: "Instance", opens: { role: "tooltip" } },
    },
    {
      path: "/instance",
      api: "/api/instance",
      name: "warning ephemeral and accent",
      // An accent that reads on the light page and falls under 3:1 on the dark one.
      body: { ...READY_WITH_WARNING, ephemeral: true, idleMinutes: 30, brand: { ...READY_WITH_WARNING.brand, accent: "#1d4ed8" } },
      ready: "Dark shows the ink in its place.",
    },
  ],
  widths: [1024, 1280],
  themes: ["light", "dark"],
  // CSS px. A desktop tool used with a mouse; WCAG 2.2 AA asks for 24.
  target: 32,
  exceptions: [
    // Radix places these zero-size spans around an open dialog to trap focus; nobody clicks them.
    { selector: "[data-radix-focus-guard]", check: "target", reason: "focus trap sentinel" },
    // The drop zone's file input is visually hidden and out of the tab order; Choose a file opens it.
    { selector: "input[type=file].sr-only", check: "target", reason: "hidden file input behind a button" },
  ],
}

import { spawn } from "node:child_process"
import { createServer } from "node:http"
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { test, expect } from "@playwright/test"
import AxeBuilder from "@axe-core/playwright"

import { IMPORT, startImportFixtures } from "./import-fixtures.mjs"

const GATE = new URL("./gate/", import.meta.url)
for (const name of existsSync(GATE) ? readdirSync(GATE).filter((f) => f.endsWith(".mjs")).sort() : []) {
  const module = await import(new URL(name, GATE).href)
  for (const list of ["routes", "states", "sessions", "answers"]) UI[list].push(...(module[list] ?? []))
}

// A copy button shows "Copy" and keeps its full name for assistive technology. Without the
// stylesheet's `.sr-only` rule in the import bundle, the full name prints beside the visible word.
const COPY_BUTTONS = "button:has(> .sr-only)"

// Collection routes the import pages must never call.
const COLLECTION_API = /^\/api\/(projects|settings|tools|jobs)(\/|$)/

test.describe.configure({ mode: "default", retries: 0 })

const CONTROLS = `a, button, input, select, textarea, summary, [role=button], [tabindex]:not([tabindex="-1"])`
const POLLS = 60
const CAPTURES = process.env.UI_CAPTURES ?? ""

// A file name part from a route's path and what sets its state apart: "/" reads "root".
const slug = (...parts) =>
  parts.filter(Boolean).map((p) => (p === "/" ? "root" : p)).join(" ").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "")

const answers = async (url = UI.baseURL, accept = () => true) => {
  try { return accept(await fetch(url)) } catch { return false }
}
const pause = (ms) => new Promise((done) => setTimeout(done, ms))

// Runs in the page: waits out enter transitions, which read as low contrast while they play.
// A looping animation such as a spinner never finishes, so it stays out of the wait.
function settle() {
  const ending = document.getAnimations().filter((a) => a.effect?.getTiming().iterations !== Infinity)
  return Promise.allSettled(ending.map((a) => a.finished)).then(() => null)
}

let binary = ""
let scratch = ""
let upstream = null
let startedCollection = false
let fixtures = null
const children = []

const spawnServer = (command, args, options) => {
  const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"], detached: process.platform !== "win32", ...options })
  child.log = ""
  child.stderr.on("data", (chunk) => { child.log = (child.log + chunk).slice(-2000) })
  children.push(child)
  return child
}

// A stand-in for api.github.com, the npm registry and the package index, so the collection server's preparation at
// start stays on this machine. It answers 404 to everything, so the server stays preparing. `paths` records what it
// was asked.
const startFakeUpstream = () =>
  new Promise((done, fail) => {
    const paths = []
    const server = createServer((req, res) => {
      paths.push(req.url)
      res.setHeader("content-type", "application/json")
      res.statusCode = 404
      res.end("{}")
    })
    server.on("error", fail)
    server.listen(0, "127.0.0.1", () => done({ url: `http://127.0.0.1:${server.address().port}`, paths, close: () => new Promise((end) => { server.close(end); server.closeAllConnections() }) }))
  })

const run = (command, args) =>
  new Promise((done, fail) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] })
    let out = ""
    for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { out = (out + chunk).slice(-2000) })
    child.on("error", fail)
    child.on("exit", (code) => (code === 0 ? done() : fail(new Error(`${command} ${args.join(" ")} exited with ${code}\n${out}`))))
  })

const waitFor = async (url, what, child, accept) => {
  for (let i = 0; i < POLLS; i++) {
    if (await answers(url, accept)) return
    if (child && child.exitCode !== null) throw new Error(`${what} stopped with ${child.exitCode}\n${child.log}`)
    await pause(1000)
  }
  throw new Error(`nothing answers at ${url} after ${POLLS} s (${what})${child ? `\n${child.log}` : ""}`)
}

const stop = async (child) => {
  if (child.exitCode !== null) return
  const gone = new Promise((done) => child.once("exit", done))
  try {
    if (process.platform === "win32") child.kill()
    else process.kill(-child.pid, "SIGTERM")
  } catch {}
  await Promise.race([gone, pause(5000)])
}

test.beforeAll(async () => {
  test.setTimeout((POLLS + 30) * 1000 + 240_000)
  scratch = mkdtempSync(join(tmpdir(), "sealift-gate-"))
  // One fixed path, so a firewall that asks per program sees the same file on every run.
  const out = resolve("test-results", "gate")
  mkdirSync(out, { recursive: true })
  binary = join(out, "sealift")
  writeCheckFiles()
  upstream = await startFakeUpstream()
  // The binary embeds web/dist, so the build comes first and the binary is built once for both roles.
  await run("pnpm", ["run", "build"])
  await run("go", ["build", "-o", binary, "../cmd/sealift"])

  if (!(await answers(UI.baseURL))) {
    if (!UI.start) throw new Error(`nothing answers at ${UI.baseURL} and UI.start is empty`)
    const collection = spawnServer(UI.start, [], { shell: true, env: { ...process.env, SEALIFT: binary, SEALIFT_GITHUB_API: upstream.url, SEALIFT_NPM_REGISTRY: upstream.url, SEALIFT_PIP_INDEX: `${upstream.url}/simple/` } })
    startedCollection = true
    await waitFor(UI.baseURL, "the collection server", collection)
    // The seed lays out every tool the start prepares, so the server turns ready without a download.
    await waitFor(`${UI.baseURL}/healthz`, "the collection server's readiness", collection, (res) => res.ok)
  }

  if (await answers(`${IMPORT.baseURL}/healthz`)) throw new Error(`${IMPORT.baseURL} answers already: the gate starts its own import server and will not reuse another`)
  fixtures = await startImportFixtures(join(scratch, "import"))
  const server = spawnServer(binary, ["import-server", "-settings", fixtures.settings, "-addr", new URL(IMPORT.baseURL).host, "-data", fixtures.data])
  await waitFor(`${IMPORT.baseURL}/healthz`, "the import server", server)
  await fixtures.seed()
})

test.afterAll(async () => {
  await Promise.all(children.splice(0).map(stop))
  if (fixtures) await fixtures.close()
  if (upstream) await upstream.close()
  upstream = null
  fixtures = null
  if (scratch) rmSync(scratch, { recursive: true, force: true })
  scratch = ""
})

// Runs in the page: the colours the dark check compares.
function colours() {
  return ["html", "body"].map((tag) => {
    const s = getComputedStyle(document.querySelector(tag))
    return `${s.backgroundColor} ${s.color}`
  }).join(" | ")
}

// Runs in the page: the selectors of what overflows and of the controls under the target size.
function measure({ controls, exceptions, target }) {
  const lifted = (el, check) => exceptions.some((e) => e.check === check && el.closest(e.selector))
  const path = (el) => {
    if (el.id) return `#${CSS.escape(el.id)}`
    const parts = []
    for (let e = el; e && e.nodeType === 1 && e !== document.documentElement; e = e.parentElement) {
      if (e.id) { parts.unshift(`#${CSS.escape(e.id)}`); break }
      const same = [...e.parentElement.children].filter((c) => c.tagName === e.tagName)
      parts.unshift(same.length > 1 ? `${e.localName}:nth-of-type(${same.indexOf(e) + 1})` : e.localName)
    }
    return parts.join(" > ")
  }
  const scrollsItself = (el) => {
    for (let e = el.parentElement; e && e !== document.body; e = e.parentElement) {
      if (/(auto|scroll|hidden|clip)/.test(getComputedStyle(e).overflowX)) return true
    }
    return false
  }
  const width = window.innerWidth
  const overflow = []
  if (document.documentElement.scrollWidth > width) {
    const out = [...document.body.querySelectorAll("*")].filter((el) =>
      el.getBoundingClientRect().right > width + 0.5 && !scrollsItself(el) && !lifted(el, "overflow"))
    const leaves = out.filter((el) => !out.some((o) => o !== el && el.contains(o)))
    overflow.push(...leaves.map(path))
  }
  const visible = (el) => {
    const s = getComputedStyle(el)
    return el.getClientRects().length > 0 && s.visibility !== "hidden" && s.display !== "none"
  }
  const inText = (el) => el.localName === "a" && getComputedStyle(el).display === "inline" &&
    el.parentElement.textContent.trim() !== el.textContent.trim()
  const big = (el) => { const r = el.getBoundingClientRect(); return r.width >= target && r.height >= target }
  const targets = []
  for (const el of document.querySelectorAll(controls)) {
    if (!visible(el) || inText(el) || lifted(el, "target")) continue
    const around = el.parentElement && el.parentElement.closest("label, a, button")
    if (big(el) || (around && big(around))) continue
    const r = el.getBoundingClientRect()
    targets.push({ selector: path(el), size: `${Math.round(r.width)} × ${Math.round(r.height)}` })
  }
  return { overflow, targets }
}

// The sidebar's column must paint down to the page's foot, so a full-page capture of a tall page
// shows no bare strip under it.
function sidebarReach() {
  const nav = document.querySelector('nav[aria-label="Places"]')
  if (!nav) return ""
  // On a phone the places sit in a tab bar fixed to the bottom, with no column to paint.
  if (getComputedStyle(nav.parentElement).position === "fixed") return ""
  let column = nav
  while (column.parentElement && getComputedStyle(column.parentElement).display !== "grid") column = column.parentElement
  const bottom = column.getBoundingClientRect().bottom + window.scrollY
  const page = document.documentElement.scrollHeight
  return bottom + 1 < page ? `sidebar column ends at ${Math.round(bottom)} px on a ${page} px page` : ""
}

// Loads one page and returns what the gate fails on: axe, overflow and small targets, plus what the
// caller adds through `extra`. `prepare` runs before the page loads, `ready` once its data arrived.
// Runs in the page: each open Term popover must show whole, inside the window and under no ancestor
// that clips its overflow.
const termsWhole = () => {
  const found = []
  for (const button of document.querySelectorAll("button[aria-expanded=true][aria-controls]")) {
    const popover = document.getElementById(button.getAttribute("aria-controls"))
    if (!popover || popover.hidden || !popover.querySelector("a")) continue
    const box = popover.getBoundingClientRect()
    const name = button.getAttribute("aria-label")
    if (box.left < 0 || box.top < 0 || box.right > innerWidth || box.bottom > innerHeight) {
      found.push(`${name}: popover leaves the window`)
      continue
    }
    for (let up = popover.parentElement; up && up !== document.documentElement; up = up.parentElement) {
      const style = getComputedStyle(up)
      if (style.overflowX === "visible" && style.overflowY === "visible") continue
      const clip = up.getBoundingClientRect()
      if (box.left < clip.left - 0.5 || box.top < clip.top - 0.5 || box.right > clip.right + 0.5 || box.bottom > clip.bottom + 0.5) {
        found.push(`${name}: popover clipped by ${up.tagName.toLowerCase()}.${[...up.classList].slice(0, 3).join(".")}`)
      }
    }
  }
  return found
}

async function inspect(page, { where, capture, url, width, theme, prepare, ready, extra }) {
  const failures = []
  await page.setViewportSize({ width, height: 800 })
  await prepare?.(page)
  if (theme === "dark") {
    await page.emulateMedia({ colorScheme: "light" })
    await page.goto(url)
    const light = await page.evaluate(colours)
    await page.emulateMedia({ colorScheme: "dark" })
    if (light === await page.evaluate(colours)) {
      failures.push(`${where} · html, body: dark theme not applied`)
    }
  } else {
    await page.emulateMedia({ colorScheme: theme })
    await page.goto(url)
  }
  await ready(page)
  await page.evaluate(settle)
  const axe = await new AxeBuilder({ page }).analyze()
  for (const v of axe.violations.filter((x) => x.impact === "serious" || x.impact === "critical")) {
    for (const node of v.nodes) failures.push(`${where} · ${node.target.join(" ")}: axe ${v.id} (${v.impact})`)
  }
  const sidebar = await page.evaluate(sidebarReach)
  if (sidebar) failures.push(`${where} · nav[aria-label=Places]: ${sidebar}`)
  const found = await page.evaluate(measure, { controls: CONTROLS, exceptions: UI.exceptions, target: UI.target })
  for (const t of await page.evaluate(termsWhole)) failures.push(`${where} · ${t}`)
  for (const s of found.overflow) failures.push(`${where} · ${s}: overflows the page horizontally`)
  for (const t of found.targets) {
    failures.push(`${where} · ${t.selector}: target under ${UI.target} × ${UI.target} CSS px (${t.size})`)
  }
  if (CAPTURES) {
    mkdirSync(CAPTURES, { recursive: true })
    await page.screenshot({ path: join(CAPTURES, `${capture}-${width}-${theme}.png`), fullPage: true, animations: "disabled" })
  }
  failures.push(...(await extra?.(page) ?? []))
  return failures
}

for (const route of UI.routes) {
  for (const width of UI.widths) {
    for (const theme of UI.themes) {
      test(`${route} ${width} ${theme}`, async ({ page }) => {
        const failures = await inspect(page, {
          where: `${route} · ${width}px · ${theme}`,
          capture: `collection-${slug(route)}`,
          url: new URL(route, UI.baseURL).href,
          width,
          theme,
          // The page's event stream stays open, so idle is a best effort.
          ready: (p) => p.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {}),
        })
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}

// Brings a loaded page to its state: the file set on its input, then each control pressed in order.
async function reach(page, { file, click }) {
  if (file) await page.locator("input[type=file]").first().setInputFiles(file)
  for (const control of click ?? []) await page.getByRole(control.role, { name: control.name, exact: true }).click()
}

for (const state of UI.states) {
  const name = state.name ?? state.open.name
  for (const width of UI.widths) {
    for (const theme of UI.themes) {
      test(`${state.path} ${name} ${width} ${theme}`, async ({ page }) => {
        const failures = await inspect(page, {
          where: `${state.path} · ${name} · ${width}px · ${theme}`,
          capture: `collection-${slug(state.path, name)}`,
          url: new URL(state.path, UI.baseURL).href,
          width,
          theme,
          prepare: state.before,
          ready: async (p) => {
            await reach(p, state)
            if (state.open) {
              await p.getByRole(state.open.role, { name: state.open.name }).click()
              await p.getByRole(state.open.opens.role, { name: state.open.opens.name }).waitFor()
            }
            if (state.ready) await p.getByText(state.ready, { exact: true }).first().waitFor({ timeout: 15_000 })
          },
        })
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}

for (const session of UI.sessions) {
  for (const width of UI.widths) {
    for (const theme of UI.themes) {
      test(`${session.path} ${session.ready} ${width} ${theme}`, async ({ page }) => {
        const failures = await inspect(page, {
          where: `${session.path} · ${session.ready} · ${width}px · ${theme}`,
          capture: `collection-${slug(session.path, session.ready)}`,
          url: new URL(session.path, UI.baseURL).href,
          width,
          theme,
          prepare: (p) =>
            p.addInitScript((storage) => {
              for (const [key, value] of Object.entries(storage)) sessionStorage.setItem(key, JSON.stringify(value))
            }, session.storage),
          ready: (p) => p.getByText(session.ready, { exact: true }).first().waitFor({ timeout: 15_000 }),
        })
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}

for (const state of UI.answers) {
  for (const width of UI.widths) {
    for (const theme of UI.themes) {
      test(`${state.path} answered by ${state.api}${state.name ? ` ${state.name}` : ""} ${width} ${theme}`, async ({ page }) => {
        const failures = await inspect(page, {
          where: `${state.path} · ${state.api} fixed${state.name ? ` · ${state.name}` : ""} · ${width}px · ${theme}`,
          capture: `collection-${slug(state.path, state.api, "fixed", state.name)}`,
          url: new URL(state.path, UI.baseURL).href,
          width,
          theme,
          prepare: (p) => p.route(`**${state.api}`, (r) => r.fulfill({ json: typeof state.body === "function" ? state.body() : state.body })),
          ready: async (p) => {
            await p.getByText(state.ready, { exact: true }).first().waitFor({ timeout: 15_000 })
            if (state.focus) {
              await p.getByRole(state.focus.role, { name: state.focus.name, exact: true }).focus()
              const opened = p.getByRole(state.focus.opens.role)
              await opened.waitFor()
              // What opens must sit above the page: a lower layer lets the content behind show through it.
              const covered = await opened.evaluate((el) => {
                const r = el.getBoundingClientRect()
                const points = [[r.left + r.width / 2, r.top + r.height / 2], [r.left + 4, r.top + 4], [r.right - 4, r.bottom - 4]]
                return points.filter(([x, y]) => !el.contains(document.elementFromPoint(x, y))).length
              })
              if (covered > 0) throw new Error(`${state.focus.opens.role} is covered by the page at ${covered} of 3 points`)
            }
          },
        })
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}

for (const route of IMPORT.routes) {
  for (const width of UI.widths) {
    for (const theme of UI.themes) {
      const label = route.path + (route.name ? ` ${route.name}` : "") + (route.hold ? " loading" : "") + (route.open ? ` ${route.open.name}` : "")
      test(`import ${route.user} ${label} ${width} ${theme}`, async ({ page }) => {
        const where = `${route.user} ${label} · ${width}px · ${theme}`
        const stray = []
        let release = () => {}
        let reached = () => {}
        const arrived = new Promise((done) => { reached = done })
        const released = new Promise((done) => { release = done })
        const failures = await inspect(page, {
          where,
          capture: `import-${slug(route.user, route.path, route.name, route.hold && "loading", route.open?.name)}`,
          url: new URL(route.path, IMPORT.baseURL).href,
          width,
          theme,
          prepare: async (p) => {
            // The gateway forwards the token the realm issued; the page never sees it.
            await p.setExtraHTTPHeaders({ "X-Access-Token": fixtures.token(route.user) })
            await p.addInitScript(() => {
              window.__violations = []
              document.addEventListener("securitypolicyviolation", (e) => {
                window.__violations.push(`${e.violatedDirective} blocked ${e.blockedURI || "inline"}`)
              })
            })
            p.on("request", (req) => {
              const { pathname } = new URL(req.url())
              if (COLLECTION_API.test(pathname)) stray.push(`${where} · ${pathname}: a collection route was called`)
            })
            // A state the server cannot hold, answered as the store writes it (import-fixtures.mjs).
            await route.before?.(p)
            if (route.hold) {
              await p.route(`**${route.hold}`, async (r) => {
                reached()
                await released
                await r.continue().catch(() => {})
              })
            }
          },
          ready: async (p) => {
            if (route.hold) await arrived
            await p.getByText(route.ready, { exact: !route.before }).first().waitFor({ timeout: 15_000 })
            if (route.open) {
              await p.getByRole(route.open.role, { name: route.open.name, exact: route.open.exact ?? true }).click()
              if (route.open.pressed) {
                await p.getByRole(route.open.role, { name: route.open.name, exact: route.open.exact ?? true, pressed: true }).waitFor()
              } else if (route.open.opens) {
                await p.getByRole(route.open.opens.role, { name: route.open.opens.name }).waitFor()
              } else {
                await p.getByRole("dialog").waitFor()
              }
            }
          },
          extra: async (p) => {
            const violations = await p.evaluate(() => window.__violations)
            const shown = await p.evaluate((selector) =>
              [...document.querySelectorAll(selector)]
                .filter((b) => b.getBoundingClientRect().width > 0 && b.querySelector(":scope > .sr-only").getBoundingClientRect().width > 1)
                .map((b) => b.innerText.replace(/\s+/g, " ").trim()), COPY_BUTTONS)
            release()
            return [
              ...stray,
              ...violations.map((v) => `${where} · content security policy: ${v}`),
              ...shown.map((t) => `${where} · button "${t}": the hidden label is visible, so the stylesheet lacks .sr-only`),
            ]
          },
        })
        release()
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}

// Runs in the page: at phone width the places form a tab bar along the bottom edge, each tab a
// 44 px target, the logo hidden, the breadcrumb still in the top bar.
function tabBar({ target }) {
  const nav = document.querySelector('nav[aria-label="Places"]')
  if (!nav) return ["nav[aria-label=Places]: missing"]
  const found = []
  const bar = nav.getBoundingClientRect()
  if (Math.abs(bar.bottom - window.innerHeight) > 1 || bar.width < window.innerWidth - 1) {
    found.push(`nav[aria-label=Places]: not a tab bar along the bottom (${Math.round(bar.left)},${Math.round(bar.top)} ${Math.round(bar.width)} × ${Math.round(bar.height)})`)
  }
  for (const link of nav.querySelectorAll("a")) {
    const r = link.getBoundingClientRect()
    if (r.width < target || r.height < target) found.push(`tab "${link.textContent.trim()}": under ${target} × ${target} CSS px (${Math.round(r.width)} × ${Math.round(r.height)})`)
  }
  const logo = nav.querySelector("[data-brand-mark]")
  if (logo && logo.getClientRects().length > 0) found.push("nav[aria-label=Places]: the logo shows in the tab bar")
  if (!document.querySelector('header nav[aria-label="Breadcrumb"]')) found.push("header: no breadcrumb")
  return found
}

// A phone's width: the pages whose longest lines broke there, opened as far as they go.
const PHONE = {
  width: 390,
  target: 44,
  collection: [
    { path: "/", ready: "Start a crossing" },
    { path: "/instance", ready: "Instance", open: [{ role: "button", name: /^Public key sha256/ }, { role: "button", name: "How to regenerate" }] },
    { path: "/update", ready: "3 checks to fix first", file: fileAt("billing-api/package.json") },
  ],
  // `columns` names blocks that must keep a readable width: a fixed grid squeezed them to nothing, and the text then ran over its neighbours inside the row, which the overflow check cannot see.
  import: [{ path: "/import", user: "alice", ready: "Not imported yet", columns: { selector: "#content li > div:first-child", min: 200 } }],
}

for (const route of [...PHONE.collection.map((r) => ({ ...r, role: "collection" })), ...PHONE.import.map((r) => ({ ...r, role: "import" }))]) {
  for (const theme of UI.themes) {
    test(`${route.role} ${route.path} at ${PHONE.width} ${theme}`, async ({ page }) => {
      const base = route.role === "import" ? IMPORT.baseURL : UI.baseURL
      const failures = await inspect(page, {
        where: `${route.role} ${route.path} · ${PHONE.width}px · ${theme}`,
        capture: `${route.role}-${slug(route.path, route.open && "open", route.file && "file")}`,
        url: new URL(route.path, base).href,
        width: PHONE.width,
        theme,
        prepare: route.user ? (p) => p.setExtraHTTPHeaders({ "X-Access-Token": fixtures.token(route.user) }) : undefined,
        ready: async (p) => {
          await reach(p, route)
          await p.getByText(route.ready, { exact: true }).first().waitFor({ timeout: 15_000 })
          for (const control of route.open ?? []) await p.getByRole(control.role, { name: control.name }).first().click()
        },
        extra: async (p) => {
          const found = await p.evaluate(tabBar, { target: PHONE.target })
          if (route.columns) {
            const narrow = await p.$$eval(route.columns.selector, (els, min) => els.map((el) => Math.round(el.getBoundingClientRect().width)).filter((w) => w < min), route.columns.min)
            for (const w of narrow) found.push(`${route.columns.selector}: ${w} px wide, under ${route.columns.min}`)
          }
          return found.map((f) => `${route.path} · ${PHONE.width}px · ${theme} · ${f}`)
        },
      })
      expect(failures, failures.join("\n")).toEqual([])
    })
  }
}

test("the collection server turned ready on the seeded tools and asked its stand-in nothing", async () => {
  // A server that already answered at baseURL was not started with the stand-in, so there is nothing to tell.
  if (!startedCollection) return
  const health = await fetch(`${UI.baseURL}/healthz`)
  expect(health.status).toBe(200)
  expect(await health.json()).toEqual({ status: "ok" })
  expect([...new Set(upstream.paths)].sort()).toEqual([])
})
