// UI gate: every route at every width, in light and dark, checked for serious or critical axe
// findings, horizontal page overflow, visible controls under the target size, and a dark theme that
// differs from the light one. Each failure names the route, width, theme and selector.
// Needs @playwright/test and @axe-core/playwright (dev dependencies). The run builds the web and one
// sealift binary, then starts both roles from it: the collection through `start` when nothing answers
// at baseURL, and the import server with its token check on (see import-fixtures.mjs). No start
// command, or a missing package, fails the run: it never skips. No screenshot diff, no clock, no
// random input. Fill the blocks below; `exceptions` take a selector, the check they lift and the reason.
export const UI = {
  baseURL: "http://127.0.0.1:18080",
  // Runs from web/ with $SEALIFT set to the binary built from the embedded web build.
  start: `data="$(mktemp -d)" && node tests/seed.mjs "$data" && exec "$SEALIFT" -addr 127.0.0.1:18080 -data "$data"`,
  routes: [
    "/",
    "/settings",
    "/sessions/demo/drop",
    "/sessions/demo/analysis",
    "/sessions/demo/review",
    "/sessions/demo/export",
    "/sessions/missing/review",
  ],
  widths: [1024, 1280],
  themes: ["light", "dark"],
  // CSS px. A desktop tool used with a mouse; WCAG 2.2 AA asks for 24.
  target: 32,
  exceptions: [
    // Radix places these zero-size spans around an open dialog to trap focus; nobody clicks them.
    { selector: "[data-radix-focus-guard]", check: "target", reason: "focus trap sentinel" },
  ],
}

import { spawn } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test, expect } from "@playwright/test"
import AxeBuilder from "@axe-core/playwright"

import { IDS, startImportFixtures } from "./import-fixtures.mjs"

// The import role: the shipped import-server behind a real token check. A route names the user whose
// token the page sends as the gateway does, an optional control to press once the page has its
// content (`open`; a `pressed` control is waited on pressed, one with `opens` waits for that role and name, any other opens a dialog), an optional API path to hold until the checks are done so the loading state
// shows (`hold`), and the text that proves the data arrived (`ready`).
export const IMPORT = {
  baseURL: "http://127.0.0.1:18090",
  routes: [
    { path: "/", user: "alice", ready: "Not imported yet" },
    { path: "/", user: "alice", open: { role: "button", name: "Importable", exact: false, pressed: true }, ready: "Not imported yet" },
    { path: "/", user: "alice", open: { role: "button", name: "Start import of 2026-11-06-new-export/packages_npm.tar.gz", opens: { role: "region", name: "Start the import of 2026-11-06-new-export/packages_npm.tar.gz" } }, ready: "Not imported yet" },
    { path: "/", user: "bob", ready: "No archive in your folder" },
    { path: "/", user: "carol", ready: "MinIO has no bucket user-carol yet: nothing to list" },
    { path: "/", user: "dave", ready: "The archives could not be listed" },
    { path: "/", user: "alice", hold: "/api/archives", ready: "Reading your folder in MinIO: user-alice/packages/npm/" },
    { path: "/imports", user: "alice", ready: "Waiting its turn" },
    { path: `/imports/${IDS.completeRemoved}`, user: "alice", ready: "Archive removed from MinIO" },
    { path: `/imports/${IDS.completeKept}`, user: "alice", ready: "Archive kept in MinIO" },
    { path: `/imports/${IDS.completePending}`, user: "alice", ready: "Checking the archive's removal" },
    { path: `/imports/${IDS.incomplete}`, user: "alice", ready: "3 of 101 packages are not in Nexus" },
    { path: `/imports/${IDS.refusedDigests}`, user: "alice", ready: "Refused before the first package" },
    { path: `/imports/${IDS.refusedLong}`, user: "alice", ready: "Refused before the first package" },
    { path: `/imports/${IDS.interrupted}`, user: "alice", ready: "45 of 101 packages are not in Nexus" },
    { path: `/imports/${IDS.running}`, user: "alice", ready: "Publishing packages: 37 of 101" },
    { path: `/imports/${IDS.queued}`, user: "alice", ready: "Waiting its turn" },
    {
      path: `/imports/${IDS.incomplete}`, user: "alice", ready: "Archive sha256 check",
      open: { role: "button", name: "Show full reason of package-099@1.0.0", opens: { role: "region", name: "Full reason of package-099@1.0.0" } },
    },
    {
      path: `/imports/${IDS.running}`, user: "alice", ready: "Publishing packages: 37 of 101",
      open: { role: "button", name: "Earlier attempts (1)", opens: { role: "list", name: "Earlier attempts" } },
    },
    { path: `/imports/${IDS.legacy}`, user: "alice", ready: "Archive sha256 check" },
    { path: `/imports/${IDS.longKey}`, user: "alice", ready: "Archive sha256 check" },
    { path: "/imports/missing-import", user: "alice", ready: "No such import" },
    { path: "/imports", user: "bob", ready: "No import yet" },
    { path: "/imports", user: "frank", ready: "Your archives in MinIO are untouched." },
    { path: "/imports", user: "alice", hold: "/api/imports", ready: "Loading your imports" },
    { path: "/imports", user: "alice", open: { role: "button", name: "Settings" }, ready: "Waiting its turn" },
  ],
}

// Collection routes the import pages must never call.
const COLLECTION_API = /^\/api\/(projects|settings|tools|jobs)(\/|$)/

test.describe.configure({ mode: "default", retries: 0 })

const CONTROLS = `a, button, input, select, textarea, summary, [role=button], [tabindex]:not([tabindex="-1"])`
const POLLS = 60

const answers = async (url = UI.baseURL) => {
  try { await fetch(url); return true } catch { return false }
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
let fixtures = null
const children = []

const spawnServer = (command, args, options) => {
  const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"], detached: process.platform !== "win32", ...options })
  child.log = ""
  child.stderr.on("data", (chunk) => { child.log = (child.log + chunk).slice(-2000) })
  children.push(child)
  return child
}

const run = (command, args) =>
  new Promise((done, fail) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] })
    let out = ""
    for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { out = (out + chunk).slice(-2000) })
    child.on("error", fail)
    child.on("exit", (code) => (code === 0 ? done() : fail(new Error(`${command} ${args.join(" ")} exited with ${code}\n${out}`))))
  })

const waitFor = async (url, what, child) => {
  for (let i = 0; i < POLLS; i++) {
    if (await answers(url)) return
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
  binary = join(scratch, "sealift")
  // The binary embeds web/dist, so the build comes first and the binary is built once for both roles.
  await run("pnpm", ["run", "build"])
  await run("go", ["build", "-o", binary, "../cmd/sealift"])

  if (!(await answers(UI.baseURL))) {
    if (!UI.start) throw new Error(`nothing answers at ${UI.baseURL} and UI.start is empty`)
    const collection = spawnServer(UI.start, [], { shell: true, env: { ...process.env, SEALIFT: binary } })
    await waitFor(UI.baseURL, "the collection server", collection)
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

// Loads one page and returns what the gate fails on: axe, overflow and small targets, plus what the
// caller adds through `extra`. `prepare` runs before the page loads, `ready` once its data arrived.
async function inspect(page, { where, url, width, theme, prepare, ready, extra }) {
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
  const found = await page.evaluate(measure, { controls: CONTROLS, exceptions: UI.exceptions, target: UI.target })
  for (const s of found.overflow) failures.push(`${where} · ${s}: overflows the page horizontally`)
  for (const t of found.targets) {
    failures.push(`${where} · ${t.selector}: target under ${UI.target} × ${UI.target} CSS px (${t.size})`)
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
          url: new URL(route, UI.baseURL).href,
          width,
          theme,
          // /api/tools asks GitHub for the latest Trivy, which can take 30 s, so idle is a best effort.
          ready: (p) => p.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {}),
        })
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}

for (const route of IMPORT.routes) {
  for (const width of UI.widths) {
    for (const theme of UI.themes) {
      const label = route.path + (route.hold ? " loading" : "") + (route.open ? ` ${route.open.name}` : "")
      test(`import ${route.user} ${label} ${width} ${theme}`, async ({ page }) => {
        const where = `${route.user} ${label} · ${width}px · ${theme}`
        const stray = []
        let release = () => {}
        let reached = () => {}
        const arrived = new Promise((done) => { reached = done })
        const released = new Promise((done) => { release = done })
        const failures = await inspect(page, {
          where,
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
            await p.getByText(route.ready, { exact: true }).first().waitFor({ timeout: 15_000 })
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
            release()
            return [...stray, ...violations.map((v) => `${where} · content security policy: ${v}`)]
          },
        })
        release()
        expect(failures, failures.join("\n")).toEqual([])
      })
    }
  }
}
