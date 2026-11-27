// The Check step's states for requirements files. The files are written under test-results/ before the run,
// as the npm states' package.json files are; the server reads them again on Analyse, so the two answers the
// seeded server never gives (a held start and a 400 that names lines) are faked with the contract's Problem.

import { mkdirSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"

const FILES = resolve("test-results", "gate", "files", "pip")
const at = (...parts) => join(FILES, ...parts)
const HASH = (i) => ` --hash=sha256:${i.toString(16).padStart(64, "0")}`
const numbered = (count, prefix, from = 0) => Array.from({ length: count }, (_, i) => [`${prefix}-${String(i + from).padStart(3, "0")}`, `${1 + (i % 9)}.${i % 23}.${i % 7}`])
const pins = (list, hashed = 0) => list.map(([name, version], i) => `${name}==${version}${i < hashed ? HASH(i + 1) : ""}`)
const text = (...lines) => `${lines.join("\n")}\n`

const LONG_PACKAGE = "acme-ledger-reconciliation-opentelemetry-exporter-postgresql"
const DEV = [
  ["coverage", "7.6.4"], ["django-stubs", "5.1.1"], ["django-stubs-ext", "5.1.1"], ["djangorestframework-stubs", "3.15.1"], ["execnet", "2.1.1"],
  ["factory_boy", "3.3.1"], ["Faker", "30.8.2"], ["freezegun", "1.5.1"], ["mypy", "1.13.0"], ["mypy-extensions", "1.0.0"], ["pytest", "8.3.3"],
  ["pytest-cov", "6.0.0"], ["pytest-django", "4.9.0"], ["pytest-mock", "3.14.0"], ["pytest-xdist", "3.6.1"], ["responses", "0.25.3"],
  ["types-PyYAML", "6.0.12.20240917"], ["types-requests", "2.32.0.20241016"],
]
const DEV_HEAD = ["-r requirements.txt", "-c constraints.txt"]

const SETS = {
  // 64 + 18 + 12 pins, 61 of them hashed: every check passes.
  compliant: {
    "requirements.txt": text(...pins(numbered(64, "ledger-lib"), 61)),
    "requirements-dev.txt": text(...DEV_HEAD, ...pins(DEV)),
    "constraints.txt": text(...pins(numbered(12, "ledger-pin"))),
  },
  // Three ranges, three lines off PyPI, two index options and a package at two versions.
  issues: {
    "requirements.txt": text(
      "--index-url https://pypi.internal.example.com/simple",
      "--extra-index-url https://download.pytorch.org/whl/cpu",
      "Django>=4.2,<5",
      "celery~=5.4.0",
      "numpy==2.1.*",
      "-e git+https://github.com/acme/billing-sdk.git@v2.3.1#egg=billing-sdk",
      "internal-auth @ git+ssh://git@gitlab.example.com/platform/internal-auth.git@4f2a91c",
      "redis==5.2.0",
      ...pins(numbered(58, "billing-lib")),
    ),
    "requirements-dev.txt": text(...DEV_HEAD, "-e ./libs/shared-models", "redis==5.1.1", ...pins(DEV)),
    "constraints.txt": text(...pins(numbered(12, "billing-pin"))),
  },
  // 142 lines without a version, the 60-character name first, and an include of a file not dropped.
  unpinned: {
    "requirements.txt": text(`${LONG_PACKAGE}>=1`, ...numbered(141, "ingest-lib").map(([name], i) => (i % 3 === 0 ? `${name}>=${1 + (i % 9)}` : name))),
    "requirements-dev.txt": text("-r requirements-base.txt", ...DEV_HEAD, ...pins(numbered(60, "ingest-tool"))),
    "constraints.txt": text(...pins(numbered(18, "ingest-pin"))),
  },
  // 142 + 60 + 18 pins, all exact, the 60-character name among them.
  worst: {
    "requirements.txt": text(`${LONG_PACKAGE}==1.4.0`, ...pins(numbered(141, "ingest-lib"))),
    "requirements-dev.txt": text(...DEV_HEAD, ...pins(numbered(60, "ingest-tool"))),
    "constraints.txt": text(...pins(numbered(18, "ingest-pin"))),
  },
}
for (const [set, files] of Object.entries(SETS)) {
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(dirname(at(set, name)), { recursive: true })
    writeFileSync(at(set, name), body)
  }
}
writeFileSync(at("package.json"), `${JSON.stringify({ name: "web-portal", dependencies: { react: "18.3.1" } }, null, 2)}\n`)
const filesOf = (set) => Object.keys(SETS[set]).map((name) => at(set, name))

// Types a name into the title's field once the files are read, then presses Enter, as a user does.
const named = (value) => (page) =>
  page.addInitScript((name) => {
    const type = () => {
      const field = document.querySelector("input[placeholder='project name']")
      if (!field) return requestAnimationFrame(type)
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(field, name)
      field.dispatchEvent(new Event("input", { bubbles: true }))
      requestAnimationFrame(() => requestAnimationFrame(() => field.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }))))
    }
    requestAnimationFrame(type)
  }, value)

// Three files held over the zone: a dragover with three items, the one fact a browser gives before the drop.
const over = (page) =>
  page.addInitScript(() => {
    const hover = () => {
      const zone = document.querySelector("[data-drop-zone]")
      if (!zone) return requestAnimationFrame(hover)
      const data = new DataTransfer()
      for (const name of ["requirements.txt", "requirements-dev.txt", "constraints.txt"]) data.items.add(new File([""], name))
      zone.dispatchEvent(new DragEvent("dragover", { bubbles: true, cancelable: true, dataTransfer: data }))
    }
    requestAnimationFrame(hover)
  })

// POST /api/projects held until the page closes, so the page stays on Starting.
const holdStart = (page) =>
  page.route((url) => url.pathname === "/api/projects", (route) =>
    route.request().method() === "POST" ? new Promise((done) => page.once("close", done)).then(() => route.abort().catch(() => {})) : route.fallback())
// POST /api/projects answered as the server refuses requirements files: a Problem whose errors name file, line, text and reason.
const PROBLEM = {
  type: "about:blank",
  title: "invalid requirements files",
  status: 400,
  detail: "the requirements files have lines sealift cannot analyze",
  errors: [
    { field: "requirements.txt", line: 7, value: 'ledger-lib-006==7.6.6 ; platform_machine == "x86_64" or {x}', reason: "marker has characters outside letters, digits, spaces and _.<>=!~\"'()-" },
    { field: "requirements-dev.txt", line: 4, value: "coverage==${COVERAGE_VERSION}", reason: "variables are not expanded" },
    { field: "constraints.txt", reason: "file has more than 10000 lines" },
  ],
}
const refuseLines = (page) =>
  page.route((url) => url.pathname === "/api/projects", (route) =>
    route.request().method() === "POST" ? route.fulfill({ status: 400, contentType: "application/problem+json", body: JSON.stringify(PROBLEM) }) : route.fallback())
const both = (...steps) => async (page) => {
  for (const step of steps) await step(page)
}

const button = (name) => ({ role: "button", name })
const PATH = "/update"
const TARGET_TEXT = "Check on one of them"

export const states = [
  { path: PATH, name: "three files over the zone", before: over, ready: "Drop to read 3 files" },
  { path: PATH, name: "a package.json with requirements files", file: [at("package.json"), ...filesOf("compliant")], ready: "Drop the package.json alone, or the requirements files alone; nothing was sent." },
  { path: PATH, name: "requirements files unnamed", file: filesOf("compliant"), ready: "Name the project first" },
  { path: PATH, name: "requirements compliant", before: named("ledger-reconciler"), file: filesOf("compliant"), ready: "Update ledger-reconciler" },
  {
    path: PATH,
    name: "requirements compliant open with a file open",
    before: named("ledger-reconciler"),
    file: filesOf("compliant"),
    click: [button("Compliant"), button(/^requirements-dev\.txt/)],
    ready: "5 checks passed",
  },
  { path: PATH, name: "the target explained", before: named("ledger-reconciler"), file: filesOf("compliant"), click: [button("What the target is")], ready: TARGET_TEXT },
  { path: PATH, name: "requirements with issues", before: named("billing-worker"), file: filesOf("issues"), ready: "4 issues" },
  {
    path: PATH,
    name: "142 lines without a version",
    before: named("analytics-ingest-pipeline-airflow-worker"),
    file: filesOf("unpinned"),
    click: [button("Show all 142 lines")],
    ready: "2 issues",
  },
  {
    path: PATH,
    name: "220 pins with every list open",
    before: named("analytics-ingest-pipeline-airflow-worker"),
    file: filesOf("worst"),
    click: [button("Compliant"), button(/^requirements\.txt/), button("Show all 142 pins")],
    ready: "5 checks passed",
  },
  { path: PATH, name: "requirements starting", before: both(named("ledger-reconciler"), holdStart), file: filesOf("compliant"), click: [button("Analyse")], ready: "Starting" },
  { path: PATH, name: "requirements refused by the server", before: both(named("ledger-reconciler"), refuseLines), file: filesOf("compliant"), click: [button("Analyse")], ready: "3 problems in the requirements files" },
]
