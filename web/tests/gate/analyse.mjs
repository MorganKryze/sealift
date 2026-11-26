// The Analyse step's states. The server marks a running job interrupted at start, so running, queued and
// failed states are answered here: GET /api/projects/web-portal is the seeded server's own answer with one
// analysis put in front, the event stream is a text/event-stream body of the events internal/jobs emits for
// that moment, closed after them, and the log is log.txt's lines. The cancelled state is the seeded one.

const PATH = "/sessions/web-portal/analysis"
const ID = "20261126T140500Z"
const JOB = "analysis-7"
const CREATED = "2026-11-26T14:05:00Z"

// One frame per event, as internal/api writes them: the kind as the event name, the whole event as data.
const frame = (kind, data, job = { id: JOB, storeId: ID }) => `event: ${kind}\ndata: ${JSON.stringify({ kind, job: job.id, storeId: job.storeId, data })}\n\n`
const line = (text, job) => frame("log", { line: text }, job)

// What an analysis emits up to its candidates: one step event as each step ends, and pnpm's output.
const beforeCandidates = (job) => [
  frame("step", { name: "validate", state: "done", durationMs: 120 }, job),
  frame("step", { name: "prepare-tools", state: "done", durationMs: 2400 }, job),
  line("pnpm: Progress: resolved 486, reused 486, downloaded 0, added 0, done", job),
  frame("step", { name: "resolve-project", state: "done", durationMs: 38_120 }, job),
  frame("step", { name: "scan-project", state: "done", durationMs: 4100 }, job),
  frame("step", { name: "list-candidates", state: "done", durationMs: 900 }, job),
]
const CANDIDATES = [
  ["react", "18.3.1"],
  ["react-dom", "18.3.1"],
  ["@typescript-eslint/eslint-plugin", "8.18.0"],
  ["express", "4.21.2"],
  ["lodash", "4.17.21"],
]
// Then each newer version tried, one that does not resolve, and the count with its estimate.
const resolving = (estimatedRemainingMs, job) => [
  ...beforeCandidates(job),
  ...CANDIDATES.map(([dependency, version]) => frame("candidate", { dependency, version, vector: [0, 0, 0, 0, 0], signals: [] }, job)),
  line("webpack-dev-server@5.2.2 does not resolve: pnpm install: exit status 1", job),
  frame("progress", { step: "resolve-candidates", done: 212, total: 486, estimatedRemainingMs }, job),
]

// The seeded server's answer for a path, changed by `edit` before the page reads it.
const edited = (page, pathname, edit) =>
  page.route((url) => url.pathname === pathname, async (route) => {
    if (route.request().method() !== "GET") return route.fallback()
    const response = await route.fetch()
    return route.fulfill({ response, json: edit(await response.json()) })
  })
const withAnalysis = (page, analysis) =>
  edited(page, "/api/projects/web-portal", (project) => ({ ...project, analyses: [{ id: ID, projectId: "web-portal", createdAt: CREATED, ...analysis }, ...(project.analyses ?? [])] }))
const stream = (page, frames) =>
  page.route((url) => url.pathname === "/api/jobs/current/events", (route) => route.fulfill({ status: 200, contentType: "text/event-stream", body: frames.join("") }))
const logOf = (page, text) =>
  page.route((url) => url.pathname === `/api/projects/web-portal/analyses/${ID}/log`, (route) => route.fulfill({ status: 200, contentType: "text/plain", body: text }))
// POST .../cancel held until the page closes, so the button stays on Cancelling.
const holdCancel = (page) =>
  page.route((url) => url.pathname === `/api/projects/web-portal/analyses/${ID}/cancel`, (route) =>
    new Promise((end) => page.once("close", end)).then(() => route.abort().catch(() => {})))
// Focuses Cancel once it is drawn, as a keyboard user who tabbed to it would see it.
const focusCancel = (page) =>
  page.addInitScript(() => {
    const focus = () => {
      const cancel = document.querySelector("button[data-focus=cancel]")
      if (cancel) cancel.focus()
      else requestAnimationFrame(focus)
    }
    requestAnimationFrame(focus)
  })

const running = (frames) => async (page) => {
  await withAnalysis(page, { state: "running" })
  await stream(page, frames)
}

const LONG = `webpack-dev-server@5.2.2 does not resolve: pnpm install: ERR_PNPM_PEER_DEP_ISSUES ${"x".repeat(518)}`
// 5 steps, 2,008 log lines and the 600-character one: 2,014 lines, 14 of them past the 2,000 kept.
const LONG_LOG = [
  ...beforeCandidates().filter((f) => f.startsWith("event: step")),
  ...Array.from({ length: 2008 }, (_, i) => line(`pnpm: Progress: resolved ${i + 1}, reused ${i + 1}, downloaded 0, added 0`)),
  line(LONG),
]

const REGISTRY =
  "resolve project: pnpm install: ERR_PNPM_META_FETCH_FAIL GET https://registry.npmjs.org/react: request to https://registry.npmjs.org/react failed, reason: connect ETIMEDOUT 104.16.2.35:443: exit status 1"
const MISSING =
  "resolve project: pnpm install: ERR_PNPM_NO_MATCHING_VERSION No matching version found for @typescript-eslint/eslint-plugin@8.46.9: exit status 1"
const failed = (step, message, log) => async (page) => {
  await withAnalysis(page, { state: "failed", pnpmVersion: "10.34.5", trivyVersion: "0.76.2", failure: { step, message } })
  await logOf(page, log)
}

// The queued analysis waits behind pipeline's, which runs: the projects list says so, the stream carries pipeline's events.
const RUNNING_ID = "20261126T135000Z"
const queued = async (page) => {
  await withAnalysis(page, { state: "queued" })
  await edited(page, "/api/projects", (projects) =>
    projects.map((p) =>
      p.id === "web-portal"
        ? { ...p, lastAnalysis: { id: ID, projectId: p.id, state: "queued", createdAt: CREATED } }
        : p.id === "pipeline"
          ? { ...p, lastAnalysis: { id: RUNNING_ID, projectId: p.id, state: "running", createdAt: "2026-11-26T13:50:00Z" } }
          : p,
    ),
  )
  await stream(page, resolving(180_000, { id: "analysis-6", storeId: RUNNING_ID }))
}

export const states = [
  { path: PATH, name: "running", before: running(resolving(300_000)), ready: "About 5 minutes left" },
  { path: PATH, name: "running with Cancel focused", before: async (page) => (await running(resolving(300_000))(page), focusCancel(page)), ready: "About 5 minutes left" },
  { path: PATH, name: "estimating", before: running(beforeCandidates().slice(0, 4)), ready: "Estimating time left" },
  { path: PATH, name: "queued", before: queued, ready: "Starts in about 3 minutes" },
  { path: PATH, name: "cancel confirm", before: running(resolving(300_000)), click: [{ role: "button", name: "Cancel" }], ready: "The work so far stops here. Your package.json is kept." },
  {
    path: PATH,
    name: "cancelling",
    before: async (page) => (await running(resolving(300_000))(page), holdCancel(page)),
    click: [{ role: "button", name: "Cancel" }, { role: "button", name: "Cancel analysis" }],
    ready: "Cancelling",
  },
  { path: PATH, name: "a 2,014-line log", before: running(LONG_LOG), ready: "2,014 lines" },
  {
    path: PATH,
    name: "failed on the registry",
    before: failed("resolve-project", REGISTRY, `pnpm: ${REGISTRY.replace("resolve project: pnpm install: ", "")}\n`),
    ready: "No answer from registry.npmjs.org",
  },
  {
    path: PATH,
    name: "failed on a missing version with the log open",
    before: failed("resolve-project", MISSING, "pnpm: ERR_PNPM_NO_MATCHING_VERSION No matching version found for @typescript-eslint/eslint-plugin@8.46.9\npnpm: The latest release of @typescript-eslint/eslint-plugin is \"8.18.0\".\n"),
    click: [{ role: "button", name: /^Log \d/ }],
    ready: "A pinned version is not on npm",
  },
  { path: `${PATH}?analysis=20261118T101500Z`, name: "cancelled", ready: "Analysis cancelled" },
  { path: PATH, name: "interrupted", before: (page) => withAnalysis(page, { state: "interrupted" }), ready: "Analysis interrupted" },
]
