import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, fireEvent, render, screen, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { cancelAnalysis, getAnalysisLog, listProjects, queueAnalysis, type Analysis, type Project, type ProjectSummary } from "@/api/projects"
import { useJobEvents } from "@/hooks/use-job-events"
import { crossingDay } from "@/lib/crossings"
import { analysisEventsReducer, initialAnalysisEventsState, type AnalysisEventsState, type JobEvent } from "@/lib/analysisEvents"

import { AnalysisScreen, analysisCause } from "./analysis-screen"

vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children, to, params, ...rest }: { children: ReactNode; to: string; params?: Record<string, string> }) => (
    <a href={Object.entries(params ?? {}).reduce((path, [key, value]) => path.replace(`$${key}`, value), to)} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock("@/hooks/use-job-events", () => ({ useJobEvents: vi.fn() }))
vi.mock("@/api/projects", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/projects")>()),
  cancelAnalysis: vi.fn(),
  getAnalysisLog: vi.fn(),
  listProjects: vi.fn(),
  queueAnalysis: vi.fn(),
}))

const ID = "20261126T140500Z"
const LONG_NAME = "customer-onboarding-portal-frontend-next"

const analysisIn = (state: string, more: Partial<Analysis> = {}) =>
  ({ id: ID, projectId: "web-portal", state, createdAt: "2026-11-26T14:05:00Z", ...more }) as Analysis
const projectWith = (analysis: Analysis) => ({ id: "web-portal", name: "web-portal", ecosystem: "npm", analyses: [analysis] }) as Project

// Folds the events a job emits through the real reducer, each received a second after the last.
const ran = (events: JobEvent[]): AnalysisEventsState =>
  events.reduce((state, event, i) => analysisEventsReducer(state, event, new Date(2026, 10, 26, 14, 11, i % 60)), initialAnalysisEventsState)
const ended = (...names: string[]): JobEvent[] => names.map((name) => ({ kind: "step", job: "3", storeId: ID, data: { name, state: "done", durationMs: 12_000 } }))
const BEFORE_CANDIDATES = ended("validate", "prepare-tools", "resolve-project", "scan-project", "list-candidates")
const tried = (done: number, total: number, estimatedRemainingMs?: number): JobEvent => ({
  kind: "progress",
  job: "3",
  storeId: ID,
  data: { step: "resolve-candidates", done, total, ...(estimatedRemainingMs === undefined ? {} : { estimatedRemainingMs }) },
})

let events: Record<string, AnalysisEventsState> = {}

function renderScreen(analysis: Analysis, { onNavigateStep = vi.fn(), onChanged = vi.fn() } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const ui = (shown: Analysis) => (
    <QueryClientProvider client={client}>
      <AnalysisScreen projectId="web-portal" project={projectWith(shown)} analysis={shown} onChanged={onChanged} onNavigateStep={onNavigateStep} />
    </QueryClientProvider>
  )
  const utils = render(ui(analysis))
  return { ...utils, show: (next: Analysis) => utils.rerender(ui(next)), onNavigateStep, onChanged }
}

const counted = (text: string) => screen.getByText((_, element) => element?.tagName === "P" && element.textContent === text)

beforeEach(() => {
  events = {}
  vi.mocked(useJobEvents).mockReset().mockImplementation((id: string) => events[id] ?? initialAnalysisEventsState)
  vi.mocked(cancelAnalysis).mockReset()
  vi.mocked(queueAnalysis).mockReset().mockResolvedValue(analysisIn("queued", { id: "20261126T150000Z" }))
  vi.mocked(listProjects).mockReset()
  vi.mocked(getAnalysisLog).mockReset().mockResolvedValue("")
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe("a running analysis", () => {
  it("titles the time left and counts newer versions tried", () => {
    const long = `webpack-dev-server@5.2.2 does not resolve: ${"x".repeat(557)}`
    events[ID] = ran([...BEFORE_CANDIDATES, { kind: "log", job: "3", storeId: ID, data: { line: long } }, tried(212, 486, 300_000)])
    renderScreen(analysisIn("running"))

    const title = screen.getByRole("heading", { level: 1, name: "About 5 minutes left" })
    expect(title).toHaveAttribute("aria-live", "polite")
    expect(counted("212 of 486 newer versions tried")).toBeInTheDocument()
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "44")
    const log = screen.getByRole("region", { name: "Log" })
    expect(screen.getByRole("button", { name: "Log 6 lines" })).toHaveAttribute("aria-expanded", "true")
    expect(screen.getByText("Live")).toBeInTheDocument()
    // The 600-character line is kept whole and wraps; nothing truncates it.
    expect(long).toHaveLength(600)
    const line = within(log).getByText(long)
    expect(line.className).not.toMatch(/truncate|ellipsis|line-clamp/)
    expect(within(log).getAllByText("candidate").length).toBeGreaterThan(0)
    expect(screen.getByText("Keeps running if you leave this page")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
  })

  it("says Estimating time left over a still track", () => {
    events[ID] = ran(ended("validate", "prepare-tools", "resolve-project"))
    renderScreen(analysisIn("running"))

    expect(screen.getByRole("heading", { level: 1, name: "Estimating time left" })).toBeInTheDocument()
    expect(counted("Scanning the project")).toBeInTheDocument()
    const track = screen.getByRole("progressbar")
    expect(track).not.toHaveAttribute("aria-valuenow")
    expect(track).toHaveAttribute("data-estimating")
  })

  it("draws the striped track still", () => {
    events[ID] = ran(ended("validate"))
    renderScreen(analysisIn("running"))

    const track = screen.getByRole("progressbar")
    for (const element of [track, ...track.querySelectorAll("*")]) {
      expect(element.getAttribute("class") ?? "").not.toMatch(/animate|transition/)
      expect((element as HTMLElement).style.animation).toBe("")
    }
  })

  it("asks in place and focuses Keep running", () => {
    events[ID] = ran([...BEFORE_CANDIDATES, tried(212, 486, 300_000)])
    renderScreen(analysisIn("running"))

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))

    expect(cancelAnalysis).not.toHaveBeenCalled()
    expect(screen.getByText("The work so far stops here. Your package.json is kept.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Keep running" })).toHaveFocus()
    expect(screen.queryByText("Keeps running if you leave this page")).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: "Keep running" }))
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus()
    expect(screen.queryByRole("button", { name: "Cancel analysis" })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    fireEvent.click(screen.getByRole("button", { name: "Cancel analysis" }))
    expect(cancelAnalysis).toHaveBeenCalledWith("web-portal", ID)
  })

  it("shows Cancelling with its width kept", async () => {
    vi.mocked(cancelAnalysis).mockReturnValue(new Promise(() => {}))
    events[ID] = ran([...BEFORE_CANDIDATES, tried(212, 486, 300_000)])
    renderScreen(analysisIn("running"))

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel analysis" }))
    })

    const cancelling = screen.getByRole("button", { name: "Cancelling" })
    expect(cancelling).toHaveAttribute("aria-disabled", "true")
    // Both words sit in the button, the one not shown kept for its width only.
    expect([...cancelling.querySelectorAll("span[aria-hidden='true']")].map((span) => span.textContent)).toContain("Cancel")
    expect(screen.queryByText("Keeps running if you leave this page")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Keep running" })).not.toBeInTheDocument()
  })

  it("keeps one progress node through the run", () => {
    events[ID] = ran(ended("validate", "prepare-tools"))
    const { show } = renderScreen(analysisIn("running"))
    const before = [screen.getByRole("heading", { level: 1 }), screen.getByRole("progressbar"), screen.getByRole("region", { name: "Log" })]

    events[ID] = ran([...BEFORE_CANDIDATES, tried(30, 486, 1_200_000)])
    show(analysisIn("running"))
    events[ID] = ran([...BEFORE_CANDIDATES, tried(212, 486, 300_000), ...ended("resolve-candidates")])
    show(analysisIn("running"))

    expect(screen.getByRole("heading", { level: 1 })).toBe(before[0])
    expect(screen.getByRole("progressbar")).toBe(before[1])
    expect(screen.getByRole("region", { name: "Log" })).toBe(before[2])
  })

  it("opens Review when the analysis ends done", () => {
    events[ID] = ran([...BEFORE_CANDIDATES, tried(486, 486, 0)])
    const { show, onNavigateStep } = renderScreen(analysisIn("running"))
    expect(onNavigateStep).not.toHaveBeenCalled()

    show(analysisIn("done"))

    expect(onNavigateStep).toHaveBeenCalledWith("review")
    expect(onNavigateStep).toHaveBeenCalledTimes(1)
  })

  it("stays on an analysis that had ended before the page opened, with Review one press away", () => {
    const { onNavigateStep } = renderScreen(analysisIn("done"))

    expect(onNavigateStep).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Review" }))
    expect(onNavigateStep).toHaveBeenCalledWith("review")
  })
})

describe("a queued analysis", () => {
  const RUNNING_ID = "20261126T135000Z"
  const summary = (id: string, name: string, state: string, createdAt: string, storeId = `${id}-analysis`) =>
    ({ id, name, ecosystem: "npm", lastAnalysis: { id: storeId, projectId: id, state, createdAt } }) as ProjectSummary
  const running = summary("billing-api", LONG_NAME, "running", "2026-11-26T13:50:00Z", RUNNING_ID)
  const self = { id: "web-portal", name: "web-portal", ecosystem: "npm", lastAnalysis: analysisIn("queued") } as ProjectSummary

  beforeEach(() => {
    events[RUNNING_ID] = ran([
      ...ended("validate", "prepare-tools", "resolve-project", "scan-project", "list-candidates").map((e) => ({ ...e, storeId: RUNNING_ID })),
      { ...tried(401, 486, 180_000), storeId: RUNNING_ID },
    ])
  })

  it("gives a start time only when no job waits before this one", async () => {
    vi.mocked(listProjects).mockResolvedValue([self, running, summary("kiosk-ui", "kiosk-ui", "queued", "2026-11-26T14:10:00Z")])
    const first = renderScreen(analysisIn("queued"))
    expect(await screen.findByRole("heading", { level: 1, name: "Starts in about 3 minutes" })).toBeInTheDocument()
    first.unmount()

    // The title reads the same before the list arrives, so each case waits for the running crossing first.
    vi.mocked(listProjects).mockResolvedValue([self, running, summary("kiosk-ui", "kiosk-ui", "queued", "2026-11-26T14:00:00Z")])
    const second = renderScreen(analysisIn("queued"))
    await screen.findByRole("link", { name: /^Open / })
    expect(screen.getByRole("heading", { level: 1, name: "Waits for the running job" })).toBeInTheDocument()
    second.unmount()

    events[RUNNING_ID] = ran(ended("validate").map((e) => ({ ...e, storeId: RUNNING_ID })))
    vi.mocked(listProjects).mockResolvedValue([self, running])
    renderScreen(analysisIn("queued"))
    await screen.findByRole("link", { name: /^Open / })
    expect(screen.getByRole("heading", { level: 1, name: "Waits for the running job" })).toBeInTheDocument()
  })

  it("names the crossing that runs now with Open", async () => {
    vi.mocked(listProjects).mockResolvedValue([self, running])
    renderScreen(analysisIn("queued"))

    const name = `${LONG_NAME} · ${crossingDay("2026-11-26T13:50:00Z")}`
    const row = (await screen.findByRole("link", { name: `Open ${name}` })).closest("li") as HTMLElement
    expect(within(row).getByText(name)).toBeInTheDocument()
    expect(within(row).getByText("Analysing")).toBeInTheDocument()
    expect(within(row).getByText((_, element) => element?.tagName === "P" && element.textContent === "401 of 486 newer versions tried")).toBeInTheDocument()
    expect(within(row).getByRole("link", { name: `Open ${name}` })).toHaveAttribute("href", "/sessions/billing-api")
    expect(vi.mocked(useJobEvents)).toHaveBeenCalledWith(RUNNING_ID, true, expect.any(Function))
    // Nothing has started here: no log and no bar, and Cancel takes it out of the queue.
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "Log" })).not.toBeInTheDocument()
    expect(screen.getByText("Keeps its place if you leave this page")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(screen.getByRole("button", { name: "Keep its place" })).toHaveFocus()
  })
})

describe("a stopped analysis", () => {
  const failed = (step: string, message: string) => analysisIn("failed", { failure: { step, message } })

  it("names the package and version of a pinned version not on npm, with Replace package.json", async () => {
    const raw = "ERR_PNPM_NO_MATCHING_VERSION No matching version found for @typescript-eslint/eslint-plugin@8.46.9"
    vi.mocked(getAnalysisLog).mockResolvedValue(`pnpm: ${raw}\n`)
    renderScreen(failed("resolve-project", `resolve project: pnpm install: ${raw}: exit status 1`))

    expect(screen.getByRole("heading", { level: 1, name: "Analysis stopped" })).toBeInTheDocument()
    const cause = screen.getByRole("alert")
    expect(within(cause).getByText("A pinned version is not on npm")).toBeInTheDocument()
    expect(within(cause).getByText("1 package")).toBeInTheDocument()
    expect(within(cause).getByText("@typescript-eslint/eslint-plugin")).toBeInTheDocument()
    expect(within(cause).getByText("8.46.9")).toBeInTheDocument()
    expect(within(cause).getByRole("link", { name: "Replace package.json" })).toHaveAttribute("href", "/update")
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument()
    await screen.findByRole("button", { name: "Log 1 line" })
    expect(screen.queryByText(raw, { exact: false })).not.toBeInTheDocument()
  })

  it("names the host of a fetch with no answer, with Retry and the run's duration", async () => {
    events[ID] = ran([...ended("validate", "prepare-tools"), { kind: "step", job: "3", storeId: ID, data: { name: "resolve-project", state: "failed", durationMs: 48_000, error: "x" } }])
    const { onChanged } = renderScreen(
      failed(
        "resolve-project",
        "resolve project: pnpm install: ERR_PNPM_META_FETCH_FAIL GET https://registry.npmjs.org/react: request to https://registry.npmjs.org/react failed, reason: connect ETIMEDOUT 104.16.2.35:443: exit status 1",
      ),
    )

    expect(counted("After 1 min 12 s. Your package.json is kept.")).toBeInTheDocument()
    const cause = screen.getByRole("alert")
    expect(within(cause).getByText("No answer from registry.npmjs.org")).toBeInTheDocument()
    fireEvent.click(within(cause).getByRole("button", { name: "Retry" }))
    await vi.waitFor(() => expect(queueAnalysis).toHaveBeenCalledWith("web-portal"))
    await vi.waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(await screen.findByText("See your administrators")).toBeInTheDocument()
  })

  it("shows an unmapped cause by its first line", () => {
    renderScreen(failed("rank", "write ranking.json: no space left on device\nsecond line of the cause"))

    expect(within(screen.getByRole("alert")).getByText("write ranking.json: no space left on device")).toBeInTheDocument()
    expect(screen.queryByText("second line of the cause", { exact: false })).not.toBeInTheDocument()
    expect(within(screen.getByRole("alert")).getByRole("button", { name: "Retry" })).toBeInTheDocument()
  })

  it("names the step of an analysis that recorded no cause", () => {
    renderScreen(failed("scan-project", ""))

    expect(within(screen.getByRole("alert")).getByText(/It stopped while scanning the project\./)).toBeInTheDocument()
  })

  it("uses no red for a cancel", async () => {
    const { container } = renderScreen(analysisIn("cancelled"))

    expect(screen.getByRole("heading", { level: 1, name: "Analysis cancelled" })).toBeInTheDocument()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    expect(container.querySelector("[class*='bad']")).toBeNull()
    expect(screen.queryByText("See your administrators")).not.toBeInTheDocument()
    const actions = [...container.querySelectorAll("a, button")].slice(-2).map((element) => element.textContent)
    expect(actions).toEqual(["Replace package.json", "Start again"])
    fireEvent.click(screen.getByRole("button", { name: "Start again" }))
    await vi.waitFor(() => expect(queueAnalysis).toHaveBeenCalledWith("web-portal"))
  })

  it("offers Start again after an interruption", () => {
    renderScreen(analysisIn("interrupted"))

    expect(screen.getByRole("heading", { level: 1, name: "Analysis interrupted" })).toBeInTheDocument()
    expect(screen.getByText("The server restarted while it ran. Your package.json is kept.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Start again" })).toBeInTheDocument()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })
})

describe("analysisCause", () => {
  it.each([
    [
      "a pinned version not on npm",
      { step: "resolve-project", message: "resolve project: pnpm install: ERR_PNPM_NO_MATCHING_VERSION No matching version found for left-pad@99.0.0: exit status 1" },
      { title: "A pinned version is not on npm", count: "1 package", items: [{ name: "left-pad", value: "99.0.0" }], action: "replace" },
    ],
    [
      "a refused connection",
      { step: "resolve-candidates", message: "resolve candidates: pnpm install: request to http://10.0.0.1:4873/react failed, reason: connect ECONNREFUSED 10.0.0.1:4873" },
      { title: "No answer from 10.0.0.1", action: "retry" },
    ],
    [
      "a timeout that names no host",
      { step: "resolve-project", message: "resolve project: pnpm install: ERR_SOCKET_TIMEOUT Socket timeout" },
      { title: "No answer from the registry", action: "retry" },
    ],
    [
      "the vulnerability database",
      { step: "scan-project", message: "scan project: trivy: exit status 1: database download failed: dial tcp: lookup ghcr.io: no such host" },
      { title: "The vulnerability database did not download", action: "retry" },
    ],
  ])("reads %s", (_, failure, expected) => {
    expect(analysisCause({ state: "failed", failure })).toMatchObject(expected)
  })

  it("asks to start again after a cancel or an interruption", () => {
    expect(analysisCause({ state: "cancelled" }).action).toBe("start-again")
    expect(analysisCause({ state: "interrupted" }).action).toBe("start-again")
  })
})
