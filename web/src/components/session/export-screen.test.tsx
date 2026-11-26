import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { apiFetch } from "@/api/client"
import { cancelExport, getAnalysisLog, queueExport, type Analysis, type Export, type Project } from "@/api/projects"
import { getInstance, getSigningKey, type Instance } from "@/api/settings"
import type { StepId } from "@/components/step-bar"
import { ExportScreen } from "@/components/session/export-screen"
import { useJobEvents } from "@/hooks/use-job-events"
import { initialAnalysisEventsState, type AnalysisEventsState } from "@/lib/analysisEvents"

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client")
  return { ...actual, apiFetch: vi.fn() }
})
vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSigningKey: vi.fn(), getInstance: vi.fn() }
})
vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn(), cancelExport: vi.fn(), getAnalysisLog: vi.fn() }
})
vi.mock("@/hooks/use-job-events", () => ({ useJobEvents: vi.fn() }))
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to, ...rest }: { children: ReactNode; to: string }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
  useNavigate: () => vi.fn(),
}))

const KEY = "a".repeat(64)
const ARCHIVE_SHA = "9c1e4b7a3f5d2c8e1a6b0d4f7c2e9a5b3d8f1c6e0a4b7d2f9c5e8a1b3d6f1a3b"
const ALL_FILES = ["findings.csv", "manifest.json", "manifest.json.sig", "packages_npm.tar.gz", "report.cdx.json", "report.trivy.json", "summary.md"]

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" } as Project["target"]
const analysis = { id: "20260921T101500Z", projectId: "demo", state: "done", createdAt: "2026-09-21T10:15:00Z" } as Analysis
const project = { id: "demo", name: "demo", ecosystem: "npm", target, createdAt: "2026-09-21T10:14:00Z", analyses: [analysis] } as Project

function exportRecord(over: Partial<Export>): Export {
  return { id: "20260921T102000Z", projectId: "demo", analysisId: analysis.id, state: "done", createdAt: "2026-09-21T10:20:00Z", files: ALL_FILES, ...over }
}

function client() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderScreen(record: Export, { of = analysis, on = project, onNavigateStep = vi.fn<(step: StepId) => void>() } = {}) {
  const view = render(
    <QueryClientProvider client={client()}>
      <ExportScreen project={on} analysis={of} relatedExport={record} onChanged={() => {}} onNavigateStep={onNavigateStep} />
    </QueryClientProvider>,
  )
  return { ...view, onNavigateStep }
}

// manifest.json as the export writes it: its archive and every package it packed.
const MANIFEST = { analysisId: analysis.id, archive: { sha256: ARCHIVE_SHA, size: 101_187_584 }, packages: Array.from({ length: 1284 }, (_, i) => ({ name: `lib-${i}` })) }

function serve(manifest: () => Promise<unknown> = () => Promise.resolve(MANIFEST)) {
  vi.mocked(apiFetch).mockImplementation((path: string) => {
    if (path.endsWith("/files/manifest.json")) return manifest() as never
    if (path.endsWith("/files/manifest.json.sig")) return Promise.resolve({ algorithm: "ed25519", publicKeySha256: KEY, signature: "AAAA" }) as never
    return Promise.reject(new Error(`unexpected request ${path}`))
  })
}

function instance(ephemeral: boolean): Instance {
  return { ephemeral, idleMinutes: 30, ready: true, preparing: [], brand: { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false } } as unknown as Instance
}

const events = (over: Partial<AnalysisEventsState>) => vi.mocked(useJobEvents).mockReturnValue({ ...initialAnalysisEventsState, ...over })

// Download links start no navigation in jsdom; the page only needs to see the press.
const stopNavigation = (event: MouseEvent) => {
  if ((event.target as Element).closest("a[download]")) event.preventDefault()
}

beforeEach(() => {
  vi.mocked(apiFetch).mockReset()
  vi.mocked(getSigningKey).mockReset().mockResolvedValue({ publicKeyPem: "pem", publicKeySha256: KEY })
  vi.mocked(getInstance).mockReset().mockResolvedValue(instance(false))
  vi.mocked(getAnalysisLog).mockReset().mockResolvedValue("")
  vi.mocked(useJobEvents).mockReset().mockReturnValue(initialAnalysisEventsState)
  vi.mocked(queueExport).mockReset()
  vi.mocked(cancelExport).mockReset()
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
  document.addEventListener("click", stopNavigation, true)
  sessionStorage.clear()
})

afterEach(() => {
  document.removeEventListener("click", stopNavigation, true)
  vi.restoreAllMocks()
})

describe("sealing", () => {
  it("shows the packages downloaded and the time left", () => {
    events({
      steps: [
        { name: "prepare", state: "done", durationMs: 40 },
        { name: "package-list", state: "done", durationMs: 120 },
        { name: "download", state: "running" },
      ],
      progressByStep: { download: { step: "download", done: 796, total: 1284, cacheHits: 12, estimatedRemainingMs: 120_000 } },
    })
    renderScreen(exportRecord({ state: "running", files: undefined }))
    expect(screen.getByRole("heading", { level: 1, name: "About 2 minutes left" })).toBeInTheDocument()
    expect(screen.getByText(/of/, { selector: "p" })).toHaveTextContent("796 of 1,284 packages downloaded")
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "62")
    expect(screen.getByRole("region", { name: "Log" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
  })

  it("names the step in words while no time left is known", () => {
    events({ steps: [{ name: "prepare", state: "running" }] })
    renderScreen(exportRecord({ state: "running", files: undefined }))
    expect(screen.getByRole("heading", { level: 1, name: "Reading the signing key" })).toBeInTheDocument()
    expect(screen.getByRole("progressbar")).toHaveAttribute("data-estimating")
  })

  it("asks before a cancel and sends it only on the confirm", async () => {
    vi.mocked(cancelExport).mockResolvedValue(exportRecord({ state: "cancelled" }))
    events({ steps: [{ name: "download", state: "running" }] })
    renderScreen(exportRecord({ state: "running", files: undefined }))
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(screen.getByText("The downloads so far stop here. Your selection and its reasons are kept.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Keep sealing" })).toHaveFocus()
    expect(cancelExport).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Cancel sealing" }))
    await waitFor(() => expect(cancelExport).toHaveBeenCalledWith("demo", "20260921T102000Z"))
  })
})

describe("a queued export", () => {
  it("says it waits for the running job and keeps its place", () => {
    renderScreen(exportRecord({ state: "queued", files: undefined }))
    expect(screen.getByRole("heading", { level: 1, name: "Waits for the running job" })).toBeInTheDocument()
    expect(screen.getByText("One job runs at a time.")).toBeInTheDocument()
    expect(screen.getByText("Keeps its place if you leave this page")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument()
  })
})

describe("a cancelled export", () => {
  it.each([
    ["cancelled while queued", exportRecord({ state: "cancelled", files: undefined }), {}],
    ["cancelled while it ran", exportRecord({ state: "running", files: undefined }), { ended: true, endState: "cancelled" as const }],
  ])("returns to Ready to seal after a cancelled export (%s)", (_name, record, stream) => {
    sessionStorage.setItem(`sealift:selection:${analysis.id}`, JSON.stringify({ express: ["5.1.0"] }))
    sessionStorage.setItem(`sealift:reasons:${analysis.id}`, JSON.stringify({ "major-jump:express": "the routes need express 5" }))
    events(stream)
    const { onNavigateStep } = renderScreen(record)
    expect(onNavigateStep).toHaveBeenCalledWith("review")
    expect(screen.queryByRole("heading", { name: "Sealed" })).not.toBeInTheDocument()
    expect(screen.queryByRole("heading", { name: /failed|stopped/i })).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(`sealift:selection:${analysis.id}`) ?? "{}")).toEqual({ express: ["5.1.0"] })
    expect(JSON.parse(sessionStorage.getItem(`sealift:reasons:${analysis.id}`) ?? "{}")).toEqual({ "major-jump:express": "the routes need express 5" })
  })
})

describe("a failed export", () => {
  it("names a failed step in words", async () => {
    renderScreen(exportRecord({ state: "failed", files: undefined, failure: { step: "prepare", message: "jobs: read signing key: permission denied" } as Export["failure"] }))
    expect(screen.getByRole("heading", { level: 1, name: "Sealing stopped" })).toBeInTheDocument()
    const cause = screen.getByRole("alert")
    expect(cause).toHaveTextContent("jobs: read signing key: permission denied")
    expect(cause).toHaveTextContent("It stopped while reading the signing key.")
    expect(within(cause).getByRole("button", { name: "Retry" })).toBeInTheDocument()
    expect(apiFetch).not.toHaveBeenCalled()
  })

  it("says a registry that did not answer by its host", () => {
    const message = "jobs: download express@5.1.0: Get \"https://registry.npmjs.org/express/-/express-5.1.0.tgz\": dial tcp: lookup registry.npmjs.org: no such host"
    renderScreen(exportRecord({ state: "failed", files: undefined, failure: { step: "download", message } as Export["failure"] }))
    const cause = screen.getByRole("alert")
    expect(cause).toHaveTextContent("No answer from registry.npmjs.org")
    expect(cause).toHaveTextContent("It stopped while downloading and verifying each package.")
    expect(cause).not.toHaveTextContent("dial tcp")
  })

  it("gives an export's own cause, never the analysis' database words", () => {
    const message = "jobs: write the package database index: no space left on device"
    renderScreen(exportRecord({ state: "failed", files: undefined, failure: { step: "archive", message } as Export["failure"] }))
    const cause = screen.getByRole("alert")
    expect(cause).not.toHaveTextContent(/vulnerability database/i)
    expect(cause).not.toHaveTextContent("package.json")
    expect(cause).toHaveTextContent(message)
  })

  it("does not fold the analysis log under a failed export", async () => {
    vi.mocked(getAnalysisLog).mockResolvedValue("resolve: lodash 4.17.21\n")
    renderScreen(exportRecord({ state: "failed", files: undefined, failure: { step: "download", message: "registry unreachable" } as Export["failure"] }))
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(getAnalysisLog).not.toHaveBeenCalled()
    expect(screen.queryByText("resolve: lodash 4.17.21")).not.toBeInTheDocument()
  })

  it("sends the same reasons on a retry", async () => {
    const analysed = {
      ...analysis,
      result: {
        target, before: [0, 0, 1, 0, 0], warnings: [], families: [],
        dependencies: [
          {
            name: "express", current: "4.17.1", jump: "5.1.0", vector: [0, 0, 0, 0, 0], cves: [],
            candidates: [{ version: "5.1.0", vector: [0, 0, 0, 0, 0], cves: [], signals: [], key: true, resolved: true, leavesLine: true }],
          },
          {
            name: "html-minifier", current: "4.0.0", vector: [0, 0, 1, 0, 0], candidates: [],
            cves: [{ id: "CVE-2022-37620", severity: "MEDIUM", package: "html-minifier@4.0.0", fixedIn: "" }],
          },
        ],
      },
    } as Analysis
    sessionStorage.setItem(`sealift:selection:${analysis.id}`, JSON.stringify({ express: ["5.1.0"] }))
    sessionStorage.setItem(
      `sealift:reasons:${analysis.id}`,
      JSON.stringify({ "major-jump:express": "the routes need express 5", "cve-without-fix:html-minifier": "build tool, never shipped" }),
    )
    vi.mocked(queueExport).mockResolvedValue(exportRecord({ id: "20260921T103000Z", state: "queued" }))
    renderScreen(exportRecord({ state: "failed", files: undefined, failure: { step: "download", message: "registry unreachable" } as Export["failure"] }), { of: analysed })

    fireEvent.click(screen.getByRole("button", { name: "Retry" }))
    await waitFor(() => expect(queueExport).toHaveBeenCalled())
    expect(vi.mocked(queueExport).mock.calls[0][2]).toEqual({
      selection: { express: ["5.1.0"] },
      includeProject: false,
      reasons: [
        { kind: "major-jump", dependencies: ["express"], text: "the routes need express 5" },
        { kind: "cve-without-fix", dependencies: ["html-minifier"], text: "build tool, never shipped" },
      ],
    })
  })
})

describe("sealed", () => {
  it("shows Sealed only once the manifest reads", async () => {
    let read: (value: unknown) => void = () => {}
    serve(() => new Promise((resolve) => (read = resolve)))
    renderScreen(exportRecord({}))
    expect(await screen.findAllByText("Reading manifest.json")).not.toHaveLength(0)
    expect(screen.queryByRole("heading", { name: "Sealed" })).not.toBeInTheDocument()
    await act(async () => read(MANIFEST))
    expect(await screen.findByRole("heading", { level: 1, name: "Sealed" })).toBeInTheDocument()
    expect(screen.getByText(/^demo · 21 Sept/)).toBeInTheDocument()
  })

  it("never shows Sealed when the manifest does not read", async () => {
    serve(() => Promise.reject(new Error("no file manifest.json in this export")))
    renderScreen(exportRecord({}))
    expect(await screen.findAllByText(/Could not read manifest\.json/)).not.toHaveLength(0)
    expect(screen.queryByRole("heading", { name: "Sealed" })).not.toBeInTheDocument()
  })

  it("puts Download all in the header of the files to carry", async () => {
    serve()
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    const carry = screen.getByRole("region", { name: /^To carry/ })
    const all = within(carry).getByRole("button", { name: "Download all" })
    expect(all).toHaveClass("bg-ink")
    expect(all.closest("div")?.querySelector("h4")).toHaveTextContent("To carry · 3 files")
    const archive = within(carry).getByText("packages_npm.tar.gz").closest("p") as HTMLElement
    expect(archive).toHaveTextContent("packages_npm.tar.gz · 1,284 packages · 96.5 MB")
    expect(within(archive).getByText("1,284")).toHaveClass("figure")
    expect(within(carry).getByRole("button", { name: /^sha256 of packages_npm\.tar\.gz 9c1e4b7a to 3d6f1a3b/ })).toBeInTheDocument()
    expect(screen.getByRole("region", { name: /^Reports/ })).toBeInTheDocument()
  })

  it("leaves out the figures a manifest does not hold", async () => {
    serve(() => Promise.resolve({ archive: { sha256: ARCHIVE_SHA } }))
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    const archive = screen.getByText("packages_npm.tar.gz").closest("p") as HTMLElement
    expect(archive).toHaveTextContent(/^packages_npm\.tar\.gz$/)
  })

  it("shows no text for the PR", async () => {
    serve()
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    expect(document.body).not.toHaveTextContent(/\bPR\b/)
    expect(document.body).not.toHaveTextContent(/Add to your/i)
  })

  it("keeps Done disabled until a download of a file to carry starts", async () => {
    serve()
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    const done = screen.getByRole("button", { name: "Done" })
    expect(done).toHaveAttribute("aria-disabled", "true")
    const cause = screen.getByText("Opens once a download starts")
    expect(cause.compareDocumentPosition(done) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.queryByRole("link", { name: "Done" })).not.toBeInTheDocument()
  })

  it.each([["Download all"], ["Download packages_npm.tar.gz"], ["Download manifest.json"], ["Download manifest.json.sig"]])(
    "opens Done after Download all or a file's own download (%s)",
    async (name) => {
      serve()
      renderScreen(exportRecord({}))
      await screen.findByRole("heading", { name: "Sealed" })
      const carry = screen.getByRole("region", { name: /^To carry/ })
      fireEvent.click(within(carry).getByRole(name === "Download all" ? "button" : "link", { name }))
      expect(screen.getByRole("link", { name: "Done" })).toHaveAttribute("href", "/")
      expect(screen.queryByText("Opens once a download starts")).not.toBeInTheDocument()
    },
  )

  it("keeps Done open on a reload of the same tab", async () => {
    serve()
    const first = renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    fireEvent.click(screen.getByRole("button", { name: "Download all" }))
    first.unmount()
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    expect(screen.getByRole("link", { name: "Done" })).toBeInTheDocument()
  })

  it("does not open Done on a report's Open or download", async () => {
    serve()
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response("# demo\n", { status: 200 }))))
    const open = vi.spyOn(window, "open").mockReturnValue(null)
    URL.createObjectURL = vi.fn(() => "blob:summary")
    URL.revokeObjectURL = vi.fn()
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    const reports = screen.getByRole("region", { name: /^Reports/ })
    fireEvent.click(within(reports).getByRole("button", { name: "Open summary.md" }))
    await waitFor(() => expect(open).toHaveBeenCalled())
    fireEvent.click(within(reports).getByRole("link", { name: "Download summary.md" }))
    expect(screen.getByRole("button", { name: "Done" })).toHaveAttribute("aria-disabled", "true")
    vi.unstubAllGlobals()
  })

  it("wraps a 40-character project name in the crossing's name", async () => {
    serve()
    const long = { ...project, name: "analytics-ingest-pipeline-airflow-worker" }
    renderScreen(exportRecord({}), { on: long })
    await screen.findByRole("heading", { name: "Sealed" })
    expect(screen.getByText(/^analytics-ingest-pipeline-airflow-worker · 21 Sept/)).toHaveClass("[overflow-wrap:anywhere]")
  })

  it("shows the erase row on an ephemeral instance only", async () => {
    serve()
    vi.mocked(getInstance).mockResolvedValue(instance(true))
    const first = renderScreen(exportRecord({}))
    expect(await screen.findByRole("button", { name: "Erase now" })).toBeInTheDocument()
    expect(screen.getByText("30 minutes")).toBeInTheDocument()
    first.unmount()
    vi.mocked(getInstance).mockResolvedValue(instance(false))
    renderScreen(exportRecord({}))
    await screen.findByRole("heading", { name: "Sealed" })
    await waitFor(() => expect(getInstance).toHaveBeenCalledTimes(2))
    expect(screen.queryByRole("button", { name: "Erase now" })).not.toBeInTheDocument()
  })
})
