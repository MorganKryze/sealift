import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { queueExport, type Analysis, type Candidate, type DependencyResult, type Export, type Project } from "@/api/projects"
import { getSettings } from "@/api/settings"
import { ReviewScreen } from "@/components/session/review-screen"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn() }
})
vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSettings: vi.fn() }
})
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  useNavigate: () => vi.fn(),
}))

function candidate(version: string, leavesLine = false): Candidate {
  return { version, vector: [0, 0, 0, 0, 0], cves: [], signals: [], key: true, resolved: true, leavesLine }
}

const dependencies: DependencyResult[] = [
  { name: "react", current: "18.2.0", jump: "19.2.0", family: "react 19", vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate("18.3.1"), candidate("19.2.0", true)] },
  { name: "react-dom", current: "18.2.0", jump: "19.2.0", family: "react 19", vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate("18.3.1"), candidate("19.2.0", true)] },
  {
    name: "html-minifier", current: "4.0.0", vector: [0, 0, 1, 0, 0], candidates: [],
    cves: [{ id: "CVE-2022-37620", severity: "MEDIUM", package: "html-minifier@4.0.0", fixedIn: "" }],
  },
]

const analysis = {
  id: "20261124T101500Z", projectId: "demo", state: "done", createdAt: "2026-11-24T10:15:00Z",
  result: {
    target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" },
    before: [0, 0, 1, 0, 0], dependencies, warnings: [],
    families: [{ name: "react 19", members: ["react", "react-dom"] }],
  },
} as Analysis
const project = {
  id: "demo", name: "demo", target: analysis.result!.target, createdAt: "2026-11-24T10:14:00Z", analyses: [analysis], exports: [],
} as unknown as Project

function renderReview() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <ReviewScreen project={project} analysis={analysis} onNavigateStep={() => {}} />
    </QueryClientProvider>,
  )
}

const exportButton = () => screen.getByRole("button", { name: "Confirm and build the archive" })
const write = (label: RegExp, text: string) => fireEvent.change(screen.getByLabelText(label), { target: { value: text } })
const precedes = (a: Node, b: Node) => (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0

beforeEach(() => {
  sessionStorage.clear()
  sessionStorage.setItem(`sealift:selection:${analysis.id}`, JSON.stringify({ react: ["19.2.0"], "react-dom": ["19.2.0"] }))
  vi.mocked(getSettings).mockReset().mockResolvedValue({ minReleaseAgeDays: 7 } as never)
  vi.mocked(queueExport).mockReset()
})

describe("the reasons block on the review screen", () => {
  it("labels each field with its family or dependency", () => {
    renderReview()
    expect(screen.getByLabelText(/react 19/)).toHaveProperty("tagName", "TEXTAREA")
    expect(screen.getByLabelText(/html-minifier/)).toHaveProperty("tagName", "TEXTAREA")
    expect(screen.getByText("react 18.2.0 to 19.2.0, react-dom 18.2.0 to 19.2.0")).toBeInTheDocument()
    expect(screen.getByText("html-minifier 4.0.0 keeps CVE-2022-37620, with no known fix")).toBeInTheDocument()
  })

  it("numbers each field as the server's refusal counts them", () => {
    renderReview()
    expect(screen.getByLabelText(/^Reason 1\s*react 19/)).toHaveProperty("tagName", "TEXTAREA")
    expect(screen.getByLabelText(/^Reason 2\s*html-minifier/)).toHaveProperty("tagName", "TEXTAREA")
  })

  it("counts the characters as a reason nears its limit", () => {
    renderReview()
    write(/react 19/, "x".repeat(100))
    expect(screen.queryByText(/of 300 characters/)).toBeNull()
    write(/react 19/, "x".repeat(250))
    expect(screen.getByText("250 of 300 characters")).toBeInTheDocument()
    expect(screen.getByLabelText(/react 19/).getAttribute("aria-describedby")).toContain("-count")
  })

  it("keeps Export disabled with its cause before it", () => {
    renderReview()
    write(/react 19/, "   ")
    const cause = screen.getByText("2 reasons missing: react 19, html-minifier")
    expect(exportButton()).toBeDisabled()
    expect(precedes(cause, exportButton())).toBe(true)
    expect(exportButton()).toHaveAccessibleDescription("2 reasons missing: react 19, html-minifier")
  })

  it("enables Export once every reason is written", async () => {
    vi.mocked(queueExport).mockResolvedValue({ id: "x", projectId: "demo", analysisId: analysis.id, state: "queued", createdAt: "" } as Export)
    renderReview()
    write(/react 19/, "the new compiler needs React 19")
    expect(exportButton()).toBeDisabled()
    write(/html-minifier/, "build tool, never shipped")
    expect(exportButton()).toBeEnabled()
    expect(screen.queryByText(/reasons? missing/)).not.toBeInTheDocument()

    fireEvent.click(exportButton())
    await waitFor(() => expect(queueExport).toHaveBeenCalled())
    expect(vi.mocked(queueExport).mock.calls[0][2]).toEqual({
      selection: { react: ["19.2.0"], "react-dom": ["19.2.0"] },
      includeProject: false,
      reasons: [
        { kind: "major-jump", dependencies: ["react", "react-dom"], text: "the new compiler needs React 19" },
        { kind: "cve-without-fix", dependencies: ["html-minifier"], text: "build tool, never shipped" },
      ],
    })
  })

  it("refuses a line break in a reason", () => {
    renderReview()
    write(/react 19/, "first line\nsecond line")
    write(/html-minifier/, "build tool")
    const field = screen.getByLabelText(/react 19/)
    expect(field).toHaveAttribute("aria-invalid", "true")
    expect(field).toHaveAccessibleDescription(expect.stringContaining("Keep the reason on one line, with no tab or control character."))
    expect(exportButton()).toBeDisabled()
    expect(screen.getByText("1 reason to fix: react 19")).toBeInTheDocument()
  })

  it("shows the server's refusal above Export", async () => {
    const words = "review.majorJump is refuse: react 18.2.0 to 19.2.0 cannot cross"
    vi.mocked(queueExport).mockRejectedValue(
      new ProblemError(400, { type: "about:blank", title: "invalid export reasons", status: 400, detail: words }),
    )
    renderReview()
    write(/react 19/, "the new compiler needs React 19")
    write(/html-minifier/, "build tool, never shipped")
    fireEvent.click(exportButton())
    const refusal = await screen.findByText(words)
    expect(refusal.closest("[role=alert]")).not.toBeNull()
    expect(precedes(refusal, exportButton())).toBe(true)
  })

  it("keeps the reasons for the analysis across a remount", () => {
    renderReview()
    write(/react 19/, "the new compiler needs React 19")
    expect(JSON.parse(sessionStorage.getItem(`sealift:reasons:${analysis.id}`) ?? "{}")).toEqual({
      "major-jump:react 19": "the new compiler needs React 19",
    })
  })
})
