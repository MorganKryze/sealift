import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getProjectManifest, queueExport, type Analysis, type Candidate, type DependencyResult, type Export, type Project } from "@/api/projects"
import { ReviewScreen } from "@/components/session/review-screen"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn(), getProjectManifest: vi.fn() }
})
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  useNavigate: () => vi.fn(),
}))

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" }
const published = "2025-03-31T14:00:00Z"

function candidate(version: string, overrides: Partial<Candidate> = {}): Candidate {
  return { version, vector: [0, 0, 0, 0, 0], cves: [], signals: [], key: true, resolved: true, leavesLine: false, published, ...overrides }
}
const cve = (id: string, severity: string, pkg: string, fixedIn?: string) => ({ id, severity, package: pkg, ...(fixedIn === undefined ? {} : { fixedIn }) })
const vectorOf = (cves: { severity: string }[]) =>
  ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => cves.filter((c) => c.severity === s).length)

function update(name: string, current: string, to: string, cves: DependencyResult["cves"]): DependencyResult {
  return { name, current, best: to, vector: vectorOf(cves), cves, candidates: [candidate(to)] }
}
function withoutFix(name: string, current: string, cves: DependencyResult["cves"]): DependencyResult {
  return { name, current, vector: vectorOf(cves), cves, candidates: [] }
}
function jumper(name: string, current: string, jump: string, familyName?: string): DependencyResult {
  return { name, current, jump, ...(familyName ? { family: familyName } : {}), vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate(jump, { leavesLine: true })] }
}
function unchanged(name: string): DependencyResult {
  return { name, current: "1.0.0", vector: [0, 0, 0, 0, 0], cves: [], candidates: [] }
}

function analysisOf(id: string, dependencies: DependencyResult[], families?: { name: string; members: string[] }[]): Analysis {
  const before = dependencies.reduce((t, d) => t.map((n, i) => n + (d.vector[i] ?? 0)), [0, 0, 0, 0, 0])
  return {
    id, projectId: "demo", state: "done", createdAt: "2026-11-24T10:15:00Z",
    result: { target, before, dependencies, warnings: [], ...(families ? { families } : {}) },
  } as Analysis
}
const projectOf = (analysis: Analysis) =>
  ({ id: "demo", name: "kiosk-ui", target, createdAt: "2026-11-24T10:14:00Z", analyses: [analysis], exports: [] }) as unknown as Project

// One reason missing: html-minifier keeps a CVE that no version fixes; lodash and express update; esbuild keeps its major.
const oneMissing = analysisOf("20261124T101500Z", [
  withoutFix("html-minifier", "4.0.0", [cve("CVE-2022-37620", "HIGH", "html-minifier@4.0.0", "")]),
  update("lodash", "4.17.20", "4.17.21", [cve("CVE-2021-23337", "HIGH", "lodash@4.17.20", "4.17.21"), cve("CVE-2020-8203", "HIGH", "lodash@4.17.20", "4.17.19")]),
  update("express", "4.18.2", "4.21.2", [cve("CVE-2024-29041", "MEDIUM", "express@4.18.2", "4.19.2, 5.0.0")]),
  {
    ...jumper("esbuild", "0.21.5", "0.25.12"),
    vector: [0, 0, 1, 0, 0],
    cves: [cve("GHSA-67mh-4wv8-2f99", "MEDIUM", "esbuild@0.21.5", "0.25.0")],
  },
  unchanged("left-pad"),
])

// The worst case: 15 major jumps in 3 families, 15 CVEs with no fix in 5 packages, a long scoped name and version.
const members = {
  "react 19": [["react", "18.3.1", "19.2.0"], ["react-dom", "18.3.1", "19.2.0"], ["@types/react", "18.3.12", "19.2.2"], ["@types/react-dom", "18.3.1", "19.2.2"], ["react-router-dom", "6.30.1", "7.9.4"], ["@testing-library/react", "15.0.7", "16.3.0"], ["react-redux", "8.1.3", "9.2.0"]],
  "eslint 9": [["eslint", "8.57.1", "9.38.0"], ["eslint-plugin-react-hooks", "4.6.2", "5.2.0"], ["@typescript-eslint/parser", "7.18.0", "8.46.1"], ["@typescript-eslint/eslint-plugin", "7.18.0", "8.46.1"], ["eslint-config-prettier", "9.1.0", "10.1.8"]],
  "vite 7": [["vite", "5.4.20", "7.1.12"], ["@vitejs/plugin-react", "4.7.0", "5.1.0"], ["vitest", "2.1.9", "4.0.8"]],
} as Record<string, [string, string, string][]>
const angularCves = [cve("CVE-2024-21490", "HIGH", "angular@1.8.3", ""), ...Array.from({ length: 10 }, (_, i) => cve(`CVE-2025-${4690 + i}`, "MEDIUM", "angular@1.8.3", ""))]
const babel = "@babel/plugin-transform-async-generator-functions"
const worst = analysisOf(
  "20261124T111500Z",
  [
    ...Object.entries(members).flatMap(([familyName, list]) => list.map(([name, from, to]) => jumper(name, from, to, familyName))),
    withoutFix("angular", "1.8.3", angularCves),
    withoutFix("html-minifier", "4.0.0", [cve("CVE-2022-37620", "HIGH", "html-minifier@4.0.0", "")]),
    withoutFix("lodash.template", "4.5.0", [cve("CVE-2021-23337", "HIGH", "lodash.template@4.5.0", "")]),
    withoutFix(babel, "1.0.0-beta.12+build.345", [cve("GHSA-2fx7-6rpj-5w4c", "HIGH", `${babel}@1.0.0-beta.12+build.345`, "")]),
    withoutFix("request", "2.88.2", [cve("CVE-2023-28155", "MEDIUM", "request@2.88.2", "")]),
    update("lodash", "4.17.20", "4.17.21", [cve("CVE-2021-23337", "HIGH", "lodash@4.17.20", "4.17.21")]),
    ...Array.from({ length: 5 }, (_, i) => unchanged(`unchanged-${i + 1}`)),
  ],
  Object.entries(members).map(([name, list]) => ({ name, members: list.map(([n]) => n).sort() })),
)
const worstSelection = Object.fromEntries(Object.values(members).flat().map(([name, , to]) => [name, [to]]))
const worstReasons = {
  "major-jump:react 19": "Moved to React 19 in branch react-19, all tests green",
  "major-jump:eslint 9": "Flat config done in PR #412, lint passes on main",
  "major-jump:vite 7": "CI and every dev machine run Node 22; Vite 7 builds the app",
  "cve-without-fix:html-minifier": "Dev dependency, runs at build time on our own HTML",
  "cve-without-fix:lodash.template": "Templates are our own files, never user input",
}

function renderReview(analysis: Analysis, storage: { selection?: object; reasons?: object } = {}) {
  if (storage.selection) sessionStorage.setItem(`sealift:selection:${analysis.id}`, JSON.stringify(storage.selection))
  if (storage.reasons) sessionStorage.setItem(`sealift:reasons:${analysis.id}`, JSON.stringify(storage.reasons))
  const onNavigateStep = vi.fn()
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <ReviewScreen project={projectOf(analysis)} analysis={analysis} onNavigateStep={onNavigateStep} />
    </QueryClientProvider>,
  )
  return { onNavigateStep }
}

const seal = () => screen.getByRole("button", { name: "Seal" })
const precedes = (a: Node, b: Node) => (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
const terms = (name: string) => screen.queryAllByRole("button", { name })

beforeEach(() => {
  sessionStorage.clear()
  vi.mocked(queueExport).mockReset()
  vi.mocked(getProjectManifest).mockReset().mockResolvedValue(JSON.stringify({ name: "kiosk-ui", dependencies: {} }))
})

describe("ReviewScreen", () => {
  it("titles what needs you with the known CVEs before and after", () => {
    renderReview(oneMissing)
    expect(screen.getByRole("heading", { level: 1, name: "One thing needs you" })).toBeInTheDocument()
    const known = screen.getByText("Known CVEs", { selector: "[data-known-cves] *" }).closest("[data-known-cves]") as HTMLElement
    // 5 before; the proposal fixes lodash's two and express's one, so html-minifier's and esbuild's stay.
    expect(known).toHaveTextContent("Known CVEs 5 to 2")
    expect(screen.queryByText(/Review the proposal/)).toBeNull()
  })

  it("counts every thing that needs you", () => {
    renderReview(worst, { selection: worstSelection, reasons: worstReasons })
    expect(screen.getByRole("heading", { level: 1, name: "3 things need you" })).toBeInTheDocument()
  })

  it("opens a group in place with its version changes", () => {
    renderReview(oneMissing)
    const updated = screen.getByRole("button", { name: /^2 packages updated/ })
    expect(updated).toHaveAttribute("aria-expanded", "false")
    expect(updated).toHaveTextContent("3 known CVEs fixed")
    expect(within(updated).getByText("3", { selector: ".figure" })).toBeInTheDocument()
    expect(screen.queryByText("lodash", { selector: "td *, td" })).toBeNull()
    fireEvent.click(updated)
    expect(updated).toHaveAttribute("aria-expanded", "true")
    const row = screen.getByText("lodash", { selector: "td *, td" }).closest("tr") as HTMLElement
    const change = within(row).getByText("4.17.20").closest("[data-version-change]") as HTMLElement
    expect(change).toHaveTextContent("4.17.20 to 4.17.21")
    expect(within(change).getByText("21", { selector: "strong" })).toBeInTheDocument()
    expect(within(row).getByText("2 high")).toBeInTheDocument()
    expect(within(row).getByText(/year|month|day/)).toBeInTheDocument()

    const expressRow = screen.getByText("express", { selector: "td *, td" }).closest("tr") as HTMLElement
    expect(within(expressRow).getByText("21.2", { selector: "strong" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^1 package kept on their major/ })).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByRole("button", { name: /^1 package unchanged/ })).toBeInTheDocument()
  })

  it("keeps Seal disabled and names every package that waits", () => {
    renderReview(worst, { selection: worstSelection, reasons: worstReasons })
    const cause = screen.getByText(`Opens once angular, ${babel} and request have a reason.`)
    expect(seal()).toHaveAttribute("aria-disabled", "true")
    expect(seal()).toHaveAccessibleDescription(cause.textContent ?? "")
    expect(precedes(cause, seal())).toBe(true)
    fireEvent.click(seal())
    expect(queueExport).not.toHaveBeenCalled()
  })

  it("names one package that waits in the singular", () => {
    renderReview(oneMissing)
    expect(screen.getByText("Opens once html-minifier has a reason.")).toBeInTheDocument()
    expect(seal()).toHaveAttribute("aria-disabled", "true")
  })

  it("seals once every reason is written and moves on to the Seal step", async () => {
    vi.mocked(queueExport).mockResolvedValue({ id: "x", projectId: "demo", analysisId: oneMissing.id, state: "queued", createdAt: "" } as Export)
    const { onNavigateStep } = renderReview(oneMissing, { reasons: { "cve-without-fix:html-minifier": "build tool, never shipped" } })
    expect(screen.queryByText(/^Opens once/)).toBeNull()
    expect(seal()).not.toHaveAttribute("aria-disabled")
    fireEvent.click(seal())
    await waitFor(() => expect(onNavigateStep).toHaveBeenCalledWith("export"))
    expect(vi.mocked(queueExport).mock.calls[0][2]).toEqual({
      selection: { lodash: ["4.17.21"], express: ["4.21.2"] },
      includeProject: false,
      reasons: [{ kind: "cve-without-fix", dependencies: ["html-minifier"], text: "build tool, never shipped" }],
    })
  })

  it("offers no Jump where none was recorded", () => {
    // What sealift 0.7.0 wrote: no jump, no family, no families, CVEs without their package or fix.
    const old = analysisOf("20261001T101500Z", [
      { name: "angular", current: "1.8.3", vector: [0, 1, 0, 0, 0], cves: [{ id: "CVE-2024-21490", severity: "HIGH" }], candidates: [candidate("2.0.0", { leavesLine: true })] },
      { name: "chalk", current: "4.1.2", vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate("5.3.0", { leavesLine: true })] },
      update("lodash", "4.17.20", "4.17.21", [{ id: "CVE-2021-23337", severity: "HIGH" }]),
    ])
    renderReview(old)
    expect(screen.queryAllByRole("button", { name: /^Jump/ })).toEqual([])
    expect(screen.queryByRole("button", { name: /kept on their major/ })).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: /packages? unchanged/ }))
    fireEvent.click(screen.getByRole("button", { name: /packages? updated/ }))
    expect(screen.queryAllByRole("button", { name: /^Jump/ })).toEqual([])
    expect(screen.getByText("angular", { selector: "[data-reason-name]" })).toBeInTheDocument()
    expect(screen.getByText("fix not recorded")).toBeInTheDocument()
    expect(screen.getByText("chalk", { selector: "td *, td" })).toBeInTheDocument()
  })

  it("puts one info button per term at its first place", () => {
    renderReview(worst, { selection: worstSelection, reasons: worstReasons })
    const jumpsBand = screen.getByRole("group", { name: /major jumps/ })
    const cveBand = screen.getByRole("group", { name: /known CVEs with no fixed version/ })
    expect(terms("What a CVE is")).toHaveLength(1)
    expect(cveBand).toContainElement(terms("What a CVE is")[0])
    expect(terms("What a major jump is")).toHaveLength(1)
    expect(jumpsBand).toContainElement(terms("What a major jump is")[0])
    expect(terms("What a severity is")).toHaveLength(1)
    expect(screen.getByText("angular", { selector: "[data-reason-name]" }).closest("[data-reason-row]")).toContainElement(terms("What a severity is")[0])
    expect(screen.getByRole("button", { name: /^1 package updated/ })).toHaveTextContent("1 known CVE fixed")
    fireEvent.click(screen.getByRole("button", { name: /^1 package updated/ }))
    expect(terms("What a CVE is")).toHaveLength(1)
    expect(terms("What a severity is")).toHaveLength(1)
    expect(terms("What a major jump is")).toHaveLength(1)
  })

  it("puts the info buttons on the title and the kept row when the reasons block is absent", () => {
    const calm = analysisOf("20261124T121500Z", oneMissing.result!.dependencies.filter((d) => d.name !== "html-minifier"))
    renderReview(calm)
    expect(screen.queryByRole("group", { name: /major jumps|known CVEs/ })).toBeNull()
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Ready to seal")
    expect(terms("What a CVE is")).toHaveLength(1)
    expect(screen.getByText("Known CVEs", { selector: "[data-known-cves] *" }).closest("[data-known-cves]")).toContainElement(terms("What a CVE is")[0])
    expect(terms("What a major jump is")).toHaveLength(1)
    const kept = screen.getByRole("button", { name: /^1 package kept on their major/ })
    expect(kept.closest("[data-group]")).toContainElement(terms("What a major jump is")[0])
    expect(terms("What a severity is")).toHaveLength(0)
    fireEvent.click(screen.getByRole("button", { name: /^2 packages updated/ }))
    fireEvent.click(kept)
    expect(terms("What a severity is")).toHaveLength(1)
    const lodashRow = screen.getByText("lodash", { selector: "td *, td" }).closest("tr") as HTMLElement
    expect(lodashRow).toContainElement(terms("What a severity is")[0])
    expect(terms("What a CVE is")).toHaveLength(1)
    expect(terms("What a major jump is")).toHaveLength(1)
  })
})
