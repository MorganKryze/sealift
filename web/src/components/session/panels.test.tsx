import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getProjectManifest, type Analysis, type Candidate, type DependencyResult, type Project } from "@/api/projects"
import { DecidePanel, JumpPanel, PipDecidePanel, PipJumpPanel } from "@/components/session/review-panels"
import type { PipPackage } from "@/lib/pipReview"
import { ReviewScreen } from "@/components/session/review-screen"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn(), getProjectManifest: vi.fn() }
})
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  useNavigate: () => vi.fn(),
}))

function candidate(version: string, overrides: Partial<Candidate> = {}): Candidate {
  return { version, vector: [0, 0, 0, 0, 0], cves: [], signals: [], key: true, resolved: true, leavesLine: false, published: "2025-03-31T14:00:00Z", ...overrides }
}

const noFix = (id: string, severity: string, pkg: string) => ({ id, severity, package: pkg, fixedIn: "" })

const htmlMinifier: DependencyResult = {
  name: "html-minifier", current: "4.0.0", vector: [0, 1, 0, 0, 0], candidates: [],
  cves: [noFix("CVE-2022-37620", "HIGH", "html-minifier@4.0.0")],
}
const lodashTemplate: DependencyResult = {
  name: "lodash.template", current: "4.5.0", best: "4.6.0", vector: [0, 0, 1, 0, 0],
  cves: [{ id: "CVE-2019-10744", severity: "MEDIUM", package: "lodash.template@4.5.0", fixedIn: "4.5.1" }],
  candidates: [candidate("4.6.0", { vector: [0, 1, 0, 0, 0], cves: [noFix("CVE-2021-23337", "HIGH", "lodash.template@4.6.0")] })],
}
const family = (name: string, current: string, jump: string): DependencyResult => ({
  name, current, jump, family: "react 19", vector: [0, 0, 0, 0, 0], cves: [],
  candidates: [candidate(jump, { leavesLine: true })],
})
const esbuild: DependencyResult = {
  name: "esbuild", current: "0.21.5", jump: "0.25.12", vector: [0, 0, 1, 0, 0],
  cves: [{ id: "GHSA-67mh-4wv8-2f99", severity: "MEDIUM", package: "esbuild@0.21.5", fixedIn: "0.25.0" }],
  candidates: [candidate("0.25.12", { leavesLine: true, published: "2025-11-01T12:00:00Z" })],
}
const dependencies = [htmlMinifier, lodashTemplate, family("react", "18.3.1", "19.2.0"), family("react-dom", "18.3.1", "19.2.0"), family("@types/react", "18.3.12", "19.2.2"), esbuild]

const analysis = {
  id: "20261124T101500Z", projectId: "demo", state: "done", createdAt: "2026-11-24T10:15:00Z",
  result: {
    target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" },
    before: [0, 1, 2, 0, 0], dependencies, warnings: [],
    families: [{ name: "react 19", members: ["@types/react", "react", "react-dom"] }],
  },
} as Analysis
const project = {
  id: "demo", name: "web-portal", target: analysis.result!.target, createdAt: "2026-11-24T10:14:00Z", analyses: [analysis], exports: [],
} as unknown as Project

const stored = (key: "selection" | "reasons") => JSON.parse(sessionStorage.getItem(`sealift:${key}:${analysis.id}`) ?? "{}")

function renderReview() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <ReviewScreen project={project} analysis={analysis} onNavigateStep={() => {}} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  sessionStorage.clear()
  vi.mocked(getProjectManifest).mockReset().mockResolvedValue(
    JSON.stringify({ name: "web-portal", dependencies: { "lodash.template": "4.5.0", react: "18.3.1", "react-dom": "18.3.1", esbuild: "0.21.5" }, devDependencies: { "html-minifier": "4.0.0", "@types/react": "18.3.12" } }),
  )
})

const panel = () => screen.getByRole("dialog")
const rowOf = (name: string) => screen.getByText(name, { selector: "[data-reason-name]" }).closest("[data-reason-row]") as HTMLElement

describe("DecidePanel", () => {
  const angular: DependencyResult = {
    name: "angular", current: "1.8.3", vector: [0, 1, 1, 0, 0], candidates: [],
    cves: [noFix("CVE-2024-21490", "HIGH", "angular@1.8.3"), { id: "CVE-2025-4690", severity: "MEDIUM", package: "angular@1.8.3" }],
  }

  it("opens Decide with its CVEs and no fixed version", () => {
    render(<DecidePanel dependency={angular} dev reason="" onRecord={() => {}} onClose={() => {}} />)
    const dialog = panel()
    expect(within(dialog).getByRole("heading", { name: "Decision" })).toBeInTheDocument()
    expect(within(dialog).getByText("angular")).toBeInTheDocument()
    expect(within(dialog).getAllByText("1.8.3").length).toBeGreaterThan(0)
    expect(within(dialog).getByText("CVE-2024-21490")).toBeInTheDocument()
    expect(within(dialog).getByText("CVE-2025-4690")).toBeInTheDocument()
    expect(within(dialog).getByText("No fixed version")).toBeInTheDocument()
    expect(within(dialog).getByText("fix not recorded")).toBeInTheDocument()
    expect(within(dialog).getByText("Dev dependency")).toBeInTheDocument()
    const newest = within(dialog).getByText("Newest version").nextElementSibling as HTMLElement
    expect(newest).toHaveTextContent("1.8.3, this one")
    expect(within(newest).getByText("1.8.3")).toHaveClass("font-mono")
    expect(within(newest).getByText(", this one", { exact: false, selector: "span:not(.font-mono)" })).toBeInTheDocument()
    expect(within(dialog).getByRole("radio", { name: "Carry" })).toHaveAttribute("aria-checked", "true")
  })

  it("keeps Record disabled with its cause until a reason is written", () => {
    const onRecord = vi.fn()
    render(<DecidePanel dependency={angular} dev={false} reason="" onRecord={onRecord} onClose={() => {}} />)
    const record = screen.getByRole("button", { name: "Record" })
    expect(record).toHaveAttribute("aria-disabled", "true")
    expect(record).toHaveAccessibleDescription("Write a reason to record.")
    fireEvent.click(record)
    expect(onRecord).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "first line\nsecond line" } })
    expect(record).toHaveAccessibleDescription("Keep the reason on one line, with no tab or control character.")
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "  Templates are our own files  " } })
    expect(record).not.toHaveAttribute("aria-disabled")
    fireEvent.click(record)
    expect(onRecord).toHaveBeenCalledWith({ carry: true, reason: "Templates are our own files" })
  })

  it("links a CVE id to its advisory only when it matches", () => {
    const ids = ["CVE-2022-37620", "GHSA-2fx7-6rpj-5w4c", 'CVE-2022-37620"><x', "GHSA-0000-0000-0000", "PYSEC-2024-1"]
    const odd: DependencyResult = { ...angular, cves: ids.map((id) => noFix(id, "HIGH", "odd@1.0.0")) }
    render(<DecidePanel dependency={odd} dev={false} reason="" onRecord={() => {}} onClose={() => {}} />)
    const nvd = screen.getByRole("link", { name: "CVE-2022-37620" })
    expect(nvd).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2022-37620")
    const ghsa = screen.getByRole("link", { name: "GHSA-2fx7-6rpj-5w4c" })
    expect(ghsa).toHaveAttribute("href", "https://github.com/advisories/GHSA-2fx7-6rpj-5w4c")
    for (const link of [nvd, ghsa]) {
      expect(link).toHaveAttribute("target", "_blank")
      expect(link.getAttribute("rel")?.split(" ").sort()).toEqual(["noopener", "noreferrer"])
    }
    for (const id of ids.slice(2)) {
      expect(screen.getByText(id).closest("a")).toBeNull()
    }
    expect(screen.getAllByRole("link").filter((a) => a.textContent !== "Read more")).toHaveLength(2)
  })

  it("explains CVE in Decide and major jump in Jump", () => {
    const { unmount } = render(<DecidePanel dependency={angular} dev={false} reason="" onRecord={() => {}} onClose={() => {}} />)
    expect(within(panel()).getAllByRole("button", { name: "What a CVE is" })).toHaveLength(1)
    expect(within(panel()).queryByRole("button", { name: "What a major jump is" })).toBeNull()
    unmount()
    render(<JumpPanel dependency={esbuild} reason="" onRecord={() => {}} onClose={() => {}} />)
    expect(within(panel()).getAllByRole("button", { name: "What a major jump is" })).toHaveLength(1)
    const change = within(panel()).getByText("0.21.5").closest("[data-version-change]") as HTMLElement
    expect(within(change).getByRole("button", { name: "What a major jump is" })).toBeInTheDocument()
  })
})

describe("the panels on the review", () => {
  it("records a carried reason into its row", async () => {
    renderReview()
    fireEvent.click(within(rowOf("html-minifier")).getByRole("button", { name: "Decide html-minifier" }))
    await waitFor(() => expect(within(panel()).getByText("Dev dependency")).toBeInTheDocument())
    fireEvent.change(within(panel()).getByLabelText(/^Reason/), { target: { value: "Dev dependency, runs at build time on our own HTML" } })
    fireEvent.click(within(panel()).getByRole("button", { name: "Record" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(within(rowOf("html-minifier")).getByText("“Dev dependency, runs at build time on our own HTML”")).toBeInTheDocument()
    expect(stored("reasons")).toEqual({ "cve-without-fix:html-minifier": "Dev dependency, runs at build time on our own HTML" })
  })

  it("leaves a package out with no reason", async () => {
    renderReview()
    fireEvent.click(within(rowOf("lodash.template")).getByRole("button", { name: "Decide lodash.template" }))
    fireEvent.click(within(panel()).getByRole("radio", { name: "Leave out" }))
    expect(within(panel()).queryByLabelText(/^Reason/)).toBeNull()
    expect(within(panel()).getByText(/The archive will not carry lodash\.template/)).toBeInTheDocument()
    const record = within(panel()).getByRole("button", { name: "Record" })
    expect(record).not.toHaveAttribute("aria-disabled")
    fireEvent.click(record)
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(stored("selection")["lodash.template"]).toEqual([])
    expect(stored("reasons")).toEqual({})
    expect(screen.queryByText("lodash.template", { selector: "[data-reason-name]" })).toBeNull()
  })

  it("jumps a family together", async () => {
    renderReview()
    fireEvent.click(screen.getByRole("button", { name: /packages kept on their major/ }))
    fireEvent.click(screen.getByRole("button", { name: "Jump react-dom" }))
    const dialog = panel()
    expect(within(dialog).getByRole("heading", { name: "Major jump" })).toBeInTheDocument()
    expect(within(dialog).getByText("3 packages that move together")).toBeInTheDocument()
    for (const name of ["react", "react-dom", "@types/react"]) expect(within(dialog).getByText(name, { selector: "td *, td" })).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText(/^Reason/), { target: { value: "Moved to React 19 in branch react-19, all tests green" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Record" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(stored("selection")).toMatchObject({ react: ["19.2.0"], "react-dom": ["19.2.0"], "@types/react": ["19.2.2"] })
    expect(stored("reasons")).toEqual({ "major-jump:react 19": "Moved to React 19 in branch react-19, all tests green" })
    expect(within(rowOf("react 19")).getByText("“Moved to React 19 in branch react-19, all tests green”")).toBeInTheDocument()
  })

  it("changes nothing on Escape", async () => {
    renderReview()
    fireEvent.click(screen.getByRole("button", { name: /packages kept on their major/ }))
    const before = sessionStorage.getItem(`sealift:selection:${analysis.id}`)
    fireEvent.click(screen.getByRole("button", { name: "Jump esbuild" }))
    fireEvent.change(within(panel()).getByLabelText(/^Reason/), { target: { value: "CI runs the new esbuild" } })
    fireEvent.keyDown(within(panel()).getByLabelText(/^Reason/), { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(sessionStorage.getItem(`sealift:selection:${analysis.id}`)).toBe(before)
    expect(stored("reasons")).toEqual({})
    expect(screen.getByRole("button", { name: "Jump esbuild" })).toBeInTheDocument()
  })

  it("gives the focus back to the row", async () => {
    renderReview()
    const decide = within(rowOf("html-minifier")).getByRole("button", { name: "Decide html-minifier" })
    decide.focus()
    fireEvent.click(decide)
    expect(panel()).toBeInTheDocument()
    fireEvent.keyDown(within(panel()).getByLabelText(/^Reason/), { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    await waitFor(() => expect(decide).toHaveFocus())
  })
})

describe("the advisory row in Decide", () => {
  const minifier: DependencyResult = {
    name: "html-minifier", current: "4.0.0", vector: [0, 1, 0, 0, 0], candidates: [],
    cves: [noFix("CVE-2022-37620", "HIGH", "html-minifier@4.0.0")],
  }

  it("says what the flaw does with its date when the analysis carries it", () => {
    const advisories = { "CVE-2022-37620": { title: "html-minifier: ReDoS in the candidate parser", published: "2022-10-31T07:15:00Z" } }
    render(<DecidePanel dependency={minifier} dev={false} reason="" advisories={advisories} onRecord={() => {}} onClose={() => {}} />)
    const flaw = within(panel()).getByText("What the flaw does").parentElement as HTMLElement
    expect(within(flaw).getByText("html-minifier: ReDoS in the candidate parser")).toBeInTheDocument()
    expect(within(flaw).getByText("31 Oct 2022")).toBeInTheDocument()
  })

  it("leaves the row out when the analysis carries none", () => {
    render(<DecidePanel dependency={minifier} dev={false} reason="" onRecord={() => {}} onClose={() => {}} />)
    expect(within(panel()).queryByText("What the flaw does")).toBeNull()
  })
})

describe("the pip panels", () => {
  const wheel = (name: string, version: string) => ({ file: `${name}-${version}-py3-none-any.whl`, url: `https://files.example/${name}`, sha256: "a".repeat(64), size: 1000 })
  const requests: PipPackage = {
    name: "requests", version: "2.32.0", files: ["requirements.txt"], pinnedAt: [{ file: "requirements.txt", line: 6 }],
    wheel: wheel("requests", "2.32.0"), cves: [], yanked: { reason: "Yanked due to conflicts with CVE-2024-35195 mitigation" },
  }
  const ecdsa: PipPackage = {
    name: "ecdsa", version: "0.19.1", files: [], wheel: wheel("ecdsa", "0.19.1"),
    cves: [{ id: "CVE-2024-23342", severity: "HIGH", fixedVersions: [] }, { id: "CVE-2024-0001", severity: "LOW", fixedVersions: ["0.20.0"] }],
  }
  const django: PipPackage = {
    name: "django", version: "5.1.4", files: ["requirements.txt"], pinnedAt: [{ file: "requirements.txt", line: 3 }],
    wheel: { ...wheel("django", "5.1.4"), uploadedAt: "2025-03-31T14:00:00Z" }, cves: [],
    previous: { version: "4.2.16", cves: [{ id: "CVE-2024-45230", severity: "HIGH", fixedVersions: ["4.2.17"] }, { id: "CVE-2024-45231", severity: "MEDIUM", fixedVersions: ["4.2.17"] }], majorJump: true },
  }

  it("decides a yanked release with the index's reason, where it is pinned and its wheel", () => {
    const onReplace = vi.fn()
    render(<PipDecidePanel pkg={requests} kind="yanked" reason="" onRecord={() => {}} onReplace={onReplace} onClose={() => {}} />)
    const dialog = panel()
    expect(within(dialog).getByRole("heading", { name: "Decision" })).toBeInTheDocument()
    expect(within(dialog).getByText("Yanked")).toBeInTheDocument()
    expect(within(dialog).getByText("“Yanked due to conflicts with CVE-2024-35195 mitigation”")).toBeInTheDocument()
    expect(within(dialog).getByText("requirements.txt, line 6")).toBeInTheDocument()
    expect(within(dialog).getByText("requests-2.32.0-py3-none-any.whl")).toBeInTheDocument()
    expect(within(dialog).getByLabelText(/^Reason/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole("button", { name: "Replace files" }))
    expect(onReplace).toHaveBeenCalled()
  })

  it("says No reason given when the index gives none", () => {
    render(<PipDecidePanel pkg={{ ...requests, yanked: { reason: "" } }} kind="yanked" reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    expect(within(panel()).getByText("No reason given")).toBeInTheDocument()
  })

  it("shows the index's reason as text", () => {
    const markup = '<img src=x onerror="alert(1)"><b>bold</b>'
    render(<PipDecidePanel pkg={{ ...requests, yanked: { reason: markup } }} kind="yanked" reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    expect(within(panel()).getByText(`“${markup}”`)).toBeInTheDocument()
    expect(panel().querySelector("img, b")).toBeNull()
  })

  it("decides a CVE with no fix with its advisory, and a dependency pinned by no file", () => {
    const advisories = { "CVE-2024-23342": { title: "ecdsa: Minerva timing attack on P-256", published: "2024-01-23T00:15:00Z" } }
    render(<PipDecidePanel pkg={ecdsa} kind="cve-without-fix" advisories={advisories} reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    const dialog = panel()
    expect(within(dialog).getByRole("link", { name: "CVE-2024-23342" })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2024-23342")
    expect(within(dialog).getByText("No fixed version")).toBeInTheDocument()
    expect(within(dialog).queryByText("CVE-2024-0001")).toBeNull()
    expect(within(dialog).getByText("ecdsa: Minerva timing attack on P-256")).toBeInTheDocument()
    expect(within(dialog).getByText("23 Jan 2024")).toBeInTheDocument()
    expect(within(dialog).getByText("dependency")).toBeInTheDocument()
  })

  it("leaves the flaw out of a pip Decide when the analysis carries none", () => {
    render(<PipDecidePanel pkg={ecdsa} kind="cve-without-fix" reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    expect(within(panel()).queryByText("What the flaw does")).toBeNull()
  })

  it("offers no Carry or Leave out for pip", () => {
    const onRecord = vi.fn()
    render(<PipDecidePanel pkg={requests} kind="yanked" reason="" onRecord={onRecord} onReplace={() => {}} onClose={() => {}} />)
    expect(screen.queryByRole("radio")).toBeNull()
    expect(screen.queryByText("Carry")).toBeNull()
    expect(screen.queryByText("Leave out")).toBeNull()
    const record = screen.getByRole("button", { name: "Record" })
    expect(record).toHaveAttribute("aria-disabled", "true")
    expect(record).toHaveAccessibleDescription("Write a reason to record.")
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "  Client tests pin 2.32.0 " } })
    fireEvent.click(record)
    expect(onRecord).toHaveBeenCalledWith("Client tests pin 2.32.0")
  })

  it("jumps with its facts and no Keep or Jump choice", () => {
    const onRecord = vi.fn()
    const onReplace = vi.fn()
    render(<PipJumpPanel pkg={django} reason="" onRecord={onRecord} onReplace={onReplace} onClose={() => {}} />)
    const dialog = panel()
    expect(within(dialog).getByRole("heading", { name: "Major jump" })).toBeInTheDocument()
    const change = within(dialog).getByText("4.2.16").closest("[data-version-change]") as HTMLElement
    expect(change).toHaveTextContent(/4\.2\.16\s*to\s*5\.1\.4/)
    expect(within(dialog).getByText("Release age")).toBeInTheDocument()
    expect(within(dialog).getByText("Known CVEs").nextElementSibling).toHaveTextContent(/1 high\s*1 medium\s*to\s*0/)
    expect(within(dialog).getByText("requirements.txt, line 3")).toBeInTheDocument()
    expect(within(dialog).getByText("django-5.1.4-py3-none-any.whl")).toBeInTheDocument()
    expect(screen.queryByRole("radio")).toBeNull()
    expect(screen.getByRole("button", { name: "Record" })).toHaveAttribute("aria-disabled", "true")
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "Moved in branch django-5" } })
    fireEvent.click(screen.getByRole("button", { name: "Record" }))
    expect(onRecord).toHaveBeenCalledWith("Moved in branch django-5")
    fireEvent.click(screen.getByRole("button", { name: "Replace files" }))
    expect(onReplace).toHaveBeenCalled()
  })

  it("explains CVE and yanked in Decide and major jump in Jump", () => {
    const { unmount } = render(<PipDecidePanel pkg={{ ...requests, cves: ecdsa.cves }} kind="yanked" reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    expect(within(panel()).getAllByRole("button", { name: "What a yanked release is" })).toHaveLength(1)
    unmount()
    const second = render(<PipDecidePanel pkg={ecdsa} kind="cve-without-fix" reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    expect(within(panel()).getAllByRole("button", { name: "What a CVE is" })).toHaveLength(1)
    second.unmount()
    render(<PipJumpPanel pkg={django} reason="" onRecord={() => {}} onReplace={() => {}} onClose={() => {}} />)
    const change = within(panel()).getByText("4.2.16").closest("[data-version-change]") as HTMLElement
    expect(within(change.parentElement as HTMLElement).getAllByRole("button", { name: "What a major jump is" })).toHaveLength(1)
  })
})
