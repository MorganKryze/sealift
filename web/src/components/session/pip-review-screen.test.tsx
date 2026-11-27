import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ComponentType, ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { getProject, queueExport, type Analysis, type Export, type Project } from "@/api/projects"
import { PipReviewScreen } from "@/components/session/pip-review-screen"
import type { PipAnalysisResult, PipPackage } from "@/lib/pipReview"
import { Route as RootRoute } from "@/routes/__root"
import { Route } from "@/routes/crossings.$projectId"

const router = vi.hoisted(() => ({ navigate: vi.fn(), search: {} as Record<string, string> }))

vi.mock("@tanstack/react-router", () => ({
  createRootRoute: (options: object) => ({ options }),
  redirect: (options: object) => options,
  createFileRoute: () => (options: object) => ({ options, useParams: () => ({ projectId: "ledger-service" }), useSearch: () => router.search }),
  useNavigate: () => router.navigate,
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
}))
vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn(), getProject: vi.fn() }
})
vi.mock("@/components/session/export-screen", () => ({ ExportScreen: () => <p>export screen</p> }))

const target = { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" }
const ID = "20261125T091500Z"
const wheel = (name: string, version: string, tag = "py3-none-any") => ({ file: `${name}-${version}-${tag}.whl`, url: `https://files.example/${name}`, sha256: "a".repeat(64), size: 1000 })
const finding = (id: string, severity: string, fixedVersions: string[] = []) => ({ id, severity, fixedVersions })
const at = (file: string, line: number) => [{ file, line }]

function pkg(name: string, version: string, more: Partial<PipPackage> = {}): PipPackage {
  return { name, version, files: ["requirements.txt"], wheel: wheel(name, version), cves: [], ...more }
}
const previous = { projectId: "ledger-service", projectName: "ledger-service", exportId: "20261120T102000Z", analysisId: "20261120T101500Z", sealedAt: "2026-11-20T10:20:00Z" }
const same = (version: string, cves: PipPackage["cves"] = []) => ({ version, cves, majorJump: false })

const PACKAGES = [
  pkg("attrs", "24.2.0", { pinnedAt: at("requirements.txt", 2) }),
  pkg("django", "5.1.4", { pinnedAt: at("requirements.txt", 3), previous: { version: "4.2.16", cves: [finding("CVE-2024-45230", "HIGH", ["4.2.17"])], majorJump: true } }),
  pkg("ecdsa", "0.19.1", { pinnedAt: at("requirements.txt", 5), cves: [finding("CVE-2024-23342", "HIGH")], previous: same("0.19.1", [finding("CVE-2024-23342", "HIGH")]) }),
  pkg("idna", "3.10", { files: [], previous: same("3.10") }),
  pkg("pillow", "10.4.0", { pinnedAt: at("requirements.txt", 7), wheel: wheel("pillow", "10.4.0", "cp311-cp311-manylinux_2_28_x86_64"), previous: same("10.2.0", [finding("CVE-2024-28219", "HIGH", ["10.3.0"])]) }),
  pkg("requests", "2.32.0", { pinnedAt: at("requirements.txt", 6), yanked: { reason: "Yanked due to conflicts with CVE-2024-35195 mitigation" }, previous: same("2.32.0") }),
]
const NO_WHEEL = pkg("psycopg2", "2.9.10", { pinnedAt: at("requirements.txt", 4), wheel: undefined, previous: same("2.9.9") })

function resultOf(packages: PipPackage[], more: Partial<PipAnalysisResult> = {}): PipAnalysisResult {
  return { target, files: ["requirements.txt", "constraints.txt"], packages, blocking: [], warnings: [], previous, ...more }
}
const analysisOf = (pipResult: PipAnalysisResult, id = ID) => ({ id, projectId: "ledger-service", state: "done", createdAt: "2026-11-25T09:15:00Z", uvVersion: "0.13.7", pipResult }) as Analysis
const projectOf = (analysis: Analysis, exports: Export[] = []) =>
  ({ id: "ledger-service", name: "ledger-service", ecosystem: "pip", pipTarget: target, analyses: [analysis], exports }) as unknown as Project

const withNoWheel = resultOf([...PACKAGES, NO_WHEEL].sort((a, b) => a.name.localeCompare(b.name)), {
  blocking: [{ name: "psycopg2", version: "2.9.10", kind: "source-only", detail: "source distribution only", pinnedAt: at("requirements.txt", 4) }],
})
const WRITTEN = {
  "major-jump:django": "Moved to Django 5.1 in branch django-5, all tests green",
  "cve-without-fix:ecdsa": "Only verifies signatures from our own HSM; never signs",
  "yanked:requests": "Our client tests run on 2.32.0; the move to 2.32.3 is #214",
}

function renderReview(result: PipAnalysisResult, reasons?: Record<string, string>, yankedRule?: "reason" | "refuse") {
  const analysis = analysisOf(result)
  if (reasons) sessionStorage.setItem(`sealift:reasons:${analysis.id}`, JSON.stringify(reasons))
  const onNavigateStep = vi.fn()
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  if (yankedRule) client.setQueryData(["instance"], { policy: { review: { proposeOtherMajors: false, majorJump: "reason", cveWithoutFix: "reason", yanked: yankedRule } } })
  render(
    <QueryClientProvider client={client}>
      <PipReviewScreen project={projectOf(analysis)} analysis={analysis} onNavigateStep={onNavigateStep} />
    </QueryClientProvider>,
  )
  return { onNavigateStep }
}

const seal = () => screen.getByRole("button", { name: /^Seal/ })

beforeEach(() => {
  cleanup()
  sessionStorage.clear()
  router.navigate.mockReset()
  router.search = {}
  vi.mocked(queueExport).mockReset()
  vi.mocked(getProject).mockReset()
})

describe("the pip review's head", () => {
  it("titles what needs you with Known CVEs before and after", () => {
    renderReview(withNoWheel)
    expect(screen.getByRole("heading", { level: 1, name: "4 things need you" })).toBeDefined()
    const known = document.querySelector("[data-known-cves]") as HTMLElement
    // Before: django's and pillow's previous CVEs and ecdsa's; after: ecdsa's.
    expect(known.textContent).toMatch(/Known CVEs\s*3\s*to\s*1/)
    expect(screen.getByText(/Python/).textContent).toMatch(/Python 3\.11\.2 · linux x86_64 · glibc 2\.28/)
  })

  it("shows a count only with no previous crossing", () => {
    // future's CVE with no fix waits for a reason, so the page reads Review, not Ready.
    renderReview(resultOf([pkg("ecdsa", "0.19.1", { cves: [finding("CVE-2024-23342", "HIGH", ["0.20.0"])] }), pkg("future", "1.0.0", { cves: [finding("CVE-2024-1001", "MEDIUM")] })], { previous: undefined }))
    const known = document.querySelector("[data-known-cves]") as HTMLElement
    expect(known.textContent).toMatch(/Known CVEs\s*2/)
    expect(known.textContent).not.toMatch(/ to /)
    expect(screen.getByRole("button", { name: /^1 package with a fix in a newer release/ })).toBeDefined()
    expect(screen.queryByRole("button", { name: /unchanged/ })).toBeNull()
  })

  it("places one info button per term at its first place", () => {
    renderReview(withNoWheel)
    fireEvent.click(screen.getByRole("button", { name: /^1 pin changed/ }))
    for (const name of ["What a CVE is", "What a severity is", "What a major jump is", "What a yanked release is", "What a wheel is"]) {
      expect(screen.getAllByRole("button", { name })).toHaveLength(1)
    }
    expect(screen.queryByRole("button", { name: "What the target is" })).toBeNull()
    const noWheel = screen.getByRole("region", { name: /no wheel for the target/ })
    expect(within(noWheel).getByRole("button", { name: "What a wheel is" })).toBeDefined()
    expect(screen.getByRole("button", { name: "What a CVE is" }).closest("[data-known-cves]")).not.toBeNull()
  })
})

describe("what holds Seal", () => {
  it("draws the no-wheel block with what the index publishes and Replace files", () => {
    renderReview(withNoWheel)
    const block = screen.getByRole("region", { name: "1 package with no wheel for the target" })
    expect(within(block).getByText("psycopg2")).toBeDefined()
    expect(within(block).getByText("2.9.10")).toBeDefined()
    expect(within(block).getByText("requirements.txt, line 4")).toBeDefined()
    expect(within(block).getByText("Publishes a source distribution only.")).toBeDefined()
    fireEvent.click(within(block).getByRole("button", { name: "Replace files" }))
    expect(router.navigate).toHaveBeenCalledWith({ to: "/update", search: { from: "ledger-service" } })
  })

  it("draws three reason bands", () => {
    renderReview(withNoWheel)
    const reasons = screen.getByRole("region", { name: "Reasons" })
    expect(within(reasons).getByRole("group", { name: "1 major jump" })).toBeDefined()
    expect(within(reasons).getByRole("group", { name: "1 known CVE with no fixed version" })).toBeDefined()
    const yanked = within(reasons).getByRole("group", { name: "1 yanked release" })
    expect(within(yanked).getByText("requirements.txt, line 6")).toBeDefined()
    expect(within(reasons).getAllByText("Reason missing")).toHaveLength(3)
    expect(within(reasons).getByRole("button", { name: "Jump django" })).toBeDefined()
    expect(within(reasons).getByRole("button", { name: "Decide ecdsa" })).toBeDefined()
    expect(within(reasons).getByRole("button", { name: "Decide requests" })).toBeDefined()
  })

  it("counts the reasons carried in each band head", () => {
    renderReview(resultOf(PACKAGES), WRITTEN)
    const reasons = screen.getByRole("region", { name: "Reasons" })
    expect(within(reasons).getByRole("group", { name: "1 yanked release, carried with 1 reason" })).toBeDefined()
    expect(within(reasons).getByText(`“${WRITTEN["yanked:requests"]}”`)).toBeDefined()
    expect(within(reasons).getByRole("button", { name: "Change requests" })).toBeDefined()
  })

  it("keeps Seal disabled and names every package that waits, wheels first", () => {
    renderReview(withNoWheel, WRITTEN)
    expect(seal().getAttribute("aria-disabled")).toBe("true")
    expect(screen.getByText("Opens once psycopg2 has a wheel for the target.")).toBeDefined()
    fireEvent.click(seal())
    expect(queueExport).not.toHaveBeenCalled()
    cleanup()
    sessionStorage.clear()
    renderReview(resultOf(PACKAGES))
    expect(seal().getAttribute("aria-disabled")).toBe("true")
    expect(screen.getByText("Opens once django, ecdsa and requests have a reason.")).toBeDefined()
  })

  it("states a yanked release refused by the instance before Seal, with no reason to write", () => {
    renderReview(resultOf(PACKAGES), WRITTEN, "refuse")
    const reasons = screen.getByRole("region", { name: "Reasons" })
    const yanked = within(reasons).getByRole("group", { name: "1 yanked release, refused by this instance" })
    expect(within(yanked).getByText("Refused by this instance's policy")).toBeDefined()
    expect(within(reasons).queryByRole("button", { name: /requests$/ })).toBeNull()
    expect(screen.getByRole("heading", { level: 1, name: "One thing needs you" })).toBeDefined()
    expect(seal().getAttribute("aria-disabled")).toBe("true")
    expect(screen.getByText("This instance refuses every yanked release: requests cannot cross.")).toBeDefined()
    fireEvent.click(seal())
    expect(queueExport).not.toHaveBeenCalled()
  })

  it("never reads Ready while a package has no wheel", () => {
    renderReview(withNoWheel, WRITTEN)
    expect(screen.getByRole("heading", { level: 1, name: "One thing needs you" })).toBeDefined()
    expect(screen.queryByText("Ready to seal")).toBeNull()
    expect(screen.queryByRole("region", { name: /^Wheels for/ })).toBeNull()
    expect(seal().getAttribute("aria-disabled")).toBe("true")
  })

  it("sends an empty selection and the reasons shown, word for word", async () => {
    vi.mocked(queueExport).mockResolvedValue({ id: "20261125T092000Z", projectId: "ledger-service", analysisId: ID, state: "queued", createdAt: "2026-11-25T09:20:00Z" } as Export)
    // A reason as typed, spaces around it included: the row shows it and the request sends it the same way.
    const typed = { ...WRITTEN, "yanked:requests": "  Our client tests run on 2.32.0; the move to 2.32.3 is #214  " }
    const { onNavigateStep } = renderReview(resultOf(PACKAGES), typed)
    expect(screen.getByRole("heading", { level: 1, name: "Ready to seal" })).toBeDefined()
    const shown = Array.from(document.querySelectorAll("[data-reason-row] p"))
      .map((p) => p.textContent ?? "")
      .filter((text) => text.startsWith("“"))
      .map((text) => text.slice(1, -1))
    fireEvent.click(seal())
    await waitFor(() => expect(onNavigateStep).toHaveBeenCalledWith("export"))
    expect(queueExport).toHaveBeenCalledWith("ledger-service", ID, {
      selection: {},
      includeProject: false,
      reasons: [
        { kind: "major-jump", dependencies: ["django"], text: WRITTEN["major-jump:django"] },
        { kind: "cve-without-fix", dependencies: ["ecdsa"], text: WRITTEN["cve-without-fix:ecdsa"] },
        { kind: "yanked", dependencies: ["requests"], text: WRITTEN["yanked:requests"] },
      ],
    })
    expect(vi.mocked(queueExport).mock.calls[0][2].reasons?.map((reason) => reason.text)).toEqual(shown)
  })
})

const GUNICORN = pkg("gunicorn", "22.0.0", { pinnedAt: at("requirements.txt", 8), cves: [finding("CVE-2024-6827", "HIGH", ["23.0.0"])], previous: same("22.0.0", [finding("CVE-2024-6827", "HIGH", ["23.0.0"])]) })
const READY = resultOf([...PACKAGES, GUNICORN].sort((a, b) => a.name.localeCompare(b.name)))

describe("Ready to seal", () => {
  it("reads Ready to seal once nothing needs you", () => {
    renderReview(READY, WRITTEN)
    expect(screen.getByRole("heading", { level: 1, name: "Ready to seal" })).toBeDefined()
    expect(screen.getByText("pins in", { exact: false })).toHaveTextContent("6 pins in 2 requirements files")
    const known = screen.getByRole("region", { name: "Known CVEs" })
    expect(known.querySelector("[data-total]")).toHaveTextContent(/^2$/)
    expect(known).not.toHaveTextContent(" to ")
    expect(document.querySelector("[data-known-cves]")).toBeNull()
    // The packages that keep a CVE a newer release fixes, each with that release.
    const keep = screen.getByRole("region", { name: "1 package keeps known CVEs a newer release fixes" })
    const row = within(keep).getByText("gunicorn").closest("li") as HTMLElement
    expect(row).toHaveTextContent("22.0.0")
    expect(row).toHaveTextContent("CVE-2024-6827")
    expect(row).toHaveTextContent(/fixed in\s*23\.0\.0/)
    expect(screen.getByRole("region", { name: /^Wheels for Python 3\.11\.2/ })).toBeDefined()
    // Ready shows no group of the set: Review keeps them.
    expect(document.querySelector("[data-group]")).toBeNull()
    expect(seal().getAttribute("aria-disabled")).toBeNull()
    const actions = seal().parentElement as HTMLElement
    expect(actions).toHaveClass("justify-end")
    for (const name of ["What a CVE is", "What a severity is", "What a wheel is", "What a major jump is", "What a yanked release is"]) {
      expect(screen.getAllByRole("button", { name })).toHaveLength(1)
    }
    expect(known).toContainElement(screen.getByRole("button", { name: "What a severity is" }))
    expect(screen.getByRole("region", { name: /^Wheels for/ })).toContainElement(screen.getByRole("button", { name: "What a wheel is" }))
  })

  it("shows each reason as it will be signed with Change", () => {
    renderReview(READY, WRITTEN)
    const reasons = screen.getByRole("region", { name: "Reasons" })
    for (const [key, text] of Object.entries(WRITTEN)) {
      const name = key.split(":")[1]
      const row = within(reasons).getByText(`“${text}”`).closest("[data-reason-row]") as HTMLElement
      expect(within(row).getByRole("button", { name: `Change ${name}` })).toBeDefined()
    }
    expect(within(reasons).queryByText("Reason missing")).toBeNull()
  })

  it("names the refusing rule and its packages when the server refuses Seal", async () => {
    const detail = "jobs: review.majorJump is refuse: django 4.2.16 to 5.1.4 is a major jump and cannot cross; review.yanked is refuse: requests 2.32.0 is yanked on the index and cannot cross"
    vi.mocked(queueExport).mockRejectedValue(new ProblemError(409, { type: "about:blank", title: "queue export", status: 409, detail }))
    renderReview(READY, WRITTEN)
    fireEvent.click(seal())
    const alert = await screen.findByRole("alert")
    const jump = within(alert).getByText("This instance refuses every major jump").closest("[data-refusal]") as HTMLElement
    expect(within(jump).getByText("django")).toBeDefined()
    expect(within(jump).getByText("4.2.16 to 5.1.4")).toBeDefined()
    expect(jump).toHaveTextContent("1 package")
    const yanked = within(alert).getByText("This instance refuses every yanked release").closest("[data-refusal]") as HTMLElement
    expect(within(yanked).getByText("requests")).toBeDefined()
    expect(within(yanked).getByText("2.32.0")).toBeDefined()
    expect(alert).not.toHaveTextContent("review.majorJump")
    expect(alert).not.toHaveTextContent("jobs:")
    fireEvent.click(within(alert).getByRole("button", { name: "Replace files" }))
    expect(router.navigate).toHaveBeenCalledWith({ to: "/update", search: { from: "ledger-service" } })
  })

  it("lists the reasons the server did not take", async () => {
    const detail = "django 4.2.16 to 5.1.4 is a major jump and needs a reason; reason 3 (yanked) repeats the reason for requests"
    vi.mocked(queueExport).mockRejectedValue(new ProblemError(400, { type: "about:blank", title: "invalid export reasons", status: 400, detail }))
    renderReview(READY, WRITTEN)
    fireEvent.click(seal())
    const alert = await screen.findByRole("alert")
    expect(within(alert).getByText("The server did not take these reasons")).toBeDefined()
    expect(within(alert).getByText("django 4.2.16 to 5.1.4 is a major jump and needs a reason")).toBeDefined()
    expect(within(alert).getByText("reason 3 (yanked) repeats the reason for requests")).toBeDefined()
  })

})

describe("the groups", () => {
  it("opens a group with Pinned in and Wheel", () => {
    renderReview(withNoWheel)
    const head = screen.getByRole("button", { name: /^1 pin changed/ })
    expect(head.textContent).toContain("1 known CVE fixed")
    fireEvent.click(head)
    const table = screen.getByRole("table")
    const columns = within(table).getAllByRole("columnheader").map((th) => th.textContent)
    expect(columns).toEqual(["Package", "Version", "Pinned in", "Known CVEs fixed", "Wheel"])
    const row = within(table).getByText("pillow").closest("tr") as HTMLElement
    expect(within(row).getByText("requirements.txt, line 7")).toBeDefined()
    expect(within(row).getByText("x86_64")).toBeDefined()
    expect(row.querySelector("[data-version-change]")?.textContent).toMatch(/10\.2\.0\s*to\s*10\.4\.0/)
    fireEvent.click(screen.getByRole("button", { name: /^1 package unchanged/ }))
    const idna = screen.getByText("idna").closest("tr") as HTMLElement
    expect(within(idna).getByText("dependency")).toBeDefined()
    expect(within(idna).getByText("any")).toBeDefined()
  })

  it("lists the first 12 rows of the worst case, then all of them", () => {
    const many = Array.from({ length: 1284 }, (_, i) => pkg(`ingest-lib-${String(i).padStart(4, "0")}`, "1.0.0", { previous: same("1.0.0") }))
    // ecdsa's CVE with no fix keeps the page on Review, where the groups show.
    const ecdsa = pkg("ecdsa", "0.19.1", { cves: [finding("CVE-2024-23342", "HIGH")], previous: same("0.19.1", [finding("CVE-2024-23342", "HIGH")]) })
    renderReview(resultOf([...many, ecdsa, pkg("pandas-stubs", "2.2.3.241126", { previous: same("1.5.3.230321") })]))
    fireEvent.click(screen.getByRole("button", { name: /^1,284 packages unchanged/ }))
    const group = screen.getByRole("button", { name: /^1,284 packages unchanged/ }).closest("[data-group]") as HTMLElement
    expect(within(group).getAllByRole("row")).toHaveLength(13)
    fireEvent.click(within(group).getByRole("button", { name: "Show all 1,284 packages" }))
    expect(within(group).getAllByRole("row")).toHaveLength(1285)
    fireEvent.click(screen.getByRole("button", { name: /^1 pin changed/ }))
    expect(document.querySelector("[data-group=changed] [data-version-change]")?.textContent).toMatch(/1\.5\.3\.230321\s*to\s*2\.2\.3\.241126/)
  })
})

describe("a pip analysis 0.7.0 recorded", () => {
  const legacy = {
    target,
    files: ["requirements.txt"],
    packages: [
      { name: "jinja2", version: "3.1.4", files: [], wheel: wheel("jinja2", "3.1.4"), cves: [{ id: "CVE-2024-56201", severity: "MEDIUM", fixedVersions: ["3.1.5"], title: "jinja2: sandbox breakout" }] },
      { name: "requests", version: "2.32.0", files: ["requirements.txt"], wheel: wheel("requests", "2.32.0"), cves: [] },
    ],
    blocking: [],
    warnings: ["requests==2.32.0 is yanked on the index: Yanked due to conflicts with CVE-2024-35195 mitigation"],
  } as PipAnalysisResult

  it("shows the warnings of a 0.7.0 analysis", () => {
    renderReview(legacy)
    expect(screen.getByText("requests==2.32.0 is yanked on the index: Yanked due to conflicts with CVE-2024-35195 mitigation")).toBeDefined()
    expect(screen.queryByRole("region", { name: "Reasons" })).toBeNull()
    expect(screen.getByRole("heading", { level: 1, name: "Ready to seal" })).toBeDefined()
    // 0.7.0 recorded files, never lines: requests is the one pin.
    expect(screen.getByText("pin in", { exact: false })).toHaveTextContent("1 pin in 1 requirements file")
    expect(within(screen.getByRole("region", { name: "1 package keeps known CVEs a newer release fixes" })).getByText("jinja2")).toBeDefined()
  })

  it("reads Pinned in from the files of a 0.7.0 analysis", () => {
    const ecdsa = { name: "ecdsa", version: "0.19.1", files: ["requirements.txt"], wheel: wheel("ecdsa", "0.19.1"), cves: [{ id: "CVE-2024-23342", severity: "HIGH", fixedVersions: [] }] }
    renderReview({ ...legacy, packages: [...legacy.packages, ecdsa] })
    expect(screen.getByRole("heading", { level: 1, name: "One thing needs you" })).toBeDefined()
    fireEvent.click(screen.getByRole("button", { name: /^1 package$/ }))
    const row = screen.getByText("requests").closest("tr") as HTMLElement
    expect(within(row).getByText("requirements.txt")).toBeDefined()
  })
})

describe("the panels on the pip review", () => {
  it("records a yanked reason into its row", async () => {
    renderReview(resultOf(PACKAGES))
    fireEvent.click(screen.getByRole("button", { name: "Decide requests" }))
    const dialog = await screen.findByRole("dialog")
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "Client tests pin 2.32.0" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Record" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(screen.getByText("“Client tests pin 2.32.0”")).toBeDefined()
    expect(screen.getByText("Opens once django and ecdsa have a reason.")).toBeDefined()
  })

  it("sends Replace files from Jump to a new crossing of the project", async () => {
    renderReview(resultOf(PACKAGES))
    fireEvent.click(screen.getByRole("button", { name: "Jump django" }))
    const dialog = await screen.findByRole("dialog")
    fireEvent.click(within(dialog).getByRole("button", { name: "Replace files" }))
    expect(router.navigate).toHaveBeenCalledWith({ to: "/update", search: { from: "ledger-service" } })
  })
})

describe("the crossing route for pip", () => {
  const renderCrossing = () => {
    const Crossing = (Route as unknown as { options: { component: ComponentType } }).options.component
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <Crossing />
      </QueryClientProvider>,
    )
  }
  const sealedExport = { id: "20261125T092000Z", projectId: "ledger-service", analysisId: ID, state: "done", createdAt: "2026-11-25T09:20:00Z" } as Export

  it("opens the pip review on a sealed crossing when the address names the review step", async () => {
    vi.mocked(getProject).mockResolvedValue(projectOf(analysisOf(resultOf(PACKAGES)), [sealedExport]))
    router.search = { step: "review" }
    renderCrossing()
    expect(await screen.findByRole("heading", { level: 1, name: "3 things need you" })).toBeDefined()
    expect(screen.queryByText("export screen")).toBeNull()
  })

  it("shows no CVE figure on a failed analysis opened at its review", async () => {
    const failed = { ...analysisOf(resultOf(PACKAGES)), state: "failed" } as Analysis
    vi.mocked(getProject).mockResolvedValue(projectOf(failed))
    router.search = { step: "review" }
    renderCrossing()
    expect(await screen.findByText("This analysis did not finish, so there is nothing to review.")).toBeDefined()
    expect(screen.queryByText("Known CVEs")).toBeNull()
    expect(screen.queryByRole("button", { name: /^Seal/ })).toBeNull()
  })

  it("keeps the no-wheel block on a failed analysis that carries one", async () => {
    const failed = { ...analysisOf(withNoWheel), state: "failed" } as Analysis
    vi.mocked(getProject).mockResolvedValue(projectOf(failed))
    router.search = { step: "review" }
    renderCrossing()
    expect(await screen.findByRole("region", { name: "1 package with no wheel for the target" })).toBeDefined()
    expect(screen.queryByText("Known CVEs")).toBeNull()
  })

  it("sends an earlier review address on a failed analysis to the same screen", async () => {
    const beforeLoad = (RootRoute as unknown as { options: { beforeLoad: (ctx: { location: { pathname: string; search: object } }) => void } }).options.beforeLoad
    let sent: unknown
    try {
      beforeLoad({ location: { pathname: "/sessions/ledger-service/review", search: {} } })
    } catch (thrown) {
      sent = thrown
    }
    expect(sent).toMatchObject({ to: "/crossings/$projectId", params: { projectId: "ledger-service" }, search: { step: "review" } })
    const failed = { ...analysisOf(resultOf(PACKAGES)), state: "failed" } as Analysis
    vi.mocked(getProject).mockResolvedValue(projectOf(failed))
    router.search = (sent as { search: Record<string, string> }).search
    renderCrossing()
    expect(await screen.findByText("This analysis did not finish, so there is nothing to review.")).toBeDefined()
    expect(screen.queryByText("Known CVEs")).toBeNull()
  })

  it("lists the files and target on the crossing's Check", async () => {
    vi.mocked(getProject).mockResolvedValue(projectOf(analysisOf(resultOf(PACKAGES))))
    router.search = { step: "check" }
    renderCrossing()
    expect(await screen.findByRole("heading", { level: 1, name: "Update ledger-service" })).toBeDefined()
    expect(screen.getByText("2 requirements files")).toBeDefined()
    expect(screen.getByText("requirements.txt")).toBeDefined()
    expect(screen.getByText("constraints.txt")).toBeDefined()
    expect(screen.getByText(/pip · Python/).textContent).toMatch(/pip · Python 3\.11\.2 · linux x86_64 · glibc 2\.28/)
    expect(screen.getByRole("button", { name: "What the target is" })).toBeDefined()
  })
})
