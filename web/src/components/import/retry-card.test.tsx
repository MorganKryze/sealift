import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { useImport } from "@/import/api/queries"
import type { Attempt, Import, ReportPackage } from "@/import/lib/outcome"

import { EndState } from "./end-state"
import { AttemptProgress } from "./progress"
import { RetryCard } from "./retry-card"
import { latestAttempt } from "@/import/lib/outcome"

afterEach(() => {
  vi.unstubAllGlobals()
})

const pkg = (state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name: "left-pad", version: "1.3.0", file: "x", state, reason: "", note: "", ...over,
})
const many = (n: number, state: string, over: Partial<ReportPackage> = {}) => Array.from({ length: n }, () => pkg(state, over))

function attempt(n: number, status: string, outcome: string, packages: ReportPackage[]): Attempt {
  return {
    n, status, outcome, endedAt: "2026-11-05T15:47:00Z",
    report: {
      outcome, reason: "", unencrypted: false, importVersion: "0.5.0", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages, archiveChecked: true,
    },
  }
}

const ID = "20261104T142000Z-a1000006"
const make = (attempts: Attempt[]): Import => ({
  id: ID, createdAt: "2026-11-04T14:20:00Z", expectedSha256: "", outcome: attempts[attempts.length - 1].outcome || attempts[attempts.length - 1].status, archiveRemoved: false, attempts,
  archive: { key: "packages/npm/2026-11-04-maps-viewer/packages_npm.tar.gz", etag: "\"a\"", size: 1 },
  manifest: { key: "packages/npm/2026-11-04-maps-viewer/manifest.json", etag: "\"b\"", size: 1 },
})

const failures = [
  ...many(1, "failed", { kind: "conflict", reason: "Nexus holds package with other bytes" }),
  ...many(1, "failed", { kind: "nexus", reason: "Nexus answered 500" }),
  ...many(1, "failed", { kind: "source", reason: "MinIO cut the read" }),
]
const incomplete = () => make([attempt(1, "ended", "incomplete", [...many(40, "published"), ...many(58, "present"), ...failures])])

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" } })

/** The page's parts the retry touches, fed by the real query hook. */
function Page() {
  const imp = useImport(ID).data
  if (!imp) {
    return null
  }
  return (
    <>
      <AttemptProgress attempt={latestAttempt(imp)} />
      <EndState imp={imp} />
      {imp.outcome === "incomplete" || imp.outcome === "interrupted" ? <RetryCard imp={imp} /> : null}
    </>
  )
}

function renderPage(answer: (init?: RequestInit) => Response, first: Import) {
  let current = first
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === `/api/imports/${ID}/retry`) {
      const res = answer(init)
      if (res.status === 202) {
        current = (await res.clone().json()) as Import
      }
      return res
    }
    return json(current)
  })
  vi.stubGlobal("fetch", fetchMock)
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Page /></QueryClientProvider>)
  return fetchMock
}

describe("RetryCard", () => {
  it("states how many packages are not in Nexus, what a retry does and the split", async () => {
    renderPage(() => json({}, 500), incomplete())
    expect(await screen.findByRole("heading", { name: "3 of 101 packages are not in Nexus" })).toBeInTheDocument()
    expect(screen.getByText(/Retry adds attempt 2 to this import/)).toBeInTheDocument()
    expect(screen.getByText("Reads the archive and its manifest from MinIO again and checks the sha256 again.")).toBeInTheDocument()
    expect(screen.getByText("Removes the archive from MinIO only once every package is in Nexus.")).toBeInTheDocument()
    const clears = screen.getByRole("group", { name: "Can succeed on retry" })
    expect(clears).toHaveTextContent("1 package")
    const change = screen.getByRole("group", { name: "Fails again until fixed outside sealift" })
    expect(within(change).getByText(/1 conflict/)).toBeInTheDocument()
    expect(within(change).getByText(/delete it in Nexus, then retry/)).toBeInTheDocument()
    expect(within(change).getByText(/1 nexus/)).toBeInTheDocument()
    expect(within(change).getByText(/import account may upload/)).toBeInTheDocument()
    expect(screen.getAllByRole("button", { name: "Retry import" })).toHaveLength(1)
  })

  it("says how many packages are in Nexus already, which a retry leaves untouched", async () => {
    renderPage(() => json({}, 500), incomplete())
    expect(await screen.findByText("Reads all 101 packages from Nexus again. 98 are there already and stay untouched; it uploads only what Nexus does not have.")).toBeInTheDocument()
  })

  it("says the general words for a failure with no kind", async () => {
    const legacy = make([attempt(1, "ended", "incomplete", [...many(10, "published"), pkg("failed", { reason: "Nexus answered 500" })])])
    renderPage(() => json({}, 500), legacy)
    expect(await screen.findByRole("heading", { name: "1 of 11 packages are not in Nexus" })).toBeInTheDocument()
    expect(screen.getByText(/Read the reason: it names what failed\. Fix that, then retry\./)).toBeInTheDocument()
    expect(screen.queryByRole("group", { name: "Fails again until fixed outside sealift" })).toBeNull()
  })

  it("puts an interrupted import's packages in the group that clears as is", async () => {
    const imp = make([attempt(1, "ended", "interrupted", [...many(56, "published"), ...many(45, "failed", { kind: "interrupted", reason: "interrupted" })])])
    renderPage(() => json({}, 500), imp)
    expect(await screen.findByRole("heading", { name: "45 of 101 packages are not in Nexus" })).toBeInTheDocument()
    expect(screen.getByRole("group", { name: "Can succeed on retry" })).toHaveTextContent("45 packages")
    expect(screen.queryByRole("group", { name: "Fails again until fixed outside sealift" })).toBeNull()
  })

  it("keeps the one primary button right after the text", async () => {
    renderPage(() => json({}, 500), incomplete())
    const button = await screen.findByRole("button", { name: "Retry import" })
    const card = button.closest("section") as HTMLElement
    expect(card.lastElementChild).toContainElement(button)
  })

  it("retry answers: a 202 shows the new attempt in place with focus on its status", async () => {
    const next = make([...incomplete().attempts, attempt(2, "queued", "", [])])
    const fetchMock = renderPage(() => json(next, 202), incomplete())
    fireEvent.click(await screen.findByRole("button", { name: "Retry import" }))
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Waiting its turn"))
    const status = screen.getByRole("status")
    await waitFor(() => expect(status).toHaveFocus())
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
    const post = fetchMock.mock.calls.find((c) => c[0] === `/api/imports/${ID}/retry`)
    expect(post?.[1]).toMatchObject({ method: "POST", body: "{}", headers: { "Content-Type": "application/json" } })
  })

  it("retry answers: a 409 shows the detail and its next action, then refetches the import", async () => {
    const detail = "an attempt is already queued or running for this import"
    const fetchMock = renderPage(() => json({ type: "about:blank", title: "Conflict", status: 409, detail }, 409), incomplete())
    const reads = () => fetchMock.mock.calls.filter((c) => c[0] === `/api/imports/${ID}`).length
    fireEvent.click(await screen.findByRole("button", { name: "Retry import" }))
    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent(detail)
    expect(alert).toHaveTextContent("Nothing was changed")
    expect(alert).toHaveTextContent("upload it again and start a new import from Archives")
    await waitFor(() => expect(reads()).toBeGreaterThan(1))
  })
})
