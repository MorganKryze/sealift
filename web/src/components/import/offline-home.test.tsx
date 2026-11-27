import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Archive, ArchiveList, Import } from "@/import/api/queries"

import { greeting, OfflineHome } from "./offline-home"

// The home's address: a refused row's Open sets `refused` to its archive's key.
const address = vi.hoisted(() => ({ search: {} as Record<string, string>, navigate: vi.fn() }))

vi.mock("@tanstack/react-router", () => ({
  useSearch: () => address.search,
  useNavigate: () => address.navigate,
  Link: ({ to, search, children, ...rest }: { to: string; search?: Record<string, string>; children: ReactNode }) => (
    <a href={search ? `${to}?${new URLSearchParams(search).toString()}` : to} {...rest}>
      {children}
    </a>
  ),
}))

// Today at 14:00 local time: the home reads "today" from local midnight.
const NOW = new Date(2026, 10, 25, 14, 0)
const at = (day: number, hour: number, minute = 0) => new Date(2026, 10, day, hour, minute).toISOString()

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] })
  vi.setSystemTime(NOW)
})

afterEach(() => {
  address.search = {}
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } })

const archive = (folder: string, modified: string, over: Partial<Archive> = {}): Archive => ({
  key: `packages/npm/${folder}/packages_npm.tar.gz`, ecosystem: "npm", size: 5_500_000, modified, importable: true, ...over,
})

const folderList = (archives: Archive[], over: Partial<ArchiveList> = {}): ArchiveList => ({
  minioConfigured: true, bucket: "user-alice", folder: "packages/npm/", folders: ["packages/npm/", "packages/pip/"], bucketMissing: false, truncated: false, unencrypted: [], archives, ...over,
})

const pkg = (i: number, state: string, extra: Record<string, string> = {}) => ({ name: `package-${i}`, version: "1.0.0", file: `package-${i}.tgz`, state, reason: "", note: "", ...extra })

function packages(published: number, failed: number, pending = 0) {
  return [
    ...Array.from({ length: published }, (_, i) => pkg(i, "published")),
    ...Array.from({ length: failed }, (_, i) => pkg(published + i, "failed", { kind: "nexus", reason: "Nexus answered 500" })),
    ...Array.from({ length: pending }, (_, i) => pkg(published + failed + i, "pending")),
  ]
}

function attempt(outcome: string, createdAt: string, list: ReturnType<typeof packages>, reason = ""): Import["attempts"][number] {
  const running = outcome === "running" || outcome === "queued"
  return {
    n: 1,
    status: running ? outcome : "ended",
    queuedAt: createdAt,
    startedAt: outcome === "queued" ? undefined : createdAt,
    endedAt: running ? undefined : createdAt,
    outcome: running ? "" : outcome,
    report: {
      outcome: running ? "" : outcome, reason, unencrypted: false, importVersion: "0.7.0",
      archive: { file: "packages_npm.tar.gz", sha256: "", size: 5_500_000 }, toolVersion: "0.7.0", analysisId: "",
      target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.0.0" },
      nexus: { url: "", repository: "" }, counts: { published: 0, present: 0, failed: 0 }, packages: list,
    },
  }
}

function imp(id: string, folder: string, outcome: string, when: string, list: ReturnType<typeof packages> = [], reason = ""): Import {
  const key = `packages/npm/${folder}/packages_npm.tar.gz`
  return {
    id, createdAt: when, outcome, archiveRemoved: outcome === "complete", expectedSha256: "",
    archive: { key, etag: `"${id}"`, size: 5_500_000 },
    manifest: { key: `packages/npm/${folder}/manifest.json`, etag: `"m${id}"`, size: 1_000 },
    attempts: [attempt(outcome, when, list, reason)],
  }
}

function renderHome({ archives = folderList([]), imports = [] as Import[], user = "alice" } = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === "/api/me") return json({ user, minioConfigured: true, bucket: "user-alice", folder: "packages/npm/", publicKeySha256: "" })
      if (url === "/api/imports") return json({ imports })
      if (url === "/api/archives") return json(archives)
      throw new Error(`unexpected request ${url}`)
    }),
  )
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <OfflineHome />
    </QueryClientProvider>,
  )
}

const group = (name: string) => screen.getByRole("region", { name })
const rowNames = (region: HTMLElement) => within(region).getAllByRole("listitem").map((li) => li.querySelector("[data-row-name]")?.textContent)
const rowOf = (name: string) => screen.getByText(name, { selector: "[data-row-name]" }).closest("li") as HTMLElement

describe("rows", () => {
  it("names each crossing in weight 600", async () => {
    const signed = { signature: "verified" as const, crossing: { project: "web-portal", sealedAt: "2026-11-25T09:00:00Z", packages: 12 } }
    const { container } = renderHome({ archives: folderList([archive("web-portal-2026-11-20", at(25, 12), signed)]) })
    await screen.findByText("web-portal · 25 Nov", { selector: "[data-row-name]" })
    const names = [...container.querySelectorAll("[data-row-name]")]
    expect(names.length).toBeGreaterThan(0)
    for (const name of names) expect(name).toHaveClass("font-semibold")
  })
})

describe("greeting", () => {
  it("greets the user by the part of the day", async () => {
    expect(greeting(new Date(2026, 10, 25, 6, 30), "alice")).toBe("Good morning, alice")
    expect(greeting(new Date(2026, 10, 25, 11, 59), "alice")).toBe("Good morning, alice")
    expect(greeting(new Date(2026, 10, 25, 12, 0), "alice")).toBe("Good afternoon, alice")
    expect(greeting(new Date(2026, 10, 25, 17, 59), "alice")).toBe("Good afternoon, alice")
    expect(greeting(new Date(2026, 10, 25, 18, 0), "alice")).toBe("Good evening, alice")
    renderHome()
    expect(await screen.findByRole("heading", { level: 1, name: "Good afternoon, alice" })).toBeInTheDocument()
  })

  it("greets without a name when the token carries none", async () => {
    expect(greeting(new Date(2026, 10, 25, 9, 0))).toBe("Good morning")
    expect(greeting(new Date(2026, 10, 25, 20, 0), "")).toBe("Good evening")
    renderHome({ user: "" })
    await screen.findByRole("region", { name: "Needs you" })
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(/^Good afternoon$/)
  })
})

describe("the offline home", () => {
  it("shows Import as the only path card", async () => {
    const { container } = renderHome()
    await screen.findByRole("region", { name: "Needs you" })
    const cards = container.querySelectorAll("[data-path-card]")
    expect(cards).toHaveLength(1)
    expect(cards[0]).toHaveAttribute("href", "/import")
    expect(cards[0]).toHaveTextContent("Import")
    expect(cards[0]).toHaveTextContent("an archive")
  })

  it("offers no Find or Audit card", async () => {
    const { container } = renderHome({ archives: folderList([archive("web-portal-2026-11-20", at(25, 12))]) })
    await screen.findByRole("region", { name: "Needs you" })
    expect(container.querySelectorAll("[data-path-card]")).toHaveLength(1)
    for (const word of [/Find/, /Audit/, /Add/, /Hand-built/]) expect(screen.queryByText(word)).not.toBeInTheDocument()
  })

  it("lists an importable archive with its ecosystem, size and upload time and Import in Needs you", async () => {
    const pip = archive("data-pipeline-2026-11-22", at(25, 12), { key: "packages/pip/data-pipeline-2026-11-22/packages_pip.tar.gz", ecosystem: "pip", size: 92_400_000 })
    renderHome({ archives: folderList([archive("web-portal-2026-11-20", at(24, 9)), pip]) })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs)).toEqual(["data-pipeline-2026-11-22/", "web-portal-2026-11-20/"])
    const row = rowOf("data-pipeline-2026-11-22/")
    expect(row).toHaveTextContent("pip · 88.1 MB · uploaded 2 hours ago")
    const action = within(row).getByRole("link", { name: "Import data-pipeline-2026-11-22/" })
    expect(action).toHaveAttribute("href", `/import?start=${encodeURIComponent(pip.key)}`)
    expect(rowOf("web-portal-2026-11-20/")).toHaveTextContent("npm · 5.2 MB · uploaded yesterday")
  })

  it("lists a failed import with Open in Needs you", async () => {
    const failed = imp("i-failed", "admin-console-2026-11-19", "incomplete", at(25, 10), packages(98, 3))
    renderHome({ archives: folderList([archive("admin-console-2026-11-19", at(24, 9), { latestImport: { id: "i-failed", outcome: "incomplete" } })]), imports: [failed] })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs)).toEqual(["admin-console-2026-11-19/"])
    const row = rowOf("admin-console-2026-11-19/")
    expect(row).toHaveTextContent("Failed")
    expect(row).toHaveTextContent("3 packages not in Nexus")
    expect(within(row).getByText("3").tagName).toBe("B")
    expect(within(row).getByRole("link", { name: "Open admin-console-2026-11-19/" })).toHaveAttribute("href", "/imports/i-failed")
    expect(within(row).queryByRole("link", { name: /^Import/ })).not.toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "In progress" })).not.toBeInTheDocument()
  })

  it("shows a refused archive's reason on its row and no Import", async () => {
    const refusedImport = imp("i-refused", "pdf-renderer-2026-11-18", "refused", at(25, 8), [], "signed with a key this side does not trust")
    renderHome({
      archives: folderList([
        archive("billing-api-2026-11-18", at(24, 9), { importable: false, reason: "no manifest.json.sig in its folder" }),
        archive("pdf-renderer-2026-11-18", at(23, 9), { latestImport: { id: "i-refused", outcome: "refused" } }),
      ]),
      imports: [refusedImport],
    })
    await screen.findByRole("region", { name: "Needs you" })
    const listed = rowOf("billing-api-2026-11-18/")
    expect(listed).toHaveTextContent("Refused")
    expect(listed).toHaveTextContent("no manifest.json.sig in its folder")
    expect(within(listed).getAllByRole("link")).toHaveLength(1)
    expect(within(listed).getByRole("link", { name: "Open billing-api-2026-11-18/" })).toHaveAttribute("href", `/?${new URLSearchParams({ refused: "packages/npm/billing-api-2026-11-18/packages_npm.tar.gz" })}`)
    const imported = rowOf("pdf-renderer-2026-11-18/")
    expect(imported).toHaveTextContent("Refused")
    expect(imported).toHaveTextContent("signed with a key this side does not trust")
    expect(within(imported).getAllByRole("link")).toHaveLength(1)
    expect(within(imported).getByRole("link", { name: "Open pdf-renderer-2026-11-18/" })).toHaveAttribute("href", "/imports/i-refused")
  })

  it("opens the refused panel from a refused row's Open, titled by the row's name", async () => {
    const key = "packages/npm/billing-api-2026-11-18/packages_npm.tar.gz"
    address.search = { refused: key }
    renderHome({ archives: folderList([archive("billing-api-2026-11-18", at(24, 9), { importable: false, reason: "no manifest.json.sig in its folder", signature: "unsigned" })]), imports: [] })
    const dialog = await screen.findByRole("dialog", { name: "Refused" })
    expect(within(dialog).getByRole("heading", { level: 3 })).toHaveTextContent("billing-api-2026-11-18/")
    expect(dialog).toHaveTextContent("No manifest.json.sig in its folder.")
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }))
    expect(address.navigate).toHaveBeenCalledWith({ to: "/", replace: true })
  })

  it("names an archive by its folder and file when its folder holds another", async () => {
    const reason = "the folder holds more than one archive"
    renderHome({
      archives: folderList([
        archive("two-archives", at(24, 9), { key: "packages/npm/two-archives/first.tar.gz", importable: false, reason }),
        archive("two-archives", at(24, 9, 1), { key: "packages/npm/two-archives/second.tar.gz", importable: false, reason }),
      ]),
    })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs)).toEqual(["two-archives/second.tar.gz", "two-archives/first.tar.gz"])
  })

  it("lists queued and running imports in In progress", async () => {
    renderHome({
      imports: [
        imp("i-queued", "intranet-portal-2026-11-25", "queued", at(25, 13)),
        imp("i-running", "search-indexer-2026-11-21", "running", at(25, 12), packages(37, 0, 64)),
      ],
    })
    const progress = await screen.findByRole("region", { name: "In progress" })
    expect(rowNames(progress)).toEqual(["intranet-portal-2026-11-25/", "search-indexer-2026-11-21/"])
    expect(rowOf("intranet-portal-2026-11-25/")).toHaveTextContent("Queued")
    const running = rowOf("search-indexer-2026-11-21/")
    expect(running).toHaveTextContent("Importing")
    expect(running).toHaveTextContent("37 of 101 packages")
    expect(within(running).getByRole("link", { name: "Open search-indexer-2026-11-21/" })).toHaveAttribute("href", "/imports/i-running")
  })

  it("lists imports complete today in Done today", async () => {
    renderHome({
      imports: [
        imp("i-today", "kiosk-ui-2026-11-21", "complete", at(25, 0, 5), packages(1284, 0)),
        imp("i-later", "maps-2026-11-24", "complete", at(25, 9), packages(12, 0)),
        imp("i-yesterday", "hr-forms-2026-11-20", "complete", at(24, 23, 55), packages(101, 0)),
      ],
    })
    const done = await screen.findByRole("region", { name: "Done today" })
    expect(rowNames(done)).toEqual(["maps-2026-11-24/", "kiosk-ui-2026-11-21/"])
    const row = rowOf("kiosk-ui-2026-11-21/")
    expect(row).toHaveTextContent("Done")
    expect(row).toHaveTextContent("1,284 packages in Nexus")
    expect(within(row).getByRole("link", { name: "Open kiosk-ui-2026-11-21/" })).toHaveAttribute("href", "/imports/i-today")
    expect(screen.queryByText("hr-forms-2026-11-20/")).not.toBeInTheDocument()
  })

  it("never lists a failure or a refusal in Done today", async () => {
    renderHome({
      archives: folderList([archive("docs-site-2026-11-25", at(25, 7), { latestImport: { id: "i-refused", outcome: "refused" } })]),
      imports: [
        imp("i-incomplete", "maps-viewer-2026-11-25", "incomplete", at(25, 9), packages(98, 3)),
        imp("i-interrupted", "payments-2026-11-25", "interrupted", at(25, 10), packages(52, 45)),
        imp("i-refused", "docs-site-2026-11-25", "refused", at(25, 11), [], "the archive's sha256 is not the expected one"),
      ],
    })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs)).toEqual(["payments-2026-11-25/", "maps-viewer-2026-11-25/", "docs-site-2026-11-25/"])
    expect(screen.queryByRole("region", { name: "Done today" })).not.toBeInTheDocument()
  })

  it("hides an empty group", async () => {
    renderHome({ archives: folderList([archive("web-portal-2026-11-20", at(25, 12))]) })
    await screen.findByRole("region", { name: "Needs you" })
    expect(screen.queryByRole("region", { name: "In progress" })).not.toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "Done today" })).not.toBeInTheDocument()
  })

  it("names both folders when nothing waits", async () => {
    renderHome()
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(needs).toHaveTextContent("No archive in user-alice/packages/npm/ or packages/pip/")
    expect(within(needs).queryByRole("listitem")).not.toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "In progress" })).not.toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "Done today" })).not.toBeInTheDocument()
  })

  it("puts refused and failed rows first, ten, then Show all", async () => {
    // 16 archives with 40-character names: 11 to import, 3 refused by the list, 2 with a failed import.
    const long = (i: number) => `${"customer-portal-frontend-monorepo-".slice(0, 33)}${String(i).padStart(2, "0")}-2611`
    const toImport = Array.from({ length: 11 }, (_, i) => archive(long(i), at(25, 13, 50 - i)))
    const refused = Array.from({ length: 3 }, (_, i) => archive(long(20 + i), at(20, 9, i), { importable: false, reason: "its signature does not match its manifest", signature: "mismatch" }))
    const failedImports = [imp("i-f1", long(30), "incomplete", at(21, 9), packages(10, 3)), imp("i-f2", long(31), "incomplete", at(22, 9), packages(10, 2))]
    const failedArchives = failedImports.map((f, i) => archive(long(30 + i), at(19, 9), { latestImport: { id: f.id, outcome: "incomplete" } }))
    expect(long(0)).toHaveLength(40)
    renderHome({ archives: folderList([...toImport, ...refused, ...failedArchives]), imports: failedImports })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    const first = rowNames(needs)
    expect(first).toHaveLength(10)
    expect(first.slice(0, 5)).toEqual([`${long(31)}/`, `${long(30)}/`, `${long(22)}/`, `${long(21)}/`, `${long(20)}/`])
    expect(first.slice(5)).toEqual(Array.from({ length: 5 }, (_, i) => `${long(i)}/`))
    const more = within(needs).getByRole("button", { name: "Show all 16 archives" })
    expect(more).toHaveAttribute("aria-expanded", "false")
    fireEvent.click(more)
    expect(rowNames(group("Needs you"))).toHaveLength(16)
    const fewer = within(group("Needs you")).getByRole("button", { name: "Show fewer" })
    expect(fewer).toHaveAttribute("aria-expanded", "true")
    fireEvent.click(fewer)
    expect(rowNames(group("Needs you"))).toHaveLength(10)
  })

  it("keeps an interrupted or cancelled import out of In progress", async () => {
    renderHome({
      imports: [
        imp("i-interrupted", "payments-2026-11-25", "interrupted", at(25, 10), packages(52, 45)),
        imp("i-cancelled", "billing-api-2026-11-25", "cancelled", at(25, 11), packages(40, 0, 61)),
        imp("i-running", "search-indexer-2026-11-21", "running", at(25, 12), packages(37, 0, 64)),
      ],
    })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs)).toEqual(["billing-api-2026-11-25/", "payments-2026-11-25/"])
    expect(rowOf("billing-api-2026-11-25/")).toHaveTextContent("Cancelled")
    expect(rowOf("billing-api-2026-11-25/")).toHaveTextContent("61 packages not in Nexus")
    expect(rowNames(group("In progress"))).toEqual(["search-indexer-2026-11-21/"])
  })

  it("names an import by its crossing once its report has one", async () => {
    const done = imp("i-today", "kiosk-ui-2026-11-21", "complete", at(25, 9), packages(12, 0))
    done.attempts[0].report.crossing = { project: "kiosk-ui", sealedAt: "2026-11-21T09:00:00Z", packages: 12 }
    renderHome({ imports: [done] })
    await screen.findByRole("region", { name: "Done today" })
    expect(rowOf("kiosk-ui · 25 Nov")).toHaveTextContent("12 packages in Nexus")
  })

  it("shows 10 rows of a group and a control that shows all 18", async () => {
    const many = Array.from({ length: 18 }, (_, i) => archive(`app-${String(i).padStart(2, "0")}`, at(25, 13, 59 - i)))
    renderHome({ archives: folderList(many) })
    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs)).toEqual(Array.from({ length: 10 }, (_, i) => `app-${String(i).padStart(2, "0")}/`))
    fireEvent.click(within(needs).getByRole("button", { name: "Show all 18 archives" }))
    expect(within(group("Needs you")).getAllByRole("listitem")).toHaveLength(18)
    expect(within(group("Needs you")).queryByRole("button", { name: /Show all/ })).not.toBeInTheDocument()
  })
})
