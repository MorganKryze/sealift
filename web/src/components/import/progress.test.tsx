import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Attempt, Import, ReportPackage } from "@/import/lib/outcome"

import { AttemptProgress, attemptLog, attemptSteps, publishRate } from "./progress"

afterEach(() => {
  vi.unstubAllGlobals()
})

const ID = "20261125T142000Z-a2000001"
const KEY = "packages/npm/web-portal-2026-11-25/packages_npm.tar.gz"

const pkg = (i: number, state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name: `package-${i}`, version: "1.0.0", file: `npm/package-${i}/-/package-${i}-1.0.0.tgz`, state, reason: "", note: "", ...over,
})

/** total packages: the first `published` published, the next `present` present, then the failures, the rest pending. */
function packages(total: number, published: number, present = 0, failures: Partial<ReportPackage>[] = []): ReportPackage[] {
  const out: ReportPackage[] = []
  for (let i = 0; i < published; i++) out.push(pkg(out.length, "published"))
  for (let i = 0; i < present; i++) out.push(pkg(out.length, "present"))
  for (const f of failures) out.push(pkg(out.length, "failed", f))
  while (out.length < total) out.push(pkg(out.length, "pending"))
  return out
}

function attempt(status: string, list: ReportPackage[], over: Partial<Attempt> = {}, checked?: boolean): Attempt {
  return {
    n: 1, status, outcome: "",
    report: {
      outcome: "", reason: "", unencrypted: false, importVersion: "", archive: { file: "packages_npm.tar.gz", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages: list, archiveChecked: checked,
    },
    ...over,
  }
}

const make = (a: Attempt, over: Partial<Import> = {}): Import => ({
  id: ID, createdAt: "2026-11-25T14:20:00Z", expectedSha256: "", outcome: a.outcome || a.status, archiveRemoved: false, attempts: [a],
  archive: { key: KEY, etag: '"a"', size: 101_187_584 }, manifest: { key: "packages/npm/web-portal-2026-11-25/manifest.json", etag: '"b"', size: 1 },
  ...over,
})

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" } })

/** Renders the progress of imp, its query data written at `at` as the page's poll would. */
function setup(first: Import, at?: number) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const write = (imp: Import, when?: number) => client.setQueryData(["imports", imp.id], imp, when === undefined ? undefined : { updatedAt: when })
  if (at !== undefined) write(first, at)
  const wrap = (node: ReactNode) => <QueryClientProvider client={client}>{node}</QueryClientProvider>
  const view = render(wrap(<AttemptProgress imp={first} attempt={first.attempts[first.attempts.length - 1]} />))
  const next = (imp: Import, when?: number) => {
    if (when !== undefined) write(imp, when)
    view.rerender(wrap(<AttemptProgress imp={imp} attempt={imp.attempts[imp.attempts.length - 1]} />))
  }
  return { ...view, next }
}

const title = () => screen.getByRole("heading", { level: 1 })

describe("a queued import", () => {
  it("says how many imports run before it, with no name", () => {
    setup(make(attempt("queued", []), { queueAhead: 1 }))
    expect(title()).toHaveTextContent("Waiting its turn")
    expect(screen.getByText(/ahead of this one/).textContent).toBe("1 import ahead of this one")
    expect(screen.getByText("Keeps its place if you leave this page")).toBeInTheDocument()
    expect(screen.queryByRole("progressbar")).toBeNull()
    expect(screen.queryByRole("region", { name: "Log" })).toBeNull()
    expect(screen.queryByRole("button", { name: /Compliant/ })).toBeNull()
    expect(screen.queryByRole("link")).toBeNull()
  })

  it("cancels a queued import with no confirmation", async () => {
    const cancelled = make(attempt("ended", [], { outcome: "cancelled" }), { outcome: "cancelled" })
    const fetchMock = vi.fn(async () => json(cancelled, 202))
    vi.stubGlobal("fetch", fetchMock)
    setup(make(attempt("queued", []), { queueAhead: 3 }))
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(screen.queryByRole("button", { name: "Keep running" })).toBeNull()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(fetchMock.mock.calls[0]).toEqual([`/api/imports/${ID}/cancel`, expect.objectContaining({ method: "POST" })])
  })
})

describe("an import that checks its archive", () => {
  it("says Checking the archive over a still track", () => {
    setup(make(attempt("running", packages(1284, 0), {}, false)))
    expect(title()).toHaveTextContent("Checking the archive")
    expect(screen.getByText(/read once against its signed manifest/).textContent).toBe("96.5 MB read once against its signed manifest")
    expect(screen.getByRole("progressbar")).toHaveAttribute("data-estimating")
    expect(screen.getByRole("region", { name: "Log" })).toBeInTheDocument()
    expect(screen.getByText("Live")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
    expect(attemptSteps(attempt("running", packages(3, 0), {}, false)).map((s) => [s.label, s.status])).toEqual([["Check", "running"], ["Publish", "upcoming"], ["In Nexus", "upcoming"]])
  })

  it("draws the striped track still", () => {
    setup(make(attempt("running", packages(1284, 0), {}, false)))
    const track = screen.getByRole("progressbar")
    expect(track.getAttribute("style") ?? "").toContain("repeating-linear-gradient")
    expect(track.className).not.toMatch(/animate/)
    expect(track.querySelector("[class*=animate]")).toBeNull()
    expect(track).not.toHaveAttribute("aria-valuenow")
  })
})

describe("an import that publishes", () => {
  it("counts the published and the present together", () => {
    setup(make(attempt("running", packages(1284, 700, 96), {}, true)))
    expect(screen.getByText(/packages in Nexus/).textContent).toBe("796 of 1,284 packages in Nexus")
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "62")
    expect(attemptSteps(attempt("running", packages(3, 1), {}, true)).map((s) => [s.label, s.status, s.current])).toEqual([
      ["Check", "done", false], ["Publish", "running", true], ["In Nexus", "upcoming", false],
    ])
    expect(screen.getByRole("button", { name: /Compliant/ })).toHaveAttribute("aria-expanded", "false")
  })

  it("titles the time left once two polls saw progress", () => {
    const at = (published: number) => make(attempt("running", packages(4206, published), {}, true))
    const { next } = setup(at(0), 1_000)
    expect(title()).toHaveTextContent("Estimating time left")
    next(at(10), 3_000)
    expect(title()).toHaveTextContent("Estimating time left")
    next(at(30), 7_000)
    // 20 packages in 4 s, 4,176 left: 835 s.
    expect(title()).toHaveTextContent("About 14 minutes left")
  })

  it("ends each log line with its result", () => {
    const nexus = "502 from the gateway in front of Nexus " + "x".repeat(600)
    const list = [pkg(0, "published"), pkg(1, "present"), pkg(2, "failed", { kind: "nexus", reason: nexus }), pkg(3, "pending")]
    setup(make(attempt("running", list, {}, true)))
    const log = screen.getByRole("region", { name: "Log" })
    expect(within(log).getByText("package-0 1.0.0 · published")).toHaveClass("text-ok")
    expect(within(log).getByText("package-1 1.0.0 · already in Nexus, same sha512")).toBeInTheDocument()
    const failed = within(log).getByText(`package-2 1.0.0 · ${nexus}`)
    expect(failed).toHaveClass("text-bad")
    expect(within(log).queryByText(/package-3/)).toBeNull()
  })

  it("shows the failed packages chip", () => {
    const fail = { kind: "nexus" as const, reason: "Nexus answered 502" }
    const { next } = setup(make(attempt("running", packages(4206, 2000, 1), {}, true)))
    expect(screen.queryByText(/packages? failed/)).toBeNull()
    next(make(attempt("running", packages(4206, 2000, 1, [fail, fail, fail]), {}, true)))
    expect(screen.getByText("3 packages failed")).toBeInTheDocument()
    expect(screen.getByText(/packages in Nexus/).textContent).toBe("2,001 of 4,206 packages in Nexus")
  })

  it("asks in place and focuses Keep running", async () => {
    const fetchMock = vi.fn(async () => json({}, 202))
    vi.stubGlobal("fetch", fetchMock)
    setup(make(attempt("running", packages(1284, 700, 96), {}, true)))
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.getByText("Packages already in Nexus stay there; a retry publishes the rest.")).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole("button", { name: "Keep running" })).toHaveFocus())
    expect(screen.getByRole("button", { name: "Cancel import" })).toBeInTheDocument()
  })

  it("shows Cancelling with its width kept", async () => {
    let answer: (r: Response) => void = () => {}
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((done) => { answer = done })))
    setup(make(attempt("running", packages(1284, 700, 96), {}, true)))
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    fireEvent.click(screen.getByRole("button", { name: "Cancel import" }))
    const button = await screen.findByRole("button", { name: /^Cancelling/ })
    expect(button).toHaveAttribute("aria-disabled", "true")
    // The word it had stays in the button, hidden, so the width holds.
    expect(button.querySelector("[aria-hidden=true].invisible")).toHaveTextContent("Cancel")
    expect(screen.queryByText("Keeps running if you leave this page")).toBeNull()
    answer(json({}, 202))
  })
})

describe("a cancelled import", () => {
  const cancelled = () =>
    make(
      attempt("ended", packages(1284, 700, 112, Array.from({ length: 472 }, () => ({ kind: "interrupted" as const, reason: "cancelled before it was published" }))), {
        outcome: "cancelled", startedAt: "2026-11-25T14:20:00Z", endedAt: "2026-11-25T14:22:53Z",
      }, true),
      { outcome: "cancelled" },
    )

  it("uses no red for a cancel and offers Retry of what is missing", () => {
    const { container } = setup(cancelled())
    expect(title()).toHaveTextContent("Import cancelled")
    expect(screen.getByText(/packages are in Nexus/).textContent).toBe("After 2 min 53 s. 812 of 1,284 packages are in Nexus.")
    expect(container.querySelector("[class*=bad]")).toBeNull()
    expect(screen.getByRole("button", { name: /^Log/ })).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByRole("button", { name: "Retry 472 packages" })).toBeInTheDocument()
    expect(screen.queryByText("Live")).toBeNull()
    const steps = attemptSteps(cancelled().attempts[0])
    expect(steps.map((s) => [s.label, s.status])).toEqual([["Check", "done"], ["Publish", "cancelled"], ["In Nexus", "upcoming"]])
  })
})

describe("the log and the progress node", () => {
  it("rebuilds the log from the report with no line twice", () => {
    const at = (published: number) => make(attempt("running", packages(4206, published), {}, true))
    const { next } = setup(at(2), 1_000)
    const lines = () => within(screen.getByRole("region", { name: "Log" })).getAllByText(/^package-\d+ 1\.0\.0 · published$/).map((l) => l.textContent)
    expect(lines()).toEqual(["package-0 1.0.0 · published", "package-1 1.0.0 · published"])
    const count = () => screen.getByRole("button", { name: /^Log/ }).textContent
    const before = count()
    next(at(2), 3_000)
    expect(count()).toBe(before)
    next(at(4), 5_000)
    next(at(4), 7_000)
    expect(lines()).toEqual(["package-0 1.0.0 · published", "package-1 1.0.0 · published", "package-2 1.0.0 · published", "package-3 1.0.0 · published"])
  })

  it("keeps one progress node through the attempt", () => {
    const { next } = setup(make(attempt("running", packages(40, 0), {}, false)))
    const heading = title()
    const bar = screen.getByRole("progressbar")
    for (const published of [0, 5, 10]) {
      next(make(attempt("running", packages(40, published), {}, true)))
      expect(title()).toBe(heading)
      expect(screen.getByRole("progressbar")).toBe(bar)
    }
  })

  it("shows the end in place", () => {
    const stopped = { kind: "interrupted" as const, reason: "cancelled before it was published" }
    const { next } = setup(make(attempt("running", packages(4, 2), {}, true)))
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
    next(make(attempt("ended", packages(4, 2, 0, [stopped, stopped]), { outcome: "cancelled" }, true), { outcome: "cancelled" }))
    expect(title()).toHaveTextContent("Import cancelled")
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull()
    next(make(attempt("ended", packages(4, 4), { outcome: "complete" }, true), { outcome: "complete" }))
    expect(screen.queryByRole("progressbar")).toBeNull()
    expect(screen.queryByRole("heading", { level: 1 })).toBeNull()
    expect(attemptSteps(attempt("ended", packages(4, 4), { outcome: "complete" }, true)).map((s) => s.status)).toEqual(["done", "done", "done"])
  })

  it("lists every ended package of an earlier attempt, once", () => {
    const lines = attemptLog(attempt("ended", packages(3, 1, 1, [{ kind: "conflict", reason: "Nexus holds it with other bytes" }]), { outcome: "incomplete" }, true))
    expect(lines.filter((l) => l.text.startsWith("package-")).map((l) => l.text)).toEqual([
      "package-0 1.0.0 · published", "package-1 1.0.0 · already in Nexus, same sha512", "package-2 1.0.0 · Nexus holds it with other bytes",
    ])
  })
})

describe("publishRate", () => {
  it("waits for two polls that both saw progress", () => {
    expect(publishRate([])).toBeUndefined()
    expect(publishRate([{ at: 0, ended: 0 }, { at: 5_000, ended: 100 }])).toBeUndefined()
    expect(publishRate([{ at: 0, ended: 0 }, { at: 5_000, ended: 0 }, { at: 10_000, ended: 0 }])).toBeUndefined()
  })

  it("waits until those polls are a few seconds apart", () => {
    expect(publishRate([{ at: 0, ended: 0 }, { at: 1_000, ended: 10 }, { at: 2_000, ended: 20 }])).toBeUndefined()
  })

  it("gives packages per ms between the first and the last poll that saw progress", () => {
    expect(publishRate([{ at: 0, ended: 0 }, { at: 2_000, ended: 10 }, { at: 4_000, ended: 10 }, { at: 6_000, ended: 30 }])).toBe(20 / 4_000)
  })
})
