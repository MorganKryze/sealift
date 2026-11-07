import { fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Attempt, ReportPackage } from "@/import/lib/outcome"

import { ReportList } from "./report-list"

afterEach(() => {
  vi.restoreAllMocks()
})

const pkg = (name: string, state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name, version: "1.0.0", file: `npm/${name}.tgz`, state, reason: "", note: "", ...over,
})

function attempt(packages: ReportPackage[], n = 1): Attempt {
  return {
    n, status: "ended", outcome: "incomplete",
    report: {
      outcome: "incomplete", reason: "", unencrypted: false, importVersion: "", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages,
    },
  }
}

const rows = () => within(screen.getByRole("list", { name: "Packages" })).queryAllByRole("listitem")

describe("report list", () => {
  it("opens on Failed when an attempt followed live ends with a failed package", () => {
    const live = { ...attempt([pkg("a", "pending"), pkg("d", "pending")]), status: "running", outcome: "" }
    const { rerender } = render(<ReportList attempt={live} />)
    expect(screen.getByRole("button", { name: /^All/ })).toHaveAttribute("aria-pressed", "true")
    rerender(<ReportList attempt={attempt([pkg("a", "published"), pkg("d", "failed", { kind: "nexus", reason: "Nexus answered 500" })])} />)
    expect(screen.getByRole("button", { name: /^Failed/ })).toHaveAttribute("aria-pressed", "true")
    expect(rows()).toHaveLength(1)
  })

  it("lists every package as name@version with its state word and an icon", () => {
    const list = [pkg("a", "published"), pkg("b", "present", { note: "Nexus already holds these bytes" }), pkg("c", "pending"), pkg("d", "failed", { kind: "nexus", reason: "Nexus answered 500" })]
    render(<ReportList attempt={attempt(list)} />)
    fireEvent.click(screen.getByRole("button", { name: /^All/ }))
    expect(rows()).toHaveLength(4)
    const text = rows().map((r) => r.textContent)
    expect(text[0]).toContain("a@1.0.0")
    expect(text[0]).toContain("Published")
    expect(text[1]).toContain("Present")
    expect(text[2]).toContain("Pending")
    expect(text[3]).toContain("Failed")
    for (const r of rows()) expect(r.querySelector("svg")).not.toBeNull()
  })

  it("shows a present package's note", () => {
    render(<ReportList attempt={attempt([pkg("b", "present", { note: "Nexus already holds these bytes" })])} />)
    expect(screen.getByText("Nexus already holds these bytes")).toBeInTheDocument()
  })

  it("shows a failed package's reason and its next action", () => {
    render(<ReportList attempt={attempt([pkg("d", "failed", { kind: "conflict", reason: "Nexus holds d@1.0.0 with other bytes" })])} />)
    expect(screen.getByText("Nexus holds d@1.0.0 with other bytes")).toBeInTheDocument()
    expect(screen.getByText(/delete it in Nexus, then retry/)).toBeInTheDocument()
  })

  it("no kind: gives the general next action", () => {
    render(<ReportList attempt={attempt([pkg("d", "failed", { reason: "connection refused" })])} />)
    expect(screen.getByText("Read the reason: it names what failed. Fix that, then retry.")).toBeInTheDocument()
  })

  it("counts packages not finished apart from failures, and keeps them in Failed", () => {
    const list = [pkg("a", "published"), pkg("b", "failed", { kind: "nexus", reason: "x" }), pkg("c", "failed", { kind: "interrupted", reason: "interrupted" }), pkg("d", "failed", { reason: "not reached" })]
    render(<ReportList attempt={attempt(list)} />)
    expect(screen.getByText("2 not finished")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Failed 3" })).toHaveAttribute("aria-pressed", "true")
    expect(rows()).toHaveLength(3)
    expect(rows().filter((r) => r.textContent?.includes("Not finished"))).toHaveLength(2)
    expect(rows().filter((r) => r.textContent?.includes("Failed"))).toHaveLength(1)
  })

  it("opens on Failed when a package failed", () => {
    render(<ReportList attempt={attempt([pkg("a", "published"), pkg("b", "failed", { kind: "nexus", reason: "x" })])} />)
    expect(screen.getByRole("button", { name: "Failed 1" })).toHaveAttribute("aria-pressed", "true")
    expect(rows()).toHaveLength(1)
  })

  it("opens on All otherwise", () => {
    render(<ReportList attempt={attempt([pkg("a", "published"), pkg("b", "present")])} />)
    expect(screen.getByRole("button", { name: "All 2" })).toHaveAttribute("aria-pressed", "true")
    expect(rows()).toHaveLength(2)
  })

  it("a refetch keeps the user's choice", () => {
    const first = attempt([pkg("a", "published"), pkg("b", "failed", { kind: "nexus", reason: "x" })])
    const { rerender } = render(<ReportList attempt={first} />)
    fireEvent.click(screen.getByRole("button", { name: /^All/ }))
    rerender(<ReportList attempt={attempt([pkg("a", "published"), pkg("b", "failed", { kind: "nexus", reason: "x" }), pkg("c", "pending")])} />)
    expect(screen.getByRole("button", { name: "All 3" })).toHaveAttribute("aria-pressed", "true")
    expect(rows()).toHaveLength(3)
  })

  it("shows the first 100 rows, then Show <n> more", () => {
    const list = Array.from({ length: 130 }, (_, i) => pkg(`p${String(i).padStart(3, "0")}`, "published"))
    render(<ReportList attempt={attempt(list)} />)
    expect(rows()).toHaveLength(100)
    fireEvent.click(screen.getByRole("button", { name: "Show 30 more" }))
    expect(rows()).toHaveLength(130)
    expect(screen.queryByRole("button", { name: /Show \d+ more/ })).toBeNull()
  })

  it("says so when no package is listed", () => {
    render(<ReportList attempt={attempt([])} />)
    expect(screen.getByText("No package is listed for this attempt.")).toBeInTheDocument()
  })

  describe("a long reason", () => {
    const reason = "nexus said no ".repeat(70).slice(0, 1000).trim()
    const list = [pkg("d", "failed", { kind: "nexus", reason })]

    function overflow(on: boolean) {
      vi.spyOn(HTMLElement.prototype, "scrollHeight", "get").mockReturnValue(on ? 120 : 30)
      vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(40)
    }

    it("is cut at two lines, with Show full reason, when it overflows", () => {
      overflow(true)
      render(<ReportList attempt={attempt(list)} />)
      expect(screen.getByText(reason).className).toContain("line-clamp-2")
      expect(screen.getByRole("button", { name: "Show full reason of d@1.0.0" })).toHaveAttribute("aria-expanded", "false")
    })

    it("offers no button when the reason fits in two lines", () => {
      overflow(false)
      render(<ReportList attempt={attempt(list)} />)
      expect(screen.queryByRole("button", { name: /Show full reason/ })).toBeNull()
    })

    it("opens the whole text in a focusable scrolling area with a copy control", () => {
      overflow(true)
      render(<ReportList attempt={attempt(list)} />)
      fireEvent.click(screen.getByRole("button", { name: "Show full reason of d@1.0.0" }))
      const area = screen.getByRole("region", { name: "Full reason of d@1.0.0" })
      expect(area).toHaveTextContent(reason)
      expect(area).toHaveAttribute("tabindex", "0")
      expect(area.className).toContain("overflow-auto")
      expect(screen.getByRole("button", { name: "Copy reason of d@1.0.0" })).toBeInTheDocument()
      expect(screen.getByRole("button", { name: "Hide full reason of d@1.0.0" })).toHaveAttribute("aria-expanded", "true")
    })
  })
})
