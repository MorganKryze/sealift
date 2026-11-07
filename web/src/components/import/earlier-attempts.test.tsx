import { fireEvent, render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { Attempt, ReportPackage } from "@/import/lib/outcome"

import { EarlierAttempts } from "./earlier-attempts"

const pkg = (name: string, state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name, version: "1.0.0", file: "x", state, reason: "", note: "", ...over,
})

function attempt(n: number, outcome: string, packages: ReportPackage[], endedAt?: string): Attempt {
  return {
    n, status: "ended", outcome, endedAt,
    report: {
      outcome, reason: "", unencrypted: false, importVersion: "", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages,
    },
  }
}

const earlier = [attempt(1, "incomplete", [pkg("a", "published"), pkg("b", "present"), pkg("c", "failed", { kind: "nexus", reason: "Nexus answered 503" })], "2026-11-05T09:20:00Z")]

describe("earlier attempts", () => {
  it("renders nothing without an earlier attempt", () => {
    const { container } = render(<EarlierAttempts attempts={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it("is folded, with the count in its button", () => {
    render(<EarlierAttempts attempts={earlier} />)
    expect(screen.getByRole("button", { name: "Earlier attempts (1)" })).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByRole("list", { name: "Earlier attempts" })).toBeNull()
  })

  it("lists each attempt with its outcome, counts and end time once opened", () => {
    render(<EarlierAttempts attempts={earlier} />)
    fireEvent.click(screen.getByRole("button", { name: "Earlier attempts (1)" }))
    const item = screen.getByRole("list", { name: "Earlier attempts" }).querySelector("li") as HTMLElement
    expect(item).toHaveTextContent("Attempt 1")
    expect(item).toHaveTextContent("Incomplete")
    expect(item).toHaveTextContent("1 published")
    expect(item).toHaveTextContent("1 present")
    expect(item).toHaveTextContent("1 failed")
    expect(item).toHaveTextContent(/Ended .*\d/)
  })

  it("says Not recorded for an end time that was never written", () => {
    render(<EarlierAttempts attempts={[attempt(1, "interrupted", [])]} />)
    fireEvent.click(screen.getByRole("button", { name: "Earlier attempts (1)" }))
    expect(screen.getByText("Ended: Not recorded")).toBeInTheDocument()
  })

  it("shows an attempt's report on demand", () => {
    render(<EarlierAttempts attempts={earlier} />)
    fireEvent.click(screen.getByRole("button", { name: "Earlier attempts (1)" }))
    expect(screen.queryByText("Nexus answered 503")).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Show report of attempt 1" }))
    expect(screen.getByRole("region", { name: "Report of attempt 1" })).toHaveTextContent("Nexus answered 503")
    fireEvent.click(screen.getByRole("button", { name: "Hide report of attempt 1" }))
    expect(screen.queryByText("Nexus answered 503")).toBeNull()
  })
})
