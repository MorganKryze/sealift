import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { Attempt, ReportPackage } from "@/import/lib/outcome"

import { AttemptProgress } from "./progress"

const pkg = (state: string): ReportPackage => ({ name: "left-pad", version: "1.3.0", file: "x", state, reason: "", note: "" })

function attempt(status: string, packages: ReportPackage[], over: Partial<Attempt> = {}, checked?: boolean): Attempt {
  return {
    n: 1, status, outcome: "",
    report: {
      outcome: "", reason: "", unencrypted: false, importVersion: "", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages, archiveChecked: checked,
    },
    ...over,
  }
}

describe("attempt progress", () => {
  it("says a queued attempt waits its turn, in the one status region", () => {
    render(<AttemptProgress attempt={attempt("queued", [])} />)
    const region = screen.getByRole("status")
    expect(region).toHaveTextContent("Waiting its turn")
    expect(region).toHaveTextContent("One import runs at a time for every user of the service, in the order they were started.")
    expect(screen.getAllByRole("status")).toHaveLength(1)
  })

  it("says Reading the manifest while no package is listed", () => {
    render(<AttemptProgress attempt={attempt("running", [])} />)
    expect(screen.getByRole("status")).toHaveTextContent("Reading the manifest")
  })

  it("says Checking the archive, with no byte progress", () => {
    render(<AttemptProgress attempt={attempt("running", [pkg("pending")], {}, false)} />)
    const region = screen.getByRole("status")
    expect(region).toHaveTextContent("Checking the archive")
    expect(region).toHaveTextContent("no byte progress")
    expect(screen.queryByRole("progressbar")).toBeNull()
  })

  it("publishing shows done of total with published, present, failed and pending", () => {
    const packages = [pkg("published"), pkg("published"), pkg("present"), pkg("failed"), pkg("pending"), pkg("pending"), pkg("pending")]
    render(<AttemptProgress attempt={attempt("running", packages, {}, true)} />)
    const region = screen.getByRole("status")
    expect(region).toHaveTextContent("Publishing packages: 4 of 7")
    expect(region).toHaveTextContent("2 published")
    expect(region).toHaveTextContent("1 present")
    expect(region).toHaveTextContent("1 failed")
    expect(region).toHaveTextContent("3 pending")
    expect(screen.getByRole("progressbar", { name: "Packages done" })).toHaveAttribute("aria-valuenow", "57")
  })

  it("says an ended attempt ended, with its counts", () => {
    const packages = [pkg("published"), pkg("failed")]
    render(<AttemptProgress attempt={attempt("ended", packages, { n: 3, outcome: "incomplete" }, true)} />)
    const region = screen.getByRole("status")
    expect(region).toHaveTextContent("Attempt 3 ended: Incomplete")
    expect(region).toHaveTextContent("1 published")
    expect(region).toHaveTextContent("1 failed")
  })

  it("keeps the same region node across three refetches of one attempt", () => {
    const first = attempt("running", [pkg("published"), pkg("pending")], {}, true)
    const { rerender } = render(<AttemptProgress attempt={first} />)
    const region = screen.getByRole("status")
    const bar = screen.getByRole("progressbar")
    for (const published of [1, 2, 3]) {
      const packages = [...Array.from({ length: published }, () => pkg("published")), pkg("pending")]
      rerender(<AttemptProgress attempt={attempt("running", packages, {}, true)} />)
      expect(screen.getByRole("status")).toBe(region)
      expect(screen.getByRole("progressbar")).toBe(bar)
    }
    expect(region).toHaveTextContent("Publishing packages: 3 of 4")
  })

  it("remounts the region when the attempt number changes", () => {
    const { rerender } = render(<AttemptProgress attempt={attempt("running", [], { n: 1 })} />)
    const region = screen.getByRole("status")
    rerender(<AttemptProgress attempt={attempt("queued", [], { n: 2 })} />)
    expect(screen.getByRole("status")).not.toBe(region)
    expect(screen.getByRole("status")).toHaveTextContent("Waiting its turn")
  })
})
