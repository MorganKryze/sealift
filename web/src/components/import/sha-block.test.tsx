import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ShaBlock } from "./sha-block"

const manifest = "a".repeat(64)
const expected = "b".repeat(64)

describe("sha block", () => {
  it("shows both digests in full, each with a copy control", () => {
    render(<ShaBlock expected={expected} manifest={manifest} checked={true} status="ended" />)
    expect(screen.getByText(manifest)).toBeInTheDocument()
    expect(screen.getByText(expected)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Copy manifest sha256" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Copy expected sha256" })).toBeInTheDocument()
  })

  it("says matched only when the attempt records that the archive passed its checks", () => {
    render(<ShaBlock expected="" manifest={manifest} checked={true} status="ended" />)
    expect(screen.getByText(/The archive matched/)).toBeInTheDocument()
  })

  it("never says matched when the checks did not pass", () => {
    render(<ShaBlock expected={expected} manifest={manifest} checked={false} status="ended" />)
    expect(screen.queryByText(/matched/i)).toBeNull()
    expect(screen.getByText("The archive has not passed its checks.")).toBeInTheDocument()
  })

  it("never says matched for an ended attempt that has no mark, and names no version", () => {
    render(<ShaBlock expected={expected} manifest={manifest} checked={undefined} status="ended" />)
    expect(screen.queryByText(/matched/i)).toBeNull()
    expect(screen.getByText("Not recorded: this attempt did not record the archive's checks.")).toBeInTheDocument()
    expect(screen.queryByText(/sealift/i)).toBeNull()
  })

  it.each(["queued", "running"])("says the checks have not run yet for a %s attempt that has no mark", (status) => {
    render(<ShaBlock expected="" manifest="" checked={undefined} status={status} />)
    expect(screen.queryByText(/matched/i)).toBeNull()
    expect(screen.queryByText(/Not recorded/)).toBeNull()
    expect(screen.getByText("The archive's checks have not run yet.")).toBeInTheDocument()
  })

  it("says so when no expected sha256 was given and when the manifest was never read", () => {
    render(<ShaBlock expected="" manifest="" checked={false} status="ended" />)
    expect(screen.getByText("No expected sha256 was given.")).toBeInTheDocument()
    expect(screen.getByText("Not read")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Copy/ })).toBeNull()
  })
})
