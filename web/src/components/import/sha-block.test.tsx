import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ShaBlock } from "./sha-block"

const manifest = "a".repeat(64)
const expected = "b".repeat(64)

describe("sha block", () => {
  it("shows both digests in full, each with a copy control", () => {
    render(<ShaBlock expected={expected} manifest={manifest} checked={true} />)
    expect(screen.getByText(manifest)).toBeInTheDocument()
    expect(screen.getByText(expected)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Copy manifest sha256" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Copy expected sha256" })).toBeInTheDocument()
  })

  it("says matched only when the attempt records that the archive passed its checks", () => {
    render(<ShaBlock expected="" manifest={manifest} checked={true} />)
    expect(screen.getByText(/The archive matched/)).toBeInTheDocument()
  })

  it("never says matched when the checks did not pass", () => {
    render(<ShaBlock expected={expected} manifest={manifest} checked={false} />)
    expect(screen.queryByText(/matched/i)).toBeNull()
    expect(screen.getByText("The archive has not passed its checks.")).toBeInTheDocument()
  })

  it("never says matched for a record that has no mark, and says Not recorded", () => {
    render(<ShaBlock expected={expected} manifest={manifest} checked={undefined} />)
    expect(screen.queryByText(/matched/i)).toBeNull()
    expect(screen.getByText(/^Not recorded/)).toBeInTheDocument()
  })

  it("says so when no expected sha256 was given and when the manifest was never read", () => {
    render(<ShaBlock expected="" manifest="" checked={false} />)
    expect(screen.getByText("No expected sha256 was given.")).toBeInTheDocument()
    expect(screen.getByText("Not read")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Copy/ })).toBeNull()
  })
})
