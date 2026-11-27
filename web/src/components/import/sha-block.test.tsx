import { fireEvent, render, screen, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { Checks } from "./sha-block"

const KEY = "7d3f0a9c" + "1".repeat(48) + "0f3b6a92"
const ARCHIVE = "fca8560dd0d96461064dad07a7f18269aff31847b39febe7df471bbd16b4861a"

function renderChecks() {
  render(<Checks publicKeySha256={KEY} archiveSha256={ARCHIVE} packages={{ checked: 1284, total: 1284 }} />)
  fireEvent.click(screen.getByRole("button", { name: "Compare" }))
  return screen.getByRole("textbox", { name: "Compare with the connected side" })
}

describe("Checks", () => {
  it("names the three checks with the value each rests on", () => {
    render(<Checks publicKeySha256={KEY} archiveSha256={ARCHIVE} packages={{ checked: 1284, total: 1284 }} />)
    expect(screen.getByText("3 passed", { exact: false })).toBeInTheDocument()
    expect(screen.getByText("the key trusted here")).toBeInTheDocument()
    expect(screen.getByText("sha256 in the manifest")).toBeInTheDocument()
    expect(screen.getByText("1,284 of 1,284")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^signing key's sha256/ })).toHaveTextContent("7d3f0a9c")
    expect(screen.getByRole("button", { name: /^archive's sha256/ })).toHaveTextContent("16b4861a")
    expect(screen.queryByRole("textbox")).toBeNull()
  })

  it("says Not recorded for the key of a report that never kept it", () => {
    render(<Checks archiveSha256={ARCHIVE} packages={{ checked: 3, total: 3 }} />)
    expect(screen.getByText("Not recorded")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /^signing key's sha256/ })).toBeNull()
  })

  it("matches either fingerprint in one Compare", () => {
    const field = renderChecks()
    expect(screen.getAllByRole("button", { name: "Compare" })).toHaveLength(1)
    fireEvent.change(field, { target: { value: `sha256:${ARCHIVE.toUpperCase()}` } })
    expect(screen.getByRole("status")).toHaveTextContent("Matches the archive's sha256")
    expect(screen.getByRole("button", { name: /^archive's sha256/ }).closest("[data-matched]")).not.toBeNull()
    fireEvent.change(field, { target: { value: KEY } })
    expect(screen.getByRole("status")).toHaveTextContent("Matches the signing key's sha256")
    expect(screen.getByRole("button", { name: /^signing key's sha256/ }).closest("[data-matched]")).not.toBeNull()
    expect(screen.getByRole("button", { name: /^archive's sha256/ }).closest("[data-matched]")).toBeNull()
  })

  it("marks the characters that differ", () => {
    const field = renderChecks()
    const pasted = ARCHIVE.slice(0, 28) + "a" + ARCHIVE.slice(29)
    fireEvent.change(field, { target: { value: pasted } })
    expect(screen.getByRole("status")).toHaveTextContent("Does not match: 1 character differs, at position 29")
    const groups = screen.getByTestId("pasted-groups")
    expect(within(groups).getAllByText("a", { selector: "mark" })).toHaveLength(1)
    expect(document.querySelectorAll("[data-matched]")).toHaveLength(0)
  })

  it("explains the checks one press away with no link", () => {
    render(<Checks publicKeySha256={KEY} archiveSha256={ARCHIVE} packages={{ checked: 1, total: 1 }} />)
    const info = screen.getByRole("button", { name: "What these checks mean" })
    expect(info).toHaveAttribute("aria-expanded", "false")
    fireEvent.click(info)
    expect(info).toHaveAttribute("aria-expanded", "true")
    const terms = screen.getAllByRole("term").map((t) => t.textContent)
    expect(terms).toEqual(["Signature", "sha256", "sha512"])
    expect(screen.getAllByRole("definition").map((d) => d.textContent)).toEqual([
      "The connected side signed the manifest. This side checked it with the key its administrators trust.",
      "A fingerprint of the file. One changed byte gives another one.",
      "Each package's own fingerprint, listed in the manifest.",
    ])
    expect(screen.queryByRole("link")).toBeNull()
    fireEvent.keyDown(info, { key: "Escape" })
    expect(info).toHaveAttribute("aria-expanded", "false")
    expect(info).toHaveFocus()
  })
})
