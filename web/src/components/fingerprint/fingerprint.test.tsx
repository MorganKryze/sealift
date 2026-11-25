import { fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { compareFingerprint, Fingerprint, FingerprintCompare, normalizeFingerprint } from "@/components/fingerprint/fingerprint"

const HASH = "3f9a1c7e0b2d4f6a8c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5a"
const GROUPS = ["3f9a1c7e", "0b2d4f6a", "8c1e3b5d", "7f9a2c4e", "6b8d0f1a", "3c5e7b9d", "2f4a6c8e", "0b1d3f5a"]
// Character 41 (1-based) changed from 3 to 8.
const DIFFERENT = HASH.slice(0, 40) + "8" + HASH.slice(41)

afterEach(() => vi.restoreAllMocks())

describe("Fingerprint", () => {
  it("shows the first 8, an ellipsis and the last 8, named first to last", () => {
    render(<Fingerprint value={HASH} label="Public key sha256" />)
    const button = screen.getByRole("button", { name: "Public key sha256 3f9a1c7e to 0b1d3f5a" })
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(within(button).getByText("…")).toHaveAttribute("aria-hidden", "true")
    expect(within(button).getByText("3f9a1c7e")).toHaveClass("font-semibold")
    expect(within(button).getByText("0b1d3f5a")).toHaveClass("font-semibold")
    expect(button.className).toMatch(/\bborder\b/)
  })

  it("takes its name from what it holds, with no aria-label", () => {
    render(<Fingerprint value={HASH} label="Public key sha256" />)
    const button = screen.getByRole("button", { name: /^Public key sha256/ })
    expect(button).not.toHaveAttribute("aria-label")
    expect(within(button).getByText("Public key sha256")).toHaveClass("sr-only")
    expect(within(button).getByText("to")).toHaveClass("sr-only")
    fireEvent.click(button)
    expect(button).not.toHaveAttribute("aria-label")
    expect(button).toHaveAccessibleName("Public key sha256 3f9a1c7e to 0b1d3f5a")
  })

  it("opens in place to groups of 8 with aria-expanded and closes on a second press", () => {
    render(<Fingerprint value={HASH} label="Public key sha256" />)
    const button = screen.getByRole("button", { name: /^Public key sha256/ })
    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "true")
    expect(within(button).getAllByText(/^[0-9a-f]{8}$/).map((g) => g.textContent)).toEqual(GROUPS)
    expect(button).not.toHaveTextContent("…")
    expect(button).toHaveAccessibleName("Public key sha256 3f9a1c7e to 0b1d3f5a")
    // Whole groups wrap: each group is one unbreakable piece.
    for (const group of within(button).getAllByText(/^[0-9a-f]{8}$/)) expect(group).toHaveClass("whitespace-nowrap")
    expect(screen.getAllByRole("button", { name: /^Public key sha256/ })).toHaveLength(1)

    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(within(button).getByText("…")).toHaveAttribute("aria-hidden", "true")
    // The name stays put while only aria-expanded changes, and it holds the closed text, so speech input finds the button by what it shows.
    expect(button).toHaveAccessibleName("Public key sha256 3f9a1c7e to 0b1d3f5a")
  })

  it("copies with an icon button beside it, so the open value keeps the width", () => {
    render(<Fingerprint value={HASH} label="Public key sha256" />)
    expect(screen.getByRole("button", { name: "Copy Public key sha256" })).toHaveTextContent(/^Copy Public key sha256$/)
  })

  it("copies all 64 characters open or closed", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true })
    render(<Fingerprint value={HASH} label="Public key sha256" />)
    fireEvent.click(screen.getByRole("button", { name: "Copy Public key sha256" }))
    await screen.findByText("Copied")
    fireEvent.click(screen.getByRole("button", { name: /^Public key sha256/ }))
    fireEvent.click(screen.getByRole("button", { name: "Copy Public key sha256" }))
    expect(writeText.mock.calls).toEqual([[HASH], [HASH]])
  })
})

describe("normalizeFingerprint", () => {
  it("reads a pasted value without prefix, colons, spaces or case", () => {
    const colons = HASH.toUpperCase().match(/../g)?.join(":") ?? ""
    expect(normalizeFingerprint(`sha256:${colons}`)).toBe(HASH)
    expect(normalizeFingerprint(`SHA256: ${GROUPS.join(" ")}\n`)).toBe(HASH)
    expect(normalizeFingerprint("  ")).toBe("")
  })
})

describe("compareFingerprint", () => {
  it("reads match only from 64 equal characters", () => {
    expect(compareFingerprint(HASH, "")).toEqual({ state: "empty", typed: 0, differs: [] })
    expect(compareFingerprint(HASH, HASH.slice(0, 24))).toEqual({ state: "partial", typed: 24, differs: [] })
    expect(compareFingerprint(HASH, HASH.slice(0, 63))).toEqual({ state: "partial", typed: 63, differs: [] })
    expect(compareFingerprint(HASH, HASH)).toEqual({ state: "match", typed: 64, differs: [] })
    expect(compareFingerprint(HASH, HASH + "0")).toEqual({ state: "differs", typed: 65, differs: [64] })
  })

  it("finds every differing character, wherever it sits", () => {
    expect(compareFingerprint(HASH, DIFFERENT)).toEqual({ state: "differs", typed: 64, differs: [40] })
    expect(compareFingerprint(HASH, DIFFERENT.slice(0, 45)).differs).toEqual([40])
    const many = "x" + HASH.slice(1, 10) + "y" + HASH.slice(11)
    expect(compareFingerprint(HASH, many).differs).toEqual([0, 10])
  })
})

function paste(value: string) {
  fireEvent.change(screen.getByRole("textbox", { name: "sha256 from the connected side" }), { target: { value } })
}

describe("FingerprintCompare", () => {
  it("shows nothing for an empty field", () => {
    const { container } = render(<FingerprintCompare trusted={HASH} open />)
    expect(screen.getByRole("textbox", { name: "sha256 from the connected side" })).toHaveValue("")
    expect(screen.getByRole("status")).toBeEmptyDOMElement()
    expect(screen.queryByText(/of 64/)).not.toBeInTheDocument()
    expect(container.querySelector("svg.lucide-circle-check, svg.lucide-circle-x")).toBeNull()
  })

  it("draws nothing while closed", () => {
    const { container } = render(<FingerprintCompare trusted={HASH} open={false} />)
    expect(container).toBeEmptyDOMElement()
  })

  it("shows only a muted count while the paste matches so far", () => {
    const { container } = render(<FingerprintCompare trusted={HASH} open />)
    paste(HASH.slice(0, 24))
    expect(screen.getByText("24 of 64")).toHaveClass("text-muted")
    expect(container.querySelector("svg.lucide-circle-check, svg.lucide-circle-x, mark")).toBeNull()
    expect(screen.getByRole("status")).toBeEmptyDOMElement()

    paste(HASH.slice(0, 63))
    expect(screen.getByText("63 of 64")).toBeInTheDocument()
    expect(container.querySelector("svg.lucide-circle-check")).toBeNull()
    const field = screen.getByRole("textbox")
    expect(field.className).not.toMatch(/border-(ok|bad)/)
  })

  it("shows a green check and a green border on a full match and says so in words", () => {
    const { container } = render(<FingerprintCompare trusted={HASH} open />)
    paste(`sha256:${HASH.toUpperCase()}`)
    expect(container.querySelector("svg.lucide-circle-check")).toHaveClass("text-ok")
    expect(screen.getByRole("textbox")).toHaveClass("border-ok")
    expect(screen.getByRole("status")).toHaveTextContent("Matches the trusted key")
    expect(screen.queryByText(/of 64/)).not.toBeInTheDocument()
  })

  it("shows a red cross and marks each differing character, even before the 64th", () => {
    const { container } = render(<FingerprintCompare trusted={HASH} open />)
    paste(DIFFERENT.slice(0, 45))
    expect(container.querySelector("svg.lucide-circle-x")).toHaveClass("text-bad")
    expect(screen.getByRole("textbox")).toHaveClass("border-bad")
    const marks = [...container.querySelectorAll("mark")]
    expect(marks.map((m) => m.textContent)).toEqual(["3", "8"])
    for (const m of marks) expect(m).toHaveClass("text-bad")
    // Both values in groups of 8.
    expect(screen.getByTestId("trusted-groups").textContent?.replace(/\s/g, "")).toBe(HASH)
    expect(screen.getByTestId("pasted-groups").textContent?.replace(/\s/g, "")).toBe(DIFFERENT.slice(0, 45))
  })

  it("says the first differing position and the count in words", () => {
    render(<FingerprintCompare trusted={HASH} open />)
    paste(DIFFERENT)
    expect(screen.getByRole("status")).toHaveTextContent("Does not match: 1 character differs, at position 41")
    paste("x" + HASH.slice(1, 10) + "y" + HASH.slice(11))
    expect(screen.getByRole("status")).toHaveTextContent("Does not match: 2 characters differ, the first at position 1")
  })

  it("carries no Match or No match word", () => {
    const { container } = render(<FingerprintCompare trusted={HASH} open />)
    for (const value of ["", HASH.slice(0, 10), HASH, DIFFERENT]) {
      paste(value)
      expect(container.textContent).not.toMatch(/\bMatch\b|\bNo match\b|\bMismatch\b/)
    }
  })

  it("sends no request", () => {
    const fetch = vi.spyOn(globalThis, "fetch")
    const open = vi.spyOn(XMLHttpRequest.prototype, "open")
    render(<FingerprintCompare trusted={HASH} open />)
    for (const value of [HASH.slice(0, 10), HASH, DIFFERENT]) paste(value)
    expect(fetch).not.toHaveBeenCalled()
    expect(open).not.toHaveBeenCalled()
  })
})
