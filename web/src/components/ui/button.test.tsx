import { render, screen } from "@testing-library/react"
import { X } from "lucide-react"
import { describe, expect, it } from "vitest"

import { Button } from "./button"

const classes = (element: HTMLElement) => element.className.split(/\s+/)

describe("button", () => {
  it("draws a tinted button with fill, border and its icon", () => {
    render(
      <Button variant="tinted">
        <X aria-hidden="true" />
        Cancel
      </Button>,
    )
    const button = screen.getByRole("button", { name: "Cancel" })
    expect(classes(button)).toEqual(expect.arrayContaining(["bg-hover", "border", "border-rule-2", "text-ink"]))
    expect(classes(button)).not.toContain("border-transparent")
    expect(button.querySelector("svg")).not.toBeNull()
    expect(button.className).toMatch(/\[&_svg\]:size-4/)
  })

  it("draws the primary in the ink with the page colour as its label", () => {
    render(<Button>Analyse</Button>)
    expect(classes(screen.getByRole("button", { name: "Analyse" }))).toEqual(expect.arrayContaining(["bg-ink", "text-bg"]))
  })

  it("gives page, default, small and icon sizes of 40, 36, 32 and 32 px", () => {
    render(
      <>
        <Button size="page">page</Button>
        <Button>default</Button>
        <Button size="sm">small</Button>
        <Button size="icon" aria-label="icon" />
      </>,
    )
    expect(classes(screen.getByRole("button", { name: "page" }))).toContain("h-10")
    expect(classes(screen.getByRole("button", { name: "default" }))).toContain("h-9")
    expect(classes(screen.getByRole("button", { name: "small" }))).toContain("h-8")
    expect(classes(screen.getByRole("button", { name: "icon" }))).toContain("size-8")
  })

  it("presses with a scale only while motion is allowed", () => {
    render(<Button>Seal</Button>)
    const button = screen.getByRole("button", { name: "Seal" })
    expect(classes(button)).toContain("motion-safe:active:scale-[0.97]")
    expect(button.className).not.toMatch(/(^|\s)active:scale/)
  })
})
