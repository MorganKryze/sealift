import { render } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { Mark } from "@/components/brand/Mark"

describe("Mark", () => {
  it("renders the full variant at a 40x40 viewBox", () => {
    const { container } = render(<Mark variant="full" />)
    expect(container.querySelector("svg")).toHaveAttribute("viewBox", "0 0 40 40")
  })

  it("renders the compact variant at a 40x40 viewBox", () => {
    const { container } = render(<Mark variant="compact" />)
    expect(container.querySelector("svg")).toHaveAttribute("viewBox", "0 0 40 40")
  })

  it("renders the pixel variant at a 16x16 viewBox", () => {
    const { container } = render(<Mark variant="pixel" />)
    expect(container.querySelector("svg")).toHaveAttribute("viewBox", "0 0 16 16")
  })
})
