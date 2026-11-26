import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { StepBar, stepBarStep } from "./step-bar"

describe("StepBar", () => {
  it("draws the running step on screen in the info colour, not ink", () => {
    render(<StepBar steps={[stepBarStep("drop", "done", false), stepBarStep("analysis", "running", true)]} />)
    const circle = screen.getByText("2")
    expect(circle.className).toContain("border-info")
    expect(circle.className).not.toContain("bg-ink")
  })
})
