import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { AnalysisWarnings } from "./analysis-warnings"

describe("AnalysisWarnings", () => {
  it("names each warning", () => {
    render(<AnalysisWarnings warnings={["lodash: metadata unreachable: 503", "express: conflict"]} />)
    expect(screen.getByRole("region", { name: "Analysis warnings" })).toBeInTheDocument()
    expect(screen.getByText("lodash: metadata unreachable: 503")).toBeInTheDocument()
    expect(screen.getByText("express: conflict")).toBeInTheDocument()
  })

  it("renders nothing without a warning", () => {
    const { container } = render(<AnalysisWarnings warnings={[]} />)
    expect(container).toBeEmptyDOMElement()
  })
})
