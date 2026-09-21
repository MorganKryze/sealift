import { fireEvent, render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { AnalysisResult } from "@/api/projects"
import { AnalysisResults } from "@/components/projects/analysis-results"

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" }

function makeResult(after: number[] | null): AnalysisResult {
  return {
    target,
    before: [1, 1, 0, 0, 0],
    after,
    warnings: [],
    dependencies: [
      {
        name: "left-pad",
        current: "1.0.0",
        best: "1.3.0",
        vector: [1, 0, 0, 0, 0],
        candidates: [
          {
            version: "1.3.0",
            vector: [0, 0, 0, 0, 0],
            signals: [{ name: "patch", evidence: "patch release", blocking: false }],
            key: true,
            resolved: true,
          },
          {
            version: "2.0.0",
            vector: [0, 0, 0, 0, 0],
            signals: [{ name: "breaking", evidence: "major version bump, likely breaking", blocking: true }],
            key: false,
            resolved: true,
          },
        ],
      },
      {
        name: "chalk",
        current: "2.0.0",
        vector: [0, 1, 0, 0, 0],
        candidates: [
          {
            version: "3.0.0",
            vector: [0, 0, 0, 0, 0],
            signals: [{ name: "breaking", evidence: "major bump, drops CommonJS", blocking: true }],
            key: false,
            resolved: true,
          },
        ],
      },
    ],
  }
}

describe("AnalysisResults", () => {
  it("preselects the best candidate for the focused dependency", () => {
    render(<AnalysisResults analysisId="a-preselect" result={makeResult([0, 0, 0, 0, 0])} />)

    expect(screen.getByLabelText("1.3.0")).toBeChecked()
    expect(screen.getByLabelText("2.0.0")).not.toBeChecked()
  })

  it("refuses to tick a blocked candidate and explains why", () => {
    render(<AnalysisResults analysisId="a-blocked" result={makeResult([0, 0, 0, 0, 0])} />)

    const blocked = screen.getByLabelText("2.0.0")
    expect(blocked).toBeDisabled()
    expect(blocked).not.toBeChecked()
    expect(screen.getAllByText(/major version bump, likely breaking/).length).toBeGreaterThan(0)
  })

  it("moves the focused dependency with the arrow keys", () => {
    render(<AnalysisResults analysisId="a-arrows" result={makeResult([0, 0, 0, 0, 0])} />)

    expect(screen.getByRole("heading", { name: "left-pad" })).toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole("listbox"), { key: "ArrowDown" })
    expect(screen.getByRole("heading", { name: "chalk" })).toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole("listbox"), { key: "ArrowUp" })
    expect(screen.getByRole("heading", { name: "left-pad" })).toBeInTheDocument()
  })

  it("says the combined check was not measured instead of showing zeros", () => {
    render(<AnalysisResults analysisId="a-null" result={makeResult(null)} />)

    expect(screen.getByText(/not measured/i)).toBeInTheDocument()
  })
})
