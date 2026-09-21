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
    render(<AnalysisResults analysisId="a-preselect" result={makeResult([0, 0, 0, 0, 0])} onContinue={() => {}} />)

    expect(screen.getByLabelText("1.3.0")).toBeChecked()
    expect(screen.getByLabelText("2.0.0")).not.toBeChecked()
  })

  it("refuses to tick a blocked candidate and explains why", () => {
    render(<AnalysisResults analysisId="a-blocked" result={makeResult([0, 0, 0, 0, 0])} onContinue={() => {}} />)

    const blocked = screen.getByLabelText("2.0.0")
    expect(blocked).toBeDisabled()
    expect(blocked).not.toBeChecked()
    expect(screen.getAllByText(/major version bump, likely breaking/).length).toBeGreaterThan(0)
  })

  it("moves the focused dependency with the arrow keys", () => {
    render(<AnalysisResults analysisId="a-arrows" result={makeResult([0, 0, 0, 0, 0])} onContinue={() => {}} />)

    expect(screen.getByRole("heading", { name: "left-pad" })).toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole("listbox"), { key: "ArrowDown" })
    expect(screen.getByRole("heading", { name: "chalk" })).toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole("listbox"), { key: "ArrowUp" })
    expect(screen.getByRole("heading", { name: "left-pad" })).toBeInTheDocument()
  })

  it("points aria-activedescendant at the focused option's own id, with no focusable button inside it", () => {
    render(<AnalysisResults analysisId="a-active" result={makeResult([0, 0, 0, 0, 0])} onContinue={() => {}} />)

    const listbox = screen.getByRole("listbox")
    const options = screen.getAllByRole("option")
    expect(options).toHaveLength(2)
    expect(options.map((option) => option.tagName)).toEqual(["LI", "LI"])
    expect(listbox).toHaveAttribute("aria-activedescendant", options[0]!.id)
    for (const option of options) {
      expect(option.querySelector("button")).toBeNull()
    }

    fireEvent.keyDown(listbox, { key: "ArrowDown" })
    expect(listbox).toHaveAttribute("aria-activedescendant", options[1]!.id)
  })

  it("says the combined check was not measured instead of showing zeros", () => {
    render(<AnalysisResults analysisId="a-null" result={makeResult(null)} onContinue={() => {}} />)

    expect(screen.getByText(/not measured/i)).toBeInTheDocument()
  })

  it("shows the recorded tool versions under the totals", () => {
    render(
      <AnalysisResults
        analysisId="a-tools"
        result={makeResult([0, 0, 0, 0, 0])}
        trivyVersion="0.72.0"
        trivyDbDate="2026-09-09T00:00:00Z"
        pnpmVersion="10.34.5"
        onContinue={() => {}}
      />,
    )

    expect(screen.getByText(/^Trivy 0\.72\.0 · DB (?!unknown).+ · pnpm 10\.34\.5$/)).toBeInTheDocument()
  })

  it("shows unknown for a tool version the analysis did not record", () => {
    render(<AnalysisResults analysisId="a-no-tools" result={makeResult([0, 0, 0, 0, 0])} onContinue={() => {}} />)

    expect(screen.getByText(/Trivy unknown · DB unknown · pnpm unknown/)).toBeInTheDocument()
  })
})
