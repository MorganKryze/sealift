import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ToolsPanel } from "@/components/settings/tools-panel"
import { formatDbDate } from "@/lib/format-tools"

const DB_DATE = "2026-11-24T06:12:00Z"

const valueOf = (term: string) => screen.getByText(term, { selector: "dt" }).nextElementSibling?.textContent

describe("ToolsPanel", () => {
  it("shows the pinned Trivy and the database date", () => {
    render(<ToolsPanel tools={{ trivy: "0.76.2", trivyDbDate: DB_DATE, pnpm: ["10.34.5"], uv: ["0.13.7"] }} />)
    expect(screen.getByRole("heading", { name: "Scanner" })).toBeInTheDocument()
    expect(valueOf("Trivy")).toBe("0.76.2")
    expect(valueOf("Vulnerability database")).toBe(`Downloaded ${formatDbDate(DB_DATE)}`)
  })

  it("says when no database was downloaded yet", () => {
    render(<ToolsPanel tools={{ trivy: "0.76.2", pnpm: [], uv: [] }} />)
    expect(valueOf("Vulnerability database")).toBe("Not downloaded yet")
  })

  it("offers no button", () => {
    const { container } = render(<ToolsPanel tools={{ trivy: "0.76.2", trivyDbDate: DB_DATE, pnpm: [], uv: [] }} />)
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
    expect(container.querySelector("input, select, textarea, button, form")).toBeNull()
  })
})
