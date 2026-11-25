import { render } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { Mark } from "@/components/brand/Mark"

// Vitest empties every .css import, so the theme is read from disk, as theme.test.ts does.
type Node = { process: { getBuiltinModule(id: "node:fs"): { readFileSync(path: string, encoding: "utf8"): string } } }
const { readFileSync } = (globalThis as unknown as Node).process.getBuiltinModule("node:fs")
const theme = readFileSync(`${(import.meta as ImportMeta & { dirname: string }).dirname}/../../styles/theme.css`, "utf8")

function paints(container: HTMLElement) {
  return new Set(
    [...container.querySelectorAll("svg > *, svg g > *")]
      .flatMap((el) => [el.getAttribute("fill"), el.getAttribute("stroke")])
      .filter((p) => p && p !== "none"),
  )
}

describe("Mark", () => {
  it("draws the small seal on a 16 unit grid below 48 px", () => {
    const { container } = render(<Mark size={28} />)
    const svg = container.querySelector("svg")
    expect(svg).toHaveAttribute("viewBox", "0 0 16 16")
    expect(svg).toHaveAttribute("width", "28")
  })

  it("draws the full seal with its pier from 48 px up", () => {
    const { container } = render(<Mark size={48} />)
    expect(container.querySelector("svg")).toHaveAttribute("viewBox", "0 0 256 256")
    expect(container.querySelector("mask")).not.toBeNull()
  })

  it("paints the seal in the text colour and the crate in the teal variable", () => {
    for (const size of [16, 72]) {
      const { container } = render(<Mark size={size} />)
      expect(paints(container)).toEqual(new Set(["currentColor", "var(--sealift-teal,#0e7490)"]))
    }
  })

  it("gives each full mark its own mask id", () => {
    const { container } = render(
      <>
        <Mark size={56} />
        <Mark size={72} />
      </>,
    )
    const ids = [...container.querySelectorAll("mask")].map((m) => m.id)
    expect(new Set(ids).size).toBe(2)
    for (const id of ids) expect(container.querySelector(`[mask="url(#${id})"]`)).not.toBeNull()
  })

  it("lightens the crate's teal in the dark theme", () => {
    const blocks = theme.replace(/\/\*[\s\S]*?\*\//g, "")
    expect(blocks).toMatch(/:root\s*\{[^}]*--sealift-teal:\s*#0e7490;/)
    expect(blocks).toMatch(/\.dark\s*\{[^}]*--sealift-teal:\s*#2bb5cc;/)
    expect(blocks).toMatch(/:root:not\(\.light\):not\(\.dark\)\s*\{[^}]*--sealift-teal:\s*#2bb5cc;/)
  })
})
