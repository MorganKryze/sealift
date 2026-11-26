import { fireEvent, render, screen, within } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import type { AnalysisResult, Candidate, DependencyResult } from "@/api/projects"
import { ReasonsBlock } from "@/components/session/reasons-block"
import { TERM_DOCS, Term } from "@/components/ui/term"
import { requiredReasons } from "@/lib/requiredReasons"

function candidate(version: string, leavesLine = false, cves: Candidate["cves"] = []): Candidate {
  return { version, vector: [0, 0, 0, 0, 0], cves, signals: [], key: true, resolved: true, leavesLine }
}

const angularCves = [
  { id: "CVE-2024-21490", severity: "HIGH", package: "angular@1.8.3", fixedIn: "" },
  ...["CVE-2025-4690", "CVE-2025-2336", "CVE-2025-0716"].map((id) => ({ id, severity: "MEDIUM", package: "angular@1.8.3", fixedIn: "" })),
]

const dependencies: DependencyResult[] = [
  { name: "react", current: "18.2.0", jump: "19.2.0", family: "react 19", vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate("19.2.0", true)] },
  { name: "react-dom", current: "18.2.0", jump: "19.2.0", family: "react 19", vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate("19.2.0", true)] },
  { name: "express", current: "4.17.1", jump: "5.1.0", vector: [0, 0, 0, 0, 0], cves: [], candidates: [candidate("5.1.0", true)] },
  {
    name: "html-minifier", current: "4.0.0", vector: [0, 1, 0, 0, 0], candidates: [],
    cves: [{ id: "CVE-2022-37620", severity: "HIGH", package: "html-minifier@4.0.0", fixedIn: "" }],
  },
  { name: "angular", current: "1.8.3", vector: [0, 1, 3, 0, 0], candidates: [], cves: angularCves },
]

const result: AnalysisResult = {
  target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" },
  before: [0, 2, 3, 0, 0],
  dependencies,
  warnings: [],
  families: [{ name: "react 19", members: ["react", "react-dom"] }],
}

const needed = requiredReasons(result, { react: ["19.2.0"], "react-dom": ["19.2.0"], express: ["5.1.0"] })

function renderBlock(reasons: Record<string, string> = {}, extra: Partial<Parameters<typeof ReasonsBlock>[0]> = {}) {
  const onDecide = vi.fn()
  const onJump = vi.fn()
  render(<ReasonsBlock needed={needed} reasons={reasons} result={result} onDecide={onDecide} onJump={onJump} {...extra} />)
  return { onDecide, onJump }
}

const band = (name: RegExp) => screen.getByRole("group", { name })
const rowOf = (name: string) => screen.getByText(name, { selector: "[data-reason-name]" }).closest("[data-reason-row]") as HTMLElement

describe("ReasonsBlock", () => {
  it("draws a band per kind", () => {
    renderBlock()
    const jumps = band(/major jumps/)
    const cves = band(/known CVEs with no fixed version/)
    expect(jumps).toHaveTextContent("3 major jumps")
    expect(within(jumps).getByText("react 19")).toBeInTheDocument()
    expect(within(jumps).getByText("2 packages")).toBeInTheDocument()
    expect(within(jumps).getByText("express")).toBeInTheDocument()
    expect(cves).toHaveTextContent("5 known CVEs with no fixed version in 2 packages")
    expect(within(cves).getByText("html-minifier")).toBeInTheDocument()
    expect(within(cves).getByText("angular")).toBeInTheDocument()
  })

  it("draws nothing when the selection needs no reason", () => {
    const { container } = render(<ReasonsBlock needed={[]} reasons={{}} result={result} onDecide={() => {}} onJump={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it("marks a missing reason with its action", () => {
    const { onDecide, onJump } = renderBlock()
    const jumps = band(/major jumps/)
    const cves = band(/known CVEs with no fixed version/)
    expect(within(jumps).getAllByText("Reason missing")).toHaveLength(2)
    expect(within(cves).getAllByText("Reason missing")).toHaveLength(2)
    fireEvent.click(within(cves).getByRole("button", { name: "Decide html-minifier" }))
    expect(onDecide).toHaveBeenCalledWith("html-minifier")
    fireEvent.click(within(jumps).getByRole("button", { name: "Jump react 19" }))
    expect(onJump).toHaveBeenCalledWith("react")
    expect(rowOf("html-minifier")).toHaveClass("tinted-warn")
  })

  it("shows a written reason's text", () => {
    const { onDecide } = renderBlock({ "cve-without-fix:html-minifier": "Dev dependency, runs at build time on our own HTML" })
    const row = rowOf("html-minifier")
    expect(row).not.toHaveClass("tinted-warn")
    expect(within(row).getByText("“Dev dependency, runs at build time on our own HTML”")).toBeInTheDocument()
    expect(within(row).queryByText("Reason missing")).toBeNull()
    fireEvent.click(within(row).getByRole("button", { name: "Change html-minifier" }))
    expect(onDecide).toHaveBeenCalledWith("html-minifier")
  })

  it("lists a row's CVEs in place past one", () => {
    renderBlock()
    const html = rowOf("html-minifier")
    expect(within(html).getByText("CVE-2022-37620")).toBeInTheDocument()
    expect(within(html).queryByRole("button", { name: /CVEs of html-minifier/ })).toBeNull()

    const angular = rowOf("angular")
    expect(within(angular).getByText("1 high")).toBeInTheDocument()
    expect(within(angular).getByText("3 medium")).toBeInTheDocument()
    const toggle = within(angular).getByRole("button", { name: "4 CVEs of angular" })
    expect(toggle).toHaveAttribute("aria-expanded", "false")
    expect(within(angular).queryByText("CVE-2025-4690")).toBeNull()
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute("aria-expanded", "true")
    for (const cve of angularCves) expect(within(angular).getByText(cve.id)).toBeInTheDocument()
    expect(within(angular).getAllByText("No fixed version")).toHaveLength(4)
  })

  it("shows the server's refusal in the block", () => {
    renderBlock({}, { refusal: "reason 1 (major-jump) covers nothing the selection takes" })
    expect(screen.getByRole("alert")).toHaveTextContent("reason 1 (major-jump) covers nothing the selection takes")
  })

  it("explains each term once, at its band heads and the first row with severities", () => {
    renderBlock()
    expect(within(band(/major jumps/)).getAllByRole("button", { name: "What a major jump is" })).toHaveLength(1)
    expect(within(band(/known CVEs with no fixed version/)).getAllByRole("button", { name: "What a CVE is" })).toHaveLength(1)
    const severity = screen.getAllByRole("button", { name: "What a severity is" })
    expect(severity).toHaveLength(1)
    expect(severity[0].closest("[data-reason-row]")).toBe(rowOf("html-minifier"))
  })

  it("explains a term one press away and gives the focus back", () => {
    render(
      <div>
        <p>Outside</p>
        <Term id="cve" />
      </div>,
    )
    const button = screen.getByRole("button", { name: "What a CVE is" })
    const text = "A CVE is a publicly listed security flaw, named by an id such as CVE-2024-4068. Known CVEs counts the ones the scan found in these versions."
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText(text)).toBeNull()

    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "true")
    const popover = document.getElementById(button.getAttribute("aria-controls") ?? "")
    expect(popover).toHaveTextContent(text)
    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "false")

    // A button turns Enter and Space into a click, which jsdom does not do: the key, then its click.
    fireEvent.keyDown(button, { key: "Enter" })
    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "true")
    const link = screen.getByRole("link", { name: "Read more" })
    link.focus()
    fireEvent.keyDown(link, { key: "Escape" })
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(button).toHaveFocus()

    fireEvent.keyDown(button, { key: " " })
    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "true")
    // The focus sits in the popover first, so only the outside press can bring it back.
    screen.getByRole("link", { name: "Read more" }).focus()
    expect(button).not.toHaveFocus()
    fireEvent.pointerDown(screen.getByText("Outside"))
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(button).toHaveFocus()
    expect(screen.queryByText(text)).toBeNull()
  })

  it("keeps its explanation inside the window beside the right edge", () => {
    render(<Term id="major-jump" />)
    const button = screen.getByRole("button", { name: "What a major jump is" })
    const popover = document.getElementById(button.getAttribute("aria-controls") ?? "") as HTMLElement
    vi.spyOn(button, "getBoundingClientRect").mockReturnValue(new DOMRect(40, 100, 32, 32))
    fireEvent.click(button)
    expect(popover).toHaveAttribute("data-align", "start")
    fireEvent.click(button)
    vi.spyOn(button, "getBoundingClientRect").mockReturnValue(new DOMRect(window.innerWidth - 120, 100, 32, 32))
    fireEvent.click(button)
    expect(popover).toHaveAttribute("data-align", "end")
  })

  it("links each term to its docs section with no opener and no referrer", () => {
    render(
      <div>
        <Term id="cve" />
        <Term id="severity" />
        <Term id="major-jump" />
      </div>,
    )
    const docs = "https://github.com/MorganKryze/sealift/blob/main/docs/how-sealift-chooses.md"
    expect(TERM_DOCS).toEqual({ cve: `${docs}#known-cves`, severity: `${docs}#severity`, "major-jump": `${docs}#major-jump` })
    const texts = {
      "What a CVE is": [TERM_DOCS.cve, "A CVE is a publicly listed security flaw, named by an id such as CVE-2024-4068. Known CVEs counts the ones the scan found in these versions."],
      "What a severity is": [
        TERM_DOCS.severity,
        "Each CVE is rated critical, high, medium or low by the harm it can do, or unknown when it has no rating. Versions are ranked by these counts, the most serious first.",
      ],
      "What a major jump is": [TERM_DOCS["major-jump"], "A major jump moves a package to a new major version, such as 4.x to 5.x. It may break your code, so it needs a reason."],
    }
    for (const [name, [href, text]] of Object.entries(texts)) {
      const button = screen.getByRole("button", { name })
      fireEvent.click(button)
      const popover = document.getElementById(button.getAttribute("aria-controls") ?? "") as HTMLElement
      expect(popover).toHaveTextContent(text)
      const link = within(popover).getByRole("link", { name: "Read more" })
      expect(link).toHaveAttribute("href", href)
      expect(link).toHaveAttribute("target", "_blank")
      expect(link.getAttribute("rel")?.split(" ").sort()).toEqual(["noopener", "noreferrer"])
      fireEvent.click(button)
    }
  })
})
