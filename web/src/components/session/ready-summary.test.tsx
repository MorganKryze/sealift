import { render, screen, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ReadySummary } from "@/components/session/ready-summary"

// Critical, high, medium, low, unknown: 25 known CVEs before, 2 after.
const before = [1, 10, 11, 3, 0]
const after = [0, 1, 1, 0, 0]

const head = () => screen.getByRole("region", { name: "Known CVEs" })
const severity = (word: string) => screen.getByText(word, { selector: "[data-severity] *" }).closest("[data-severity]") as HTMLElement
const delta = (scope: HTMLElement) => scope.querySelector("[data-delta]") as HTMLElement

describe("ReadySummary", () => {
  it("shows the total before and after large", () => {
    render(<ReadySummary before={before} after={after} checkedTogether directDependencies={150} />)
    const total = head().querySelector("[data-total]") as HTMLElement
    expect(total).toHaveTextContent("25 to 2")
    expect(within(total).getByText("2")).toHaveClass("font-semibold")
    expect(within(total).getByText("25")).not.toHaveClass("font-semibold")
    expect(total).toHaveClass("text-[34px]")
    expect(delta(head().querySelector("[data-total-block]") as HTMLElement)).toHaveTextContent("−23")
  })

  it("gives each severity its delta with arrow and sign", () => {
    render(<ReadySummary before={[1, 1, 2, 0, 0]} after={[0, 3, 2, 0, 0]} checkedTogether directDependencies={3} />)
    const critical = severity("critical")
    expect(critical).toHaveTextContent("1 to 0")
    expect(delta(critical)).toHaveTextContent("−1")
    expect(delta(critical)).toHaveClass("text-ok")
    expect(delta(critical).querySelector(".lucide-arrow-down")).not.toBeNull()

    const high = severity("high")
    expect(high).toHaveTextContent("1 to 3")
    expect(delta(high)).toHaveTextContent("+2")
    expect(delta(high)).toHaveClass("text-bad")
    expect(delta(high).querySelector(".lucide-arrow-up")).not.toBeNull()

    const medium = severity("medium")
    // An unchanged count shows no delta: the arrow already says it.
    expect(delta(medium)).toBeNull()
    expect(severity("low")).toHaveTextContent("0 to 0")
    // Unknown shows only when a count holds one, so the four columns add up to the total.
    expect(screen.queryByText("unknown", { selector: "[data-severity] *" })).toBeNull()
  })

  it("names an unknown severity when a count holds one", () => {
    render(<ReadySummary before={[0, 0, 0, 0, 2]} after={[0, 0, 0, 0, 1]} checkedTogether directDependencies={3} />)
    expect(severity("unknown")).toHaveTextContent("2 to 1")
  })

  it("says not checked together for a hand-made selection", () => {
    const { rerender } = render(<ReadySummary before={before} after={after} checkedTogether directDependencies={150} />)
    expect(screen.queryByText("Not checked together")).toBeNull()
    rerender(<ReadySummary before={before} after={after} checkedTogether={false} directDependencies={150} />)
    const line = screen.getByText("Not checked together")
    expect(head().querySelector("[data-total-block]")).toContainElement(line)
  })

  it("counts the direct dependencies", () => {
    render(<ReadySummary before={before} after={after} checkedTogether directDependencies={1} />)
    expect(screen.getByText("direct dependency", { exact: false })).toHaveTextContent("1 direct dependency")
  })

  it("explains Known CVEs and the severities from the head", () => {
    render(<ReadySummary before={before} after={after} checkedTogether directDependencies={150} />)
    const cve = screen.getAllByRole("button", { name: "What a CVE is" })
    const sev = screen.getAllByRole("button", { name: "What a severity is" })
    expect(cve).toHaveLength(1)
    expect(sev).toHaveLength(1)
    expect(head().querySelector("[data-total-block]")).toContainElement(cve[0])
    expect(screen.getByText("By severity").parentElement).toContainElement(sev[0])
    expect(cve[0]).toHaveAttribute("aria-expanded", "false")
  })
})
