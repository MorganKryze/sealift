import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { Instance } from "@/api/settings"
import { PolicySection } from "@/components/settings/policy-section"

const policy: Instance["policy"] = {
  target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
  pipTarget: { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" },
  minReleaseAgeDays: 14,
  resolveParallelism: 4,
  downloadParallelism: 16,
  review: { proposeOtherMajors: false, majorJump: "reason", cveWithoutFix: "reason" },
}

// The value a term of the description list holds.
const valueOf = (term: string) => screen.getByText(term, { selector: "dt" }).nextElementSibling?.textContent

describe("PolicySection", () => {
  it("shows both targets, the release age and the parallelism, their figures in weight 600", () => {
    render(<PolicySection policy={policy} ephemeral={false} />)
    expect(screen.getByRole("heading", { name: "Policy" })).toBeInTheDocument()
    expect(screen.getByText("Set at deploy")).toBeInTheDocument()
    expect(valueOf("npm target")).toBe("Node 22.17.1, Linux x64 · glibc")
    expect(valueOf("pip target")).toBe("Python 3.11.2, Linux x86_64 · glibc 2.28")
    expect(valueOf("Release age")).toBe("At least 14 days old")
    expect(valueOf("Parallelism")).toBe("4 resolves, 16 downloads")
    expect(valueOf("Projects")).toBe("Kept until someone deletes them")
    for (const figure of ["22.17.1", "3.11.2", "2.28", "14 days", "4", "16"]) expect(screen.getByText(figure)).toHaveClass("figure")
  })

  it("shows the review rules at their defaults", () => {
    render(<PolicySection policy={policy} ephemeral={false} />)
    expect(valueOf("Proposals")).toBe("Inside the current line")
    expect(valueOf("Major jump")).toBe("Needs a reason")
    expect(valueOf("CVE without fix")).toBe("Needs a reason")
  })

  it("shows the review rules a deployment widened or tightened", () => {
    render(<PolicySection policy={{ ...policy, review: { proposeOtherMajors: true, majorJump: "refuse", cveWithoutFix: "refuse" } }} ephemeral={false} />)
    expect(valueOf("Proposals")).toBe("Any version")
    expect(valueOf("Major jump")).toBe("Refused")
    expect(valueOf("CVE without fix")).toBe("Refused")
  })

  it("names a target outside the platform list by its fields", () => {
    render(<PolicySection policy={{ ...policy, target: { ...policy.target, os: "darwin", cpu: "arm64", libc: "" } }} ephemeral={false} />)
    expect(valueOf("npm target")).toBe("Node 22.17.1, darwin arm64")
  })

  it("says ephemeral mode and its idle delay", () => {
    render(<PolicySection policy={policy} ephemeral idleMinutes={45} />)
    expect(valueOf("Projects")).toBe("Erased with their caches after 45 minutes without activityEphemeral mode")
    expect(screen.getByText("45 minutes")).toHaveClass("figure")
  })

  it("offers no input, select or button", () => {
    const { container } = render(<PolicySection policy={policy} ephemeral idleMinutes={1} />)
    expect(container.querySelector("input, select, textarea, button, form")).toBeNull()
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
    expect(container.querySelector("dl")).not.toBeNull()
  })
})
