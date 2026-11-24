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
}

// The value a term of the description list holds.
const valueOf = (term: string) => screen.getByText(term, { selector: "dt" }).nextElementSibling?.textContent

describe("PolicySection", () => {
  it("shows both targets, the release age and the parallelism", () => {
    render(<PolicySection policy={policy} ephemeral={false} />)
    expect(screen.getByRole("heading", { name: "Policy" })).toBeInTheDocument()
    expect(screen.getByText("Set by your deployment.")).toBeInTheDocument()
    expect(valueOf("npm target")).toBe("Linux x64 · glibc, Node 22.17.1, pnpm 10.34.5")
    expect(valueOf("pip target")).toBe("Linux x86_64 · glibc 2.28, Python 3.11.2, uv 0.13.7")
    expect(valueOf("Minimum release age")).toBe("14 days")
    expect(valueOf("Resolve parallelism")).toBe("4 at once")
    expect(valueOf("Download parallelism")).toBe("16 at once")
    expect(valueOf("Mode")).toBe("Projects stay until someone deletes them.")
  })

  it("names a target outside the platform list by its fields", () => {
    render(<PolicySection policy={{ ...policy, target: { ...policy.target, os: "darwin", cpu: "arm64", libc: "" } }} ephemeral={false} />)
    expect(valueOf("npm target")).toBe("darwin arm64, Node 22.17.1, pnpm 10.34.5")
  })

  it("says ephemeral mode and its idle delay", () => {
    render(<PolicySection policy={policy} ephemeral idleMinutes={45} />)
    expect(valueOf("Mode")).toBe("Ephemeral: a project is erased after 45 minutes without activity.")
  })

  it("offers no input, select or button", () => {
    const { container } = render(<PolicySection policy={policy} ephemeral idleMinutes={1} />)
    expect(container.querySelector("input, select, textarea, button, form")).toBeNull()
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
    expect(container.querySelector("dl")).not.toBeNull()
  })
})
