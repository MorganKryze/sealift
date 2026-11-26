import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { deleteProject } from "@/api/projects"
import { getInstance, type Instance } from "@/api/settings"
import { EphemeralBanner, EraseProject } from "@/components/ephemeral"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getInstance: vi.fn() }
})
vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, deleteProject: vi.fn() }
})

function wrap(node: React.ReactNode) {
  render(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>)
}

// A ready instance under the default policy and brand, in the mode given.
function instance(mode: Pick<Instance, "ephemeral" | "idleMinutes">): Instance {
  return {
    ...mode,
    ready: true,
    preparing: [],
    brand: { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false },
    policy: {
      target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
      pipTarget: { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" },
      minReleaseAgeDays: 14,
      resolveParallelism: 4,
      downloadParallelism: 16,
      review: { proposeOtherMajors: false, majorJump: "reason", cveWithoutFix: "reason", yanked: "reason" },
    },
    tools: { trivy: "0.55.0", pnpm: ["10.34.5"], uv: ["0.13.7"] },
  }
}

beforeEach(() => {
  vi.mocked(deleteProject).mockReset()
})

describe("ephemeral banner", () => {
  it("names the mode and the idle delay", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: true, idleMinutes: 45 }))
    wrap(<EphemeralBanner />)
    expect(await screen.findByText(/Ephemeral instance/)).toBeInTheDocument()
    expect(screen.getByText(/45 minutes without activity/)).toBeInTheDocument()
  })

  it("says minute for a one-minute delay", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: true, idleMinutes: 1 }))
    wrap(<EphemeralBanner />)
    expect(await screen.findByText(/after 1 minute without activity/)).toBeInTheDocument()
  })

  it("shows nothing outside the mode", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: false }))
    wrap(<EphemeralBanner />)
    await waitFor(() => expect(getInstance).toHaveBeenCalled())
    expect(screen.queryByText(/Ephemeral instance/)).toBeNull()
  })
})

describe("erase project", () => {
  const erase = (onErased = vi.fn()) => wrap(<EraseProject projectId="project-abc123" idleMinutes={30} onErased={onErased} />)

  it("shows the delay with Erase now", () => {
    erase()
    const row = screen.getByText(/erased after/).closest("section") as HTMLElement
    expect(row).toHaveTextContent("This project and its files are erased after 30 minutes without activity.")
    expect(row.querySelector(".tinted-warn")).not.toBeNull()
    expect(within(row).getByText("30 minutes")).toHaveClass("figure")
    expect(within(row).getByRole("button", { name: "Erase now" })).toBeInTheDocument()
  })

  it("says minute for a one-minute delay", () => {
    wrap(<EraseProject projectId="project-abc123" idleMinutes={1} onErased={vi.fn()} />)
    expect(screen.getByText("1 minute")).toBeInTheDocument()
  })

  it("confirms in place and focuses Keep it", () => {
    erase()
    fireEvent.click(screen.getByRole("button", { name: "Erase now" }))
    const confirm = screen.getByRole("alertdialog", { name: "Erase this project and its files now?" })
    expect(confirm).toHaveClass("tinted-bad")
    expect(confirm).toHaveTextContent("Download what you carry first.")
    expect(within(confirm).getByRole("button", { name: "Keep it" })).toHaveFocus()
    expect(deleteProject).not.toHaveBeenCalled()
  })

  it("asks first, then deletes, clears the tab's storage and hands back", async () => {
    vi.mocked(deleteProject).mockResolvedValue(undefined)
    sessionStorage.setItem("selection:a1", '{"lodash":["4.17.21"]}')
    const onErased = vi.fn()
    erase(onErased)

    fireEvent.click(screen.getByRole("button", { name: "Erase now" }))
    expect(deleteProject).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Erase" }))

    await waitFor(() => expect(onErased).toHaveBeenCalled())
    expect(deleteProject).toHaveBeenCalledWith("project-abc123")
    expect(sessionStorage.getItem("selection:a1")).toBeNull()
  })

  it("clears the tab's storage when the delete answered after removing the project", async () => {
    vi.mocked(deleteProject).mockRejectedValue(new ProblemError(500, { type: "about:blank", title: "delete project", status: 500 }))
    sessionStorage.setItem("selection:a1", '{"lodash":["4.17.21"]}')
    erase()
    fireEvent.click(screen.getByRole("button", { name: "Erase now" }))
    fireEvent.click(screen.getByRole("button", { name: "Erase" }))
    await waitFor(() => expect(sessionStorage.getItem("selection:a1")).toBeNull())
  })

  it("keeps the tab's storage when a running job refused the delete", async () => {
    vi.mocked(deleteProject).mockRejectedValue(new ProblemError(409, { type: "about:blank", title: "delete project", status: 409 }))
    sessionStorage.setItem("selection:a1", '{"lodash":["4.17.21"]}')
    erase()
    fireEvent.click(screen.getByRole("button", { name: "Erase now" }))
    fireEvent.click(screen.getByRole("button", { name: "Erase" }))
    expect(await screen.findByText("delete project")).toBeInTheDocument()
    expect(sessionStorage.getItem("selection:a1")).not.toBeNull()
    sessionStorage.clear()
  })

  it.each([
    ["Keep it", (confirm: HTMLElement) => fireEvent.click(within(confirm).getByRole("button", { name: "Keep it" }))],
    ["Escape", (confirm: HTMLElement) => fireEvent.keyDown(confirm, { key: "Escape" })],
  ])("keeps the project on %s and gives the focus back to Erase now", (_name, stepBack) => {
    erase()
    fireEvent.click(screen.getByRole("button", { name: "Erase now" }))
    stepBack(screen.getByRole("alertdialog"))
    expect(deleteProject).not.toHaveBeenCalled()
    expect(screen.queryByRole("alertdialog")).toBeNull()
    expect(screen.getByRole("button", { name: "Erase now" })).toHaveFocus()
  })
})
