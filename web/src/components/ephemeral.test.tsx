import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
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
      review: { proposeOtherMajors: false, majorJump: "reason", cveWithoutFix: "reason" },
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
  it("asks first, then deletes, clears the tab's storage and hands back", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: true, idleMinutes: 60 }))
    vi.mocked(deleteProject).mockResolvedValue(undefined)
    sessionStorage.setItem("selection:a1", '{"lodash":["4.17.21"]}')
    const onErased = vi.fn()
    wrap(<EraseProject projectId="project-abc123" onErased={onErased} />)

    fireEvent.click(await screen.findByRole("button", { name: "Erase this project now" }))
    expect(deleteProject).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Erase" }))

    await waitFor(() => expect(onErased).toHaveBeenCalled())
    expect(deleteProject).toHaveBeenCalledWith("project-abc123")
    expect(sessionStorage.getItem("selection:a1")).toBeNull()
  })

  it("clears the tab's storage when the delete answered after removing the project", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: true, idleMinutes: 60 }))
    vi.mocked(deleteProject).mockRejectedValue(new ProblemError(500, { type: "about:blank", title: "delete project", status: 500 }))
    sessionStorage.setItem("selection:a1", '{"lodash":["4.17.21"]}')
    wrap(<EraseProject projectId="project-abc123" onErased={vi.fn()} />)
    fireEvent.click(await screen.findByRole("button", { name: "Erase this project now" }))
    fireEvent.click(screen.getByRole("button", { name: "Erase" }))
    await waitFor(() => expect(sessionStorage.getItem("selection:a1")).toBeNull())
  })

  it("keeps the tab's storage when a running job refused the delete", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: true, idleMinutes: 60 }))
    vi.mocked(deleteProject).mockRejectedValue(new ProblemError(409, { type: "about:blank", title: "delete project", status: 409 }))
    sessionStorage.setItem("selection:a1", '{"lodash":["4.17.21"]}')
    wrap(<EraseProject projectId="project-abc123" onErased={vi.fn()} />)
    fireEvent.click(await screen.findByRole("button", { name: "Erase this project now" }))
    fireEvent.click(screen.getByRole("button", { name: "Erase" }))
    expect(await screen.findByText("delete project")).toBeInTheDocument()
    expect(sessionStorage.getItem("selection:a1")).not.toBeNull()
    sessionStorage.clear()
  })

  it("keeps the project when the user steps back", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: true, idleMinutes: 60 }))
    wrap(<EraseProject projectId="project-abc123" onErased={vi.fn()} />)
    fireEvent.click(await screen.findByRole("button", { name: "Erase this project now" }))
    fireEvent.click(screen.getByRole("button", { name: "Keep it" }))
    expect(deleteProject).not.toHaveBeenCalled()
    expect(screen.queryByRole("alertdialog")).toBeNull()
  })

  it("is absent outside the mode", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance({ ephemeral: false }))
    wrap(<EraseProject projectId="project-abc123" onErased={vi.fn()} />)
    await waitFor(() => expect(getInstance).toHaveBeenCalled())
    expect(screen.queryByRole("button", { name: "Erase this project now" })).toBeNull()
  })
})
