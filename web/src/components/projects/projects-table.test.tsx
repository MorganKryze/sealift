import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { ProjectSummary } from "@/api/projects"
import { ProjectsTable } from "@/components/projects/projects-table"

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" }

const projects: ProjectSummary[] = [
  {
    id: "p1",
    name: "left-pad-app",
    target,
    lastAnalysis: {
      id: "a1",
      projectId: "p1",
      state: "done",
      createdAt: "2026-09-01T00:00:00Z",
      result: {
        target,
        before: [2, 5, 0, 0, 1],
        dependencies: [],
        warnings: [],
      },
    },
  },
  {
    id: "p2",
    name: "empty-project",
    target,
  },
]

// ProjectsTable links each project name with <Link>, which needs a router
// context to render: a minimal router with one route, rendering the table
// itself, is enough without pulling in the app's own route tree.
function renderTable() {
  const rootRoute = createRootRoute({ component: () => <ProjectsTable projects={projects} /> })
  const router = createRouter({ routeTree: rootRoute, history: createMemoryHistory() })
  return render(<RouterProvider router={router} />)
}

describe("ProjectsTable", () => {
  it("renders every project with its severity counts", async () => {
    renderTable()

    expect(await screen.findByText("left-pad-app")).toBeInTheDocument()
    expect(screen.getByText("empty-project")).toBeInTheDocument()
    expect(screen.getByText(/2 critical/)).toBeInTheDocument()
    expect(screen.getByText(/5 high/)).toBeInTheDocument()
  })

  it("links each project name to its page", async () => {
    renderTable()

    const link = await screen.findByRole("link", { name: "left-pad-app" })
    expect(link).toHaveAttribute("href", "/projects/p1")
  })
})
