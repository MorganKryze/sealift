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

describe("ProjectsTable", () => {
  it("renders every project with its severity counts", () => {
    render(<ProjectsTable projects={projects} />)

    expect(screen.getByText("left-pad-app")).toBeInTheDocument()
    expect(screen.getByText("empty-project")).toBeInTheDocument()
    expect(screen.getByText(/2 critical/)).toBeInTheDocument()
    expect(screen.getByText(/5 high/)).toBeInTheDocument()
  })
})
