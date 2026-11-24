import { render, screen } from "@testing-library/react"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { describe, expect, it } from "vitest"

import { ProblemNotice } from "./problem-notice"

describe("problem notice", () => {
  it("names the status and the log when the response carried no problem", () => {
    render(<ProblemNotice status={500} problem={null} />)
    expect(screen.getByText("Request failed with HTTP 500")).toBeInTheDocument()
    expect(screen.getByText(/no detail reached the browser/)).toBeInTheDocument()
  })

  it("keeps the server's title and detail when there is one", () => {
    render(<ProblemNotice status={500} problem={{ type: "about:blank", title: "update trivy db", status: 500, detail: "operation not permitted" }} />)
    expect(screen.getByText("update trivy db")).toBeInTheDocument()
    expect(screen.getByText("operation not permitted")).toBeInTheDocument()
  })

  it("leads to Home, where the tools show their progress, when they are not ready", async () => {
    const problem = { type: "tools-missing", title: "tools not ready", status: 409 }
    const root = createRootRoute()
    const page = createRoute({ getParentRoute: () => root, path: "/", component: () => <ProblemNotice status={409} problem={problem} /> })
    const router = createRouter({ routeTree: root.addChildren([page]), history: createMemoryHistory({ initialEntries: ["/"] }) })
    render(<RouterProvider router={router} />)
    await screen.findByText("tools not ready")
    expect(screen.queryByText("Open setup")).not.toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Follow their preparation on Home" })).toHaveAttribute("href", "/")
  })
})
