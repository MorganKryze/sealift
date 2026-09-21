import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { ProjectsView } from "@/components/projects/projects-view"

const noop = () => {}

describe("ProjectsView", () => {
  it("shows a quiet loading state while the query is pending", () => {
    render(<ProjectsView status="pending" onRetry={noop} onFile={noop} onInvalidFile={noop} />)

    expect(screen.getByRole("status")).toHaveTextContent("Loading projects")
    expect(screen.queryByText("Nothing in the hold yet")).not.toBeInTheDocument()
  })

  it("names what failed and offers a retry on a failed fetch", () => {
    const onRetry = vi.fn()
    render(
      <ProjectsView
        status="error"
        error={new Error("network down")}
        onRetry={onRetry}
        onFile={noop}
        onInvalidFile={noop}
      />,
    )

    expect(screen.getByRole("alert")).toHaveTextContent("network down")
    expect(screen.queryByText("Nothing in the hold yet")).not.toBeInTheDocument()

    screen.getByRole("button", { name: "Retry" }).click()
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it("shows the empty state only once the list has loaded and is really empty", () => {
    render(<ProjectsView status="success" projects={[]} onRetry={noop} onFile={noop} onInvalidFile={noop} />)

    expect(screen.getByText("Nothing in the hold yet")).toBeInTheDocument()
  })
})
