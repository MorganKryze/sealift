import { render, screen } from "@testing-library/react"
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { describe, expect, it } from "vitest"

import { ArchiveRow } from "./archive-row"

const HOSTILE = "<img src=x onerror=alert(1)> javascript:alert(1)"

describe("text from an archive renders as text", () => {
  it("a key and a reason holding markup and a javascript link show as words", async () => {
    const root = createRootRoute({
      component: () => (
        <ul>
          <ArchiveRow archive={{ key: `packages/npm/${HOSTILE}/packages_npm.tar.gz`, size: 1, modified: "2026-11-05T08:00:00Z", importable: true }} onStart={() => {}} />
          <ArchiveRow archive={{ key: "packages/npm/b/packages_npm.tar.gz", size: 1, modified: "2026-11-05T08:00:00Z", importable: false, reason: HOSTILE }} onStart={() => {}} />
        </ul>
      ),
    })
    render(<RouterProvider router={createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: ["/"] }) })} />)
    expect(await screen.findAllByText(new RegExp(HOSTILE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toHaveLength(2)
    expect(document.querySelector("img")).toBeNull()
    expect(document.querySelector("a[href^='javascript' i]")).toBeNull()
    expect(document.querySelector("[onerror]")).toBeNull()
  })
})
