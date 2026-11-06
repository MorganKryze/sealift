import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import { ImportHeader } from "./header"

beforeAll(() => {
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "")
  }
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open")
  }
})

afterEach(() => vi.restoreAllMocks())

const me = { user: "alice", minioConfigured: true, bucket: "user-alice", folder: "packages/npm/" }

async function renderAt(path: string) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(me), { headers: { "Content-Type": "application/json" } }))
  const root = createRootRoute({ component: () => (<><ImportHeader /><Outlet /></>) })
  const page = (p: string) => createRoute({ getParentRoute: () => root, path: p, component: () => <p>page {p}</p> })
  const router = createRouter({
    routeTree: root.addChildren([page("/"), page("/imports"), page("/imports/$importId")]),
    history: createMemoryHistory({ initialEntries: [path] }),
  })
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await screen.findByRole("link", { name: "Archives" })
}

describe("ImportHeader", () => {
  it("shows the lockup, the two links and the user from /me", async () => {
    await renderAt("/")
    expect(screen.getAllByRole("img", { name: "sealift" }).length).toBeGreaterThan(0)
    expect(screen.getByRole("link", { name: "Archives" })).toHaveAttribute("href", "/")
    expect(screen.getByRole("link", { name: "Imports" })).toHaveAttribute("href", "/imports")
    expect(await screen.findByText("alice")).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith("/api/me", undefined)
  })

  it.each([
    ["/", "Archives", "Imports"],
    ["/imports", "Imports", "Archives"],
    ["/imports/20261106T101500Z-3f9a0c1d", "Imports", "Archives"],
  ])("at %s marks %s as the current page and not %s", async (path, current, other) => {
    await renderAt(path)
    expect(screen.getByRole("link", { name: current })).toHaveAttribute("aria-current", "page")
    expect(screen.getByRole("link", { name: other })).not.toHaveAttribute("aria-current")
  })

  it("Settings opens the sheet", async () => {
    await renderAt("/")
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Settings" }))
    const sheet = await screen.findByRole("dialog", { name: "Settings" })
    await waitFor(() => expect(within(sheet).getByText("user-alice")).toBeInTheDocument())
  })
})
