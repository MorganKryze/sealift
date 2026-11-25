import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { type AnyRouter, createMemoryHistory, createRootRoute, createRouter, type ErrorRouteComponent, RouterProvider } from "@tanstack/react-router"
import { fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ImportApiError } from "@/import/api/client"
import { OFFLINE_INSTANCE, OFFLINE_PLACES, offlineCrumbs } from "@/import/lib/places"
import { Route as ImportRoot } from "@/import/routes/__root"
import { routeTree } from "@/import/routeTree.gen"

const TRUSTED = "3f9a1c7e0b2d4f6a8c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5a"

const meFor = (user: string) => ({ user, minioConfigured: true, bucket: `user-${user}`, folder: "packages/npm/", publicKeySha256: TRUSTED })

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })

// The import role's real route tree, its root and frame included; only the service's answers are faked.
function serve(user: string) {
  vi.spyOn(window, "scrollTo").mockImplementation(() => {})
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/me") return json(meFor(user))
    return new Promise<Response>(() => {})
  })
}

async function renderAt(path: string, { user = "lea.martin" }: { user?: string } = {}) {
  serve(user)
  return renderRouter(createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [path] }) }))
}

async function renderRouter(router: AnyRouter) {
  const view = render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await screen.findByRole("navigation", { name: "Places" })
  return view
}

async function renderInstance(user?: string) {
  const view = await renderAt("/instance", { user })
  await screen.findByRole("heading", { level: 1, name: "Instance" })
  await screen.findByRole("button", { name: /^Public key sha256 / })
  return view
}

const places = () => screen.getByRole("navigation", { name: "Places" })
const compare = () => screen.getByRole("button", { name: "Compare" })
const field = () => screen.queryByRole("textbox", { name: "sha256 from the connected side" })

afterEach(() => {
  vi.restoreAllMocks()
  document.title = ""
})

describe("the import side's frame", () => {
  it("lists Home and Imports, Instance at the bottom and the user's initials", async () => {
    await renderInstance()
    const list = within(places()).getByRole("list")
    expect(within(list).getAllByRole("link").map((l) => [l.textContent, l.getAttribute("href")])).toEqual([
      ["Home", "/"],
      ["Imports", "/imports"],
    ])
    const links = within(places()).getAllByRole("link")
    expect(links.map((l) => l.textContent)).toEqual(["Home", "Imports", "Instance"])
    expect(links[2]).toHaveAttribute("href", "/instance")
    expect(links[2]).toHaveAttribute("aria-current", "page")
    expect(list).not.toContainElement(links[2])
    expect(within(places()).getByText("LM")).toBeInTheDocument()
    expect(within(places()).getByText("Signed in as lea.martin")).toBeInTheDocument()
  })

  it("shows the default side label with the unplugged icon", async () => {
    await renderInstance()
    const bar = screen.getByRole("banner")
    expect(bar.children).toHaveLength(2)
    expect(bar.children[1]).toHaveTextContent(/^Offline$/)
    expect(bar.children[1].querySelector("svg.lucide-unplug")).not.toBeNull()
    expect(document.title).toBe("sealift")
  })

  it("names the page in the breadcrumb, an import under Imports", async () => {
    expect(offlineCrumbs("/")).toEqual([{ label: "Home" }])
    expect(offlineCrumbs("/imports")).toEqual([{ label: "Imports" }])
    expect(offlineCrumbs("/imports/20261104T142000Z-a1000006")).toEqual([{ label: "Imports", to: "/imports" }, { label: "Import" }])
    expect(offlineCrumbs("/instance")).toEqual([{ label: "Instance" }])

    await renderInstance()
    const crumb = within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByText("Instance")
    expect(crumb).toHaveAttribute("aria-current", "page")
  })

  it("keeps a failed page inside the frame", async () => {
    serve("lea.martin")
    const Failed = ImportRoot.options.errorComponent as ErrorRouteComponent
    const error = new ImportApiError(503, { type: "about:blank", title: "Unavailable", status: 503, detail: "The service is stopping" })
    const failing = createRootRoute({ component: () => <Failed error={error} reset={() => {}} info={{ componentStack: "" }} /> })
    const view = await renderRouter(createRouter({ routeTree: failing, history: createMemoryHistory() }))
    expect(screen.getByRole("main")).toContainElement(await screen.findByText(/The service is stopping/))
    view.unmount()

    await renderAt("/nowhere")
    expect(await screen.findByText("Nothing here")).toBeInTheDocument()
    expect(screen.getByRole("main")).toContainElement(screen.getByText("Nothing here"))
    expect(screen.getAllByRole("navigation", { name: "Places" })).toHaveLength(1)
  })

  it("lists only places the route tree holds", () => {
    const router = createRouter({ routeTree, history: createMemoryHistory() })
    for (const place of [...OFFLINE_PLACES, OFFLINE_INSTANCE]) {
      expect(router.matchRoutes(place.to).map((m) => m.routeId), place.to).not.toEqual(["__root__"])
    }
  })

  it("makes initials from up to two parts of the user name", async () => {
    for (const [user, letters] of [
      ["l.martin", "LM"],
      ["alice", "AL"],
      ["jo", "JO"],
      ["anne_marie-dupont", "AM"],
      ["jean luc", "JL"],
    ]) {
      const view = await renderInstance(user)
      expect(within(places()).getByText(letters)).toBeInTheDocument()
      view.unmount()
    }
  })
})

describe("OfflineInstancePage", () => {
  it("shows the trusted key as a fingerprint", async () => {
    await renderInstance()
    const key = screen.getByRole("button", { name: "Public key sha256 3f9a1c7e…0b1d3f5a" })
    expect(key).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByRole("button", { name: "Copy Public key sha256" })).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 2, name: "Trusted key" })).toBeInTheDocument()
    expect(screen.getByText("An archive signed with any other key is refused.")).toBeInTheDocument()
  })

  it("opens the compare on Compare and closes it on a second press", async () => {
    await renderInstance()
    expect(compare()).toHaveAttribute("aria-expanded", "false")
    expect(field()).not.toBeInTheDocument()

    fireEvent.click(compare())
    expect(compare()).toHaveAttribute("aria-expanded", "true")
    expect(field()).toBeInTheDocument()
    expect(document.getElementById(compare().getAttribute("aria-controls") ?? "")).toContainElement(field())

    fireEvent.click(compare())
    expect(compare()).toHaveAttribute("aria-expanded", "false")
    expect(field()).not.toBeInTheDocument()
  })

  it("shows the green check when the pasted key matches", async () => {
    await renderInstance()
    fireEvent.click(compare())
    fireEvent.change(field()!, { target: { value: `sha256:${TRUSTED.toUpperCase()}` } })
    expect(field()).toHaveClass("border-ok")
    expect(field()?.parentElement?.querySelector("svg.lucide-circle-check")).not.toBeNull()
    expect(screen.getByRole("status")).toHaveTextContent("Matches the trusted key")
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it("shows the user, the bucket and both folders", async () => {
    await renderInstance()
    const folders = screen.getByRole("heading", { level: 2, name: "Your folders" }).closest("section")!
    const rows = within(folders).getAllByRole("term").map((term) => [term.textContent, term.nextElementSibling?.textContent])
    expect(rows).toEqual([
      ["Signed in as", "lea.martin"],
      ["Bucket", "user-lea.martin"],
      ["npm archives", "packages/npm/"],
      ["pip archives", "packages/pip/"],
    ])
  })

  it("holds the theme choice and no other control", async () => {
    await renderInstance()
    const page = screen.getByRole("main")
    expect(within(page).getByRole("radiogroup", { name: "Theme" })).toBeInTheDocument()
    expect(within(page).getAllByRole("radio").map((r) => r.textContent)).toEqual(["System", "Light", "Dark"])
    expect(within(page).getAllByRole("button")).toEqual([
      within(page).getByRole("button", { name: "Public key sha256 3f9a1c7e…0b1d3f5a" }),
      within(page).getByRole("button", { name: "Copy Public key sha256" }),
      within(page).getByRole("button", { name: "Compare" }),
    ])
    expect(within(page).queryAllByRole("link")).toEqual([])
    expect(within(page).queryAllByRole("textbox")).toEqual([])
  })
})
