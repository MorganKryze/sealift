import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, useRouterState } from "@tanstack/react-router"
import { fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it } from "vitest"

import { type Brand, BrandMark, BrandProvider, contrastRatio, DEFAULT_BRAND, PAGE, SideLabel, usableAccent } from "@/components/frame/brand"
import { Frame } from "@/components/frame/frame"
import { StepBar, stepBarStep } from "@/components/step-bar"
import { ONLINE_INSTANCE, ONLINE_PLACES, onlineCrumbs } from "@/lib/places"

// Vitest empties every .css import, ?raw included, so the theme is read from disk, as theme.test.ts does.
type Node = { process: { getBuiltinModule(id: "node:fs"): { readFileSync(path: string, encoding: "utf8"): string } } }
const { readFileSync } = (globalThis as unknown as Node).process.getBuiltinModule("node:fs")
const theme = readFileSync(`${(import.meta as ImportMeta & { dirname: string }).dirname}/../../styles/theme.css`, "utf8")

// The --bg of each theme, comments dropped: the light one in :root, the dark one in .dark and in the system dark block.
function pageColours(css: string) {
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, "")
  const values = (selector: RegExp) => [...bare.matchAll(selector)].map((m) => /--bg:\s*([^;]+);/.exec(m[1])?.[1].trim())
  return {
    light: values(/(?:^|\})\s*:root\s*\{([^}]*)\}/g),
    dark: [...values(/\.dark\s*\{([^}]*)\}/g), ...values(/:root:not\(\.light\):not\(\.dark\)\s*\{([^}]*)\}/g)],
  }
}

const WARNING = "CVE database refresh failed: dial tcp: lookup ghcr.io: no such host. The database of 22 Nov stays in use."

const BRANDED: Brand = { name: "Northwind lift", online: "Connected", offline: "Isolated", reviewWord: "MR", logo: true }

async function renderAt(path: string, { brand = DEFAULT_BRAND, warning, projectName }: { brand?: Brand; warning?: string; projectName?: string } = {}) {
  const root = createRootRoute({
    component: function Root() {
      const pathname = useRouterState({ select: (s) => s.location.pathname })
      return (
        <BrandProvider brand={brand}>
          <Frame side="online" places={ONLINE_PLACES} instance={ONLINE_INSTANCE} instanceWarning={warning} crumbs={onlineCrumbs(pathname, projectName)}>
            <Outlet />
          </Frame>
        </BrandProvider>
      )
    },
  })
  const page = (p: string) => createRoute({ getParentRoute: () => root, path: p, component: () => <p>page {p}</p> })
  const router = createRouter({
    routeTree: root.addChildren([page("/"), page("/instance"), page("/sessions/$sessionId/analysis")]),
    history: createMemoryHistory({ initialEntries: [path] }),
  })
  const view = render(<RouterProvider router={router} />)
  await screen.findByText(/^page /)
  return view
}

const places = () => screen.getByRole("navigation", { name: "Places" })
const placeLink = (name: string) => within(places()).getByRole("link", { name: new RegExp(`^${name}`) })

afterEach(() => {
  document.documentElement.style.removeProperty("--brand-light")
  document.documentElement.style.removeProperty("--brand-dark")
  document.title = ""
})

describe("PAGE", () => {
  it("holds the page colours the theme paints, so the accent check measures against the real page", () => {
    const { light, dark } = pageColours(theme)
    expect(light).toEqual([PAGE.light])
    expect(dark).toEqual([PAGE.dark, PAGE.dark])
  })
})

describe("Frame", () => {
  it("puts the breadcrumb at the left and the side label at the right, nothing else", async () => {
    await renderAt("/")
    const bar = screen.getByRole("banner")
    expect(bar.children).toHaveLength(2)
    expect(bar.children[0]).toBe(within(bar).getByRole("navigation", { name: "Breadcrumb" }))
    expect(bar.children[1]).toHaveTextContent(/^Online$/)
    expect(within(bar).queryAllByRole("button")).toEqual([])
  })

  it("marks the current place with aria-current and keeps Instance at the bottom", async () => {
    await renderAt("/")
    expect(placeLink("Home")).toHaveAttribute("aria-current", "page")
    expect(placeLink("Instance")).not.toHaveAttribute("aria-current")
    const links = within(places()).getAllByRole("link")
    expect(links.map((l) => l.textContent)).toEqual(["Home", "Projects", "Instance"])
    expect(placeLink("Instance")).toHaveAttribute("href", "/instance")
  })

  it("marks Instance as the current place on its own page and Home on a session's", async () => {
    const view = await renderAt("/instance")
    expect(placeLink("Instance")).toHaveAttribute("aria-current", "page")
    expect(placeLink("Home")).not.toHaveAttribute("aria-current")
    view.unmount()
    await renderAt("/sessions/demo/analysis", { projectName: "web-portal" })
    expect(placeLink("Home")).toHaveAttribute("aria-current", "page")
  })

  it("draws the current place's icon in the brand colour and no other", async () => {
    await renderAt("/")
    expect(placeLink("Home").querySelector("svg")).toHaveClass("text-brand")
    expect(placeLink("Instance").querySelector("svg")).not.toHaveClass("text-brand")
  })

  it("marks Instance with an amber chip whose tooltip gives the warning, by hover and keyboard", async () => {
    await renderAt("/", { warning: WARNING })
    const instance = placeLink("Instance")
    expect(instance).toHaveAccessibleDescription(WARNING)
    expect(instance.querySelector(".tinted-warn svg.lucide-triangle-alert")).not.toBeNull()
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument()

    fireEvent.mouseEnter(instance)
    expect(screen.getByRole("tooltip")).toHaveTextContent(WARNING)
    fireEvent.mouseLeave(instance)
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument()

    fireEvent.focus(instance)
    expect(screen.getByRole("tooltip")).toHaveTextContent(WARNING)
    fireEvent.keyDown(instance, { key: "Escape" })
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument()
  })

  it("draws no chip on Instance without a warning", async () => {
    await renderAt("/")
    expect(placeLink("Instance").querySelector(".tinted-warn")).toBeNull()
    expect(placeLink("Instance")).not.toHaveAccessibleDescription()
  })

  it("offers a skip link first", async () => {
    await renderAt("/")
    const first = screen.getAllByRole("link")[0]
    expect(first).toHaveTextContent("Skip to content")
    expect(first).toHaveAttribute("href", "#content")
    expect(screen.getByRole("main")).toHaveAttribute("id", "content")
  })

  it("marks the last crumb", async () => {
    const view = await renderAt("/")
    const home = within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByText("Home")
    expect(home).toHaveAttribute("aria-current", "page")
    view.unmount()

    await renderAt("/sessions/demo/analysis", { projectName: "web-portal" })
    const crumbs = within(screen.getByRole("navigation", { name: "Breadcrumb" })).getAllByRole("listitem")
    expect(crumbs.map((c) => c.textContent)).toEqual(["Home", "web-portal"])
    expect(within(crumbs[0]).getByRole("link", { name: "Home" })).toHaveAttribute("href", "/")
    expect(within(crumbs[1]).getByText("web-portal")).toHaveAttribute("aria-current", "page")
    expect(within(crumbs[1]).queryByRole("link")).not.toBeInTheDocument()
  })

  it("shows the deployment's name in the title, its logo and its side label", async () => {
    await renderAt("/", { brand: BRANDED })
    expect(document.title).toBe("Northwind lift")
    expect(within(places()).getByRole("presentation")).toHaveAttribute("src", "/api/instance/logo")
    expect(screen.getByRole("banner").lastElementChild).toHaveTextContent(/^Connected$/)
    expect(screen.queryByText("Online")).not.toBeInTheDocument()
  })

  it("falls back to the default mark and labels", async () => {
    await renderAt("/")
    expect(document.title).toBe("sealift")
    expect(places().querySelector("img")).toBeNull()
    expect(places().querySelector("svg[viewBox='0 0 40 40']")).not.toBeNull()
    expect(screen.getByRole("banner").querySelector("svg.lucide-globe")).not.toBeNull()

    render(<SideLabel side="offline" />)
    const offline = screen.getByText("Offline").parentElement as HTMLElement
    expect(offline.querySelector("svg.lucide-unplug")).not.toBeNull()
  })

  it("draws today's mark in the ink", () => {
    const { container } = render(<BrandMark size={28} />)
    const paints = [...container.querySelectorAll("svg *")].flatMap((el) => [el.getAttribute("fill"), el.getAttribute("stroke")]).filter((p) => p && p !== "none")
    expect(paints.length).toBeGreaterThan(0)
    expect(new Set(paints)).toEqual(new Set(["var(--ink)", "var(--accent)", "var(--background)"]))
    expect(theme).toMatch(/--accent:\s*var\(--ink\);/)
    expect(theme).toMatch(/--background:\s*var\(--bg\);/)
    // Still: nothing on the mark or its wrapper moves.
    expect(container.innerHTML).not.toMatch(/animate-/)
    expect(container.firstElementChild).toHaveAttribute("aria-hidden", "true")
  })

  it("draws the logo as an image from the instance's address", () => {
    const { container } = render(
      <BrandProvider brand={BRANDED}>
        <BrandMark size={28} />
      </BrandProvider>,
    )
    const img = container.querySelector("img") as HTMLImageElement
    expect(img).toHaveAttribute("src", "/api/instance/logo")
    expect(img).toHaveAttribute("alt", "")
    expect(container.querySelector("svg")).toBeNull()
    expect(sources["/src/components/frame/brand.tsx"]).not.toMatch(/dangerouslySetInnerHTML|fetch\(/)
  })

  it("uses the accent only where it reaches 3:1", () => {
    const light = usableAccent("#facc15", "#ffffff")
    expect(light.color).toBeNull()
    expect(light.ratio).toBeLessThan(3)
    const dark = usableAccent("#facc15", "#111113")
    expect(dark.color).toBe("#facc15")
    expect(dark.ratio).toBeGreaterThanOrEqual(3)
    expect(usableAccent(undefined, "#ffffff").color).toBeNull()
    expect(usableAccent("red; background: url(x)", "#ffffff").color).toBeNull()

    const view = render(<BrandProvider brand={{ ...DEFAULT_BRAND, accent: "#facc15" }}>page</BrandProvider>)
    const root = document.documentElement.style
    expect(root.getPropertyValue("--brand-light")).toBe("")
    expect(root.getPropertyValue("--brand-dark")).toBe("#facc15")
    view.unmount()
    expect(root.getPropertyValue("--brand-dark")).toBe("")
  })

  it("gives a ratio of 21 for black on white and 1 for one colour", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5)
    expect(contrastRatio("#ffffff", "#000000")).toBeCloseTo(21, 5)
    expect(contrastRatio("#0b6e99", "#0b6e99")).toBe(1)
  })
})

const sources = import.meta.glob(["/src/**/*.{ts,tsx}", "!/src/**/*.test.{ts,tsx}", "!/src/**/*.d.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>

describe("the brand module", () => {
  it("no source file outside the brand module holds a side label, the review word or the contact", () => {
    const literal = /["'`>]\s*(Online|Offline|PR|MR)\s*["'`<]|See your administrators|mailto:/
    const holders = Object.entries(sources)
      .filter(([, text]) => literal.test(text))
      .map(([file]) => file)
    expect(Object.keys(sources).length).toBeGreaterThan(50)
    expect(holders).toEqual(["/src/components/frame/brand.tsx"])
  })

  it("no screen of the frame names the product but through the brand", () => {
    const screens = Object.entries(sources).filter(
      ([file]) =>
        (file.startsWith("/src/components/frame/") && file !== "/src/components/frame/brand.tsx") ||
        file === "/src/lib/places.ts" ||
        file === "/src/components/preparing-screen.tsx",
    )
    expect(screens.map(([file]) => file).sort()).toEqual(["/src/components/frame/frame.tsx", "/src/components/preparing-screen.tsx", "/src/lib/places.ts"])
    expect(screens.filter(([, text]) => /sealift/i.test(text)).map(([file]) => file)).toEqual([])
  })
})

describe("StepBar", () => {
  const steps = [
    stepBarStep("drop", "done", false, () => {}),
    stepBarStep("analysis", "available", true),
    stepBarStep("review", "upcoming", false),
    stepBarStep("export", "upcoming", false),
  ]

  it("numbers each step and marks the current one with aria-current step", () => {
    render(<StepBar steps={[stepBarStep("drop", "available", true), ...steps.slice(1).map((s) => ({ ...s, current: false }))]} />)
    const items = [...screen.getByRole("navigation", { name: "Session steps" }).querySelectorAll("[data-step]")]
    expect(items.map((i) => i.textContent)).toEqual(["1Drop", "2Analyse", "3Review", "4Export"])
    expect(screen.getByText("Drop").closest("[aria-current]")).toHaveAttribute("aria-current", "step")
    expect(document.querySelectorAll("[aria-current]")).toHaveLength(1)
  })

  it("shows a done step with a check and keeps the current one marked", () => {
    render(<StepBar steps={steps} />)
    expect(screen.getByRole("button", { name: /Drop/ }).querySelector("svg.lucide-check")).not.toBeNull()
    expect(screen.getByText("Analyse").closest("[aria-current]")).toHaveAttribute("aria-current", "step")
  })

  it("fills the step line with a transform", () => {
    const { container } = render(<StepBar steps={steps} />)
    const fills = [...container.querySelectorAll<HTMLElement>("[data-step-fill]")]
    expect(fills.map((f) => f.style.transform)).toEqual(["scaleX(1)", "scaleX(0)", "scaleX(0)"])
    for (const f of fills) {
      expect(f).toHaveClass("transition-transform")
      expect(f.style.width).toBe("")
    }
  })
})
