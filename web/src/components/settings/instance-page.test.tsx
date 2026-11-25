import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router"
import { render, screen, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getInstance, getSigningKey, type Instance } from "@/api/settings"
import { InstancePage } from "@/components/settings/instance-page"
import { dbDateTitle, formatDbDate } from "@/lib/format-tools"
import { routeTree } from "@/routeTree.gen"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getInstance: vi.fn(), getSigningKey: vi.fn() }
})

const SHA = "3f9a1c7e0b2d4f6a8c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5a"
const DB_DATE = "2026-11-22T06:12:00Z"
const WARNING = "could not refresh the vulnerability database: dial tcp: lookup ghcr.io: no such host; using the database from 2026-11-22"

const INSTANCE: Instance = {
  ephemeral: false,
  ready: true,
  preparing: [
    { name: "trivy", state: "ready", version: "0.76.2" },
    { name: "trivy-db", state: "ready", version: DB_DATE },
    { name: "signing-key", state: "ready", version: SHA },
    { name: "pnpm", state: "ready", version: "10.34.5" },
    { name: "uv", state: "ready", version: "0.13.7" },
  ],
  brand: { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false },
  policy: {
    target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
    pipTarget: { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" },
    minReleaseAgeDays: 14,
    resolveParallelism: 4,
    downloadParallelism: 16,
    review: { proposeOtherMajors: false, majorJump: "reason", cveWithoutFix: "refuse" },
  },
  tools: { trivy: "0.76.2", trivyDbDate: DB_DATE, pnpm: ["10.34.5"], uv: ["0.13.7"] },
}

const client = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })

async function renderPage(instance: Instance = INSTANCE) {
  const view = render(
    <QueryClientProvider client={client()}>
      <InstancePage instance={instance} />
    </QueryClientProvider>,
  )
  await screen.findByRole("button", { name: "Public key sha256 3f9a1c7e to 0b1d3f5a" })
  return view
}

const region = (name: string) => screen.getByRole("region", { name })

beforeEach(() => {
  vi.mocked(getInstance).mockReset().mockResolvedValue(INSTANCE)
  vi.mocked(getSigningKey).mockReset().mockResolvedValue({ publicKeyPem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n", publicKeySha256: SHA })
  localStorage.clear()
})

describe("InstancePage", () => {
  it("shows each readiness item with its version in weight 600 and the database's date", async () => {
    await renderPage()
    const ready = region("Ready")
    for (const [title, figure] of [
      ["Trivy", "0.76.2"],
      ["pnpm", "10.34.5"],
      ["uv", "0.13.7"],
    ]) {
      const item = within(ready).getByRole("heading", { name: title }).closest("li") as HTMLElement
      expect(within(item).getByText(figure)).toHaveClass("figure")
    }
    const db = within(ready).getByRole("heading", { name: "CVE database" }).closest("li") as HTMLElement
    const age = within(db).getByText(formatDbDate(DB_DATE))
    expect(age.closest("p")).toHaveTextContent(`Updated ${formatDbDate(DB_DATE)}`)
    expect(age).toHaveAttribute("title", dbDateTitle(DB_DATE))
    expect(age).toHaveClass("font-semibold")
    expect(within(ready).getByRole("heading", { level: 2, name: "Ready" })).toBeInTheDocument()
    expect(within(ready).getByRole("heading", { level: 3, name: "Signing key" })).toBeInTheDocument()
    expect(within(ready).getByText("5 items ready")).toBeInTheDocument()
  })

  it("says under each ready tool the check it passed before it was installed", async () => {
    await renderPage()
    const ready = region("Ready")
    for (const [title, proof] of [
      ["Trivy", "sha256 matches the pinned release"],
      ["pnpm", "Integrity matches the npm registry"],
      ["uv", "sha256 matches the package index"],
    ]) {
      const item = within(ready).getByRole("heading", { name: title }).closest("li") as HTMLElement
      expect(within(item).getByText(proof)).toBeInTheDocument()
    }
  })

  it("shows a database warning as a closed amber row", async () => {
    await renderPage({ ...INSTANCE, warning: WARNING })
    const row = screen.getByText(WARNING).closest("li")
    expect(row).toHaveClass("tinted-warn")
    expect(row).toHaveTextContent("CVE database")
    expect(within(region("Ready")).getByText("4 items ready")).toBeInTheDocument()
    expect(within(region("Ready")).getByText("1 warning")).toHaveClass("tinted-warn")
  })

  it("counts a warning only on the database row it marks", async () => {
    const preparing = INSTANCE.preparing.map((item) => (item.name === "trivy-db" ? { name: "trivy-db" as const, state: "preparing" as const } : item))
    await renderPage({ ...INSTANCE, preparing, warning: WARNING })
    expect(within(region("Ready")).getByText("4 items ready")).toBeInTheDocument()
    expect(within(region("Ready")).queryByText("1 warning")).toBeNull()
  })

  it("shows ephemeral mode and its idle delay", async () => {
    await renderPage({ ...INSTANCE, ephemeral: true, idleMinutes: 30 })
    const policy = region("Policy")
    expect(within(policy).getByText("30 minutes")).toHaveClass("figure")
    expect(within(policy).getByText("Ephemeral mode")).toBeInTheDocument()
    expect(policy).toHaveTextContent("Erased with their caches after 30 minutes without activity")
  })

  it("shows the policy with no input, select or button", async () => {
    await renderPage({ ...INSTANCE, ephemeral: true, idleMinutes: 1 })
    const policy = region("Policy")
    expect(policy).toHaveTextContent("Set at deploy")
    expect(policy.querySelector("input, select, textarea, button, form, [role=button], [contenteditable]")).toBeNull()
  })

  it("holds the theme choice", async () => {
    await renderPage()
    const appearance = region("Appearance")
    expect(within(appearance).getByRole("radiogroup", { name: "Theme" })).toBeInTheDocument()
    expect(within(appearance).getByRole("radio", { name: "System" })).toHaveAttribute("aria-checked", "true")
    expect(within(appearance).getByText("This browser only")).toBeInTheDocument()
    expect(within(appearance).queryByText("Accent")).not.toBeInTheDocument()
  })

  it("names the theme and the ratio where the accent falls short", async () => {
    await renderPage({ ...INSTANCE, brand: { ...INSTANCE.brand, accent: "#1d4ed8" } })
    const appearance = region("Appearance")
    expect(within(appearance).getByText("#1d4ed8")).toBeInTheDocument()
    expect(appearance).toHaveTextContent("Light 6.7:1")
    expect(within(appearance).getByText("Dark 2.8:1, under 3:1").closest(".tinted-warn")).not.toBeNull()
    expect(within(appearance).getByText("Dark shows the ink in its place.")).toBeInTheDocument()
  })

  it("the settings address shows Instance", async () => {
    const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/settings"] }) })
    render(
      <QueryClientProvider client={client()}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    )
    expect(await screen.findByRole("heading", { level: 1, name: "Instance" })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe("/instance")
    expect(within(screen.getByRole("navigation", { name: "Places" })).getByRole("link", { name: /^Instance/ })).toHaveAttribute("aria-current", "page")
  })

  it("shows no fact twice", async () => {
    const { container } = await renderPage({ ...INSTANCE, ephemeral: true, idleMinutes: 30 })
    const text = container.textContent ?? ""
    const count = (fact: string) => text.split(fact).length - 1
    for (const fact of ["0.76.2", formatDbDate(DB_DATE), "3f9a1c7e", "10.34.5", "0.13.7", "22.17.1", "3.11.2", "30 minutes", "14 days"]) {
      expect(count(fact), fact).toBe(1)
    }
  })
})
