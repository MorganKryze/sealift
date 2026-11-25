import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { getInstance, type Instance } from "@/api/settings"
import { type Brand, BrandProvider, DEFAULT_BRAND } from "@/components/frame/brand"
import { PreparingScreen, WhenReady } from "@/components/preparing-screen"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getInstance: vi.fn() }
})

const SHA = "3f1c9a5e7b2d4c60a8e1f3b5d7c9a1e3f5b7d9c1e3a5b7d9f1c3e5a7b9d1f3c5"
const NOW = new Date("2026-11-24T09:30:18Z")
const NEXT_TRY = "2026-11-24T09:31:00Z"
const CAUSE = "vulnerability database download: Get \"https://ghcr.io/v2/\": dial tcp: lookup ghcr.io: no such host"

function instance(preparing: Instance["preparing"], brand: Brand = DEFAULT_BRAND): Instance {
  return {
    ephemeral: false,
    ready: preparing.every((item) => item.state === "ready"),
    preparing,
    brand,
    policy: {
      target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
      pipTarget: { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" },
      minReleaseAgeDays: 14,
      resolveParallelism: 4,
      downloadParallelism: 16,
      review: { proposeOtherMajors: false, majorJump: "reason", cveWithoutFix: "reason" },
    },
    tools: { trivy: "0.76.2", pnpm: [], uv: [] },
  }
}

const preparing: Instance["preparing"] = [
  { name: "trivy", version: "0.76.2", state: "ready" },
  { name: "trivy-db", state: "failed", reason: CAUSE, nextTry: NEXT_TRY },
  { name: "signing-key", version: SHA, state: "ready" },
  { name: "pnpm", version: "10.34.5", state: "preparing" },
  { name: "uv", version: "0.13.7", state: "preparing" },
]

const allReady: Instance["preparing"] = [
  { name: "trivy", version: "0.76.2", state: "ready" },
  { name: "trivy-db", version: "2026-11-24T06:12:00Z", state: "ready" },
  { name: "signing-key", version: SHA, state: "ready" },
  { name: "pnpm", version: "10.34.5", state: "ready" },
  { name: "uv", version: "0.13.7", state: "ready" },
]

const item = (title: RegExp) => screen.getByRole("heading", { name: title }).closest("li") as HTMLElement

function renderScreen(items = preparing, brand: Brand = DEFAULT_BRAND) {
  const page = (next: Instance["preparing"]) => (
    <BrandProvider brand={brand}>
      <PreparingScreen instance={instance(next, brand)} />
    </BrandProvider>
  )
  const view = render(page(items))
  return (next: Instance["preparing"]) => view.rerender(page(next))
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true })
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
  vi.mocked(getInstance).mockReset()
  document.title = ""
})

describe("PreparingScreen", () => {
  it("shows the brand's name, the still mark and its side label and no place", () => {
    const { container } = render(
      <BrandProvider brand={DEFAULT_BRAND}>
        <PreparingScreen instance={instance(preparing)} />
      </BrandProvider>,
    )
    expect(screen.getByText("sealift")).toBeInTheDocument()
    expect(screen.getByText("Online")).toBeInTheDocument()
    expect(container.querySelector("svg[viewBox='0 0 40 40']")).not.toBeNull()
    expect(container.innerHTML).not.toMatch(/animate-(enter|pop|stamp|fade)|mark-lift/)
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 1, name: "Preparing this instance" })).toBeInTheDocument()
  })

  it("shows a deployment's name and logo", () => {
    renderScreen(preparing, { ...DEFAULT_BRAND, name: "Northwind lift", online: "Connected", logo: true })
    expect(screen.getByText("Northwind lift")).toBeInTheDocument()
    expect(screen.getByText("Connected")).toBeInTheDocument()
    expect(document.querySelector("img")).toHaveAttribute("src", "/api/instance/logo")
  })

  it("shows each item's state and a failed item's cause", () => {
    renderScreen()
    expect(screen.getByText("2 of 5 ready")).toBeInTheDocument()
    expect(screen.getByText("1 failed")).toBeInTheDocument()
    expect(within(item(/^Trivy$/)).getByText("Ready")).toBeInTheDocument()
    expect(within(item(/^Trivy$/)).getByText("0.76.2")).toHaveClass("figure")
    expect(within(item(/^CVE database$/)).getByText("Failed")).toBeInTheDocument()
    expect(within(item(/^CVE database$/)).getByText(CAUSE)).toBeInTheDocument()
    expect(within(item(/^Signing key$/)).getByText("Ready")).toBeInTheDocument()
    expect(within(item(/^pnpm$/)).getByText("Preparing")).toBeInTheDocument()
    expect(within(item(/^uv$/)).getByText("Preparing")).toBeInTheDocument()
    expect(item(/^CVE database$/)).toHaveClass("tinted-bad")
    expect(item(/^pnpm$/)).toHaveClass("tinted-info")
    expect(screen.getAllByRole("listitem")).toHaveLength(5)
  })

  it("points to the administrators after a failure only, with no action", () => {
    const rerender = renderScreen()
    expect(screen.getByText("Still failing after a few tries?")).toBeInTheDocument()
    expect(screen.getByText("See your administrators")).toBeInTheDocument()
    rerender(preparing.map((i) => (i.state === "failed" ? { name: i.name, state: "preparing" as const } : i)))
    expect(screen.queryByText("See your administrators")).not.toBeInTheDocument()
  })

  it("shows a failed item's next try as a chip under its cause, the delay in weight 600", async () => {
    renderScreen()
    const db = item(/^CVE database$/)
    const chip = within(db).getByText(/^Next try in/)
    expect(chip).toHaveTextContent("Next try in 42 s")
    expect(within(chip).getByText("42 s")).toHaveClass("figure")
    expect(within(db).getByText(CAUSE).compareDocumentPosition(chip) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(chip).toHaveTextContent("Next try in 40 s")
  })

  it("names a next try that is due in words", () => {
    renderScreen([{ name: "trivy", version: "0.76.2", state: "failed", reason: CAUSE, nextTry: "2026-11-24T09:00:00Z" }])
    expect(within(item(/^Trivy$/)).getByText("Trying again now")).toBeInTheDocument()
  })

  it("shows the signing key's sha256 as a fingerprint", () => {
    renderScreen()
    const key = item(/^Signing key$/)
    expect(within(key).getByRole("button", { name: "Signing key sha256 3f1c9a5e to b9d1f3c5" })).toHaveAttribute("aria-expanded", "false")
    expect(within(key).queryByText(SHA)).not.toBeInTheDocument()
  })

  it("shows a sha256 inside a cause as a fingerprint and the rest as text", () => {
    renderScreen([{ name: "trivy", version: "0.76.2", state: "failed", reason: `trivy archive: sha256 ${SHA} does not match the pinned one` }])
    const row = item(/^Trivy$/)
    expect(within(row).getByRole("button", { name: /^sha256 3f1c9a5e to b9d1f3c5$/ })).toBeInTheDocument()
    expect(row).toHaveTextContent("trivy archive: sha256")
    expect(row).toHaveTextContent("does not match the pinned one")
  })

  it("announces changes in a polite status on a box element", () => {
    const update = renderScreen()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    const status = within(item(/^CVE database$/)).getByRole("status")
    expect(status).toHaveTextContent("Failed")
    expect(status).toHaveTextContent(CAUSE)
    expect(status.className).not.toMatch(/\bcontents\b/)
    expect(status.tagName).toBe("DIV")
    // A countdown inside a live region would speak every second.
    expect(status).not.toHaveTextContent("Next try")

    update(allReady)
    expect(within(item(/^CVE database$/)).getByRole("status")).toBe(status)
    expect(status).toHaveTextContent("CVE database")
    expect(status).toHaveTextContent("Ready")
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })

  it("offers no button", () => {
    renderScreen(preparing.filter((i) => i.name !== "signing-key"))
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
  })

  it("shows a reason that holds markup as text", () => {
    const reason = '<img src="x" onerror="alert(1)"><b>502 Bad Gateway</b>'
    renderScreen([{ name: "trivy", version: "0.76.2", state: "failed", reason }])
    const row = item(/^Trivy$/)
    expect(within(row).getByText(reason)).toBeInTheDocument()
    expect(row.querySelector("img, b")).toBeNull()
  })
})

function renderWhenReady() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <WhenReady>
        <nav aria-label="Places">
          <p>Home</p>
        </nav>
      </WhenReady>
    </QueryClientProvider>,
  )
}

describe("WhenReady", () => {
  it("shows the page asked for once ready", async () => {
    vi.mocked(getInstance).mockResolvedValueOnce(instance(preparing)).mockResolvedValue(instance(allReady))
    renderWhenReady()

    expect(await screen.findByRole("heading", { name: "Preparing this instance" })).toBeInTheDocument()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(await screen.findByText("Home")).toBeInTheDocument()
    expect(screen.queryByRole("heading", { name: "Preparing this instance" })).not.toBeInTheDocument()
    const calls = vi.mocked(getInstance).mock.calls.length

    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000)
    })
    expect(vi.mocked(getInstance).mock.calls.length).toBe(calls)
  })

  it("shows no place before the instance is ready", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance(preparing))
    renderWhenReady()
    expect(await screen.findByRole("heading", { name: "Preparing this instance" })).toBeInTheDocument()
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument()
    expect(screen.queryByText("Home")).not.toBeInTheDocument()
  })

  it("names the page with the deployment's name while it prepares", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance(preparing, { ...DEFAULT_BRAND, name: "Northwind lift" }))
    renderWhenReady()
    await screen.findByRole("heading", { name: "Preparing this instance" })
    expect(document.title).toBe("Northwind lift")
  })

  it("offers a retry when the first answer fails", async () => {
    vi.mocked(getInstance).mockRejectedValueOnce(new Error("network")).mockResolvedValue(instance(preparing))
    renderWhenReady()

    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach the server.")
    fireEvent.click(screen.getByRole("button", { name: "Retry" }))
    expect(await screen.findByRole("heading", { name: "Preparing this instance" })).toBeInTheDocument()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })

  it("says the server is unreachable when a later poll fails", async () => {
    vi.mocked(getInstance).mockResolvedValueOnce(instance(preparing)).mockRejectedValue(new Error("network"))
    renderWhenReady()
    expect(await screen.findByRole("heading", { name: "Preparing this instance" })).toBeInTheDocument()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach the server.")
    expect(screen.queryByText(CAUSE)).not.toBeInTheDocument()
  })

  it("announces that preparation ended", async () => {
    vi.mocked(getInstance).mockResolvedValueOnce(instance(preparing)).mockResolvedValue(instance(allReady))
    renderWhenReady()
    expect(await screen.findByRole("heading", { name: "Preparing this instance" })).toBeInTheDocument()
    const before = screen.getAllByRole("status")

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    await screen.findByText("Home")
    const live = screen.getByRole("status")
    expect(live).toHaveTextContent("sealift is ready.")
    expect(before).toContain(live)
  })
})
