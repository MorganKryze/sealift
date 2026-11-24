import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { getInstance, type Instance } from "@/api/settings"
import { PreparingScreen, WhenReady } from "@/components/preparing-screen"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getInstance: vi.fn() }
})

const SHA = "3f1c9a5e7b2d4c60a8e1f3b5d7c9a1e3f5b7d9c1e3a5b7d9f1c3e5a7b9d1f3c5"
const NEXT_TRY = "2026-11-24T09:31:00Z"
const CAUSE = "vulnerability database download: Get \"https://ghcr.io/v2/\": dial tcp: lookup ghcr.io: no such host"

function instance(preparing: Instance["preparing"]): Instance {
  return {
    ephemeral: false,
    ready: preparing.every((item) => item.state === "ready"),
    preparing,
    brand: { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false },
    policy: {
      target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
      pipTarget: { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" },
      minReleaseAgeDays: 14,
      resolveParallelism: 4,
      downloadParallelism: 16,
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

function renderScreen(items = preparing) {
  const view = render(<PreparingScreen instance={instance(items)} />)
  return (next: Instance["preparing"]) => view.rerender(<PreparingScreen instance={instance(next)} />)
}

afterEach(() => {
  vi.useRealTimers()
  vi.mocked(getInstance).mockReset()
})

describe("PreparingScreen", () => {
  it("lists each item with its state", () => {
    renderScreen()
    expect(screen.getByRole("heading", { level: 1, name: "Preparing sealift" })).toBeInTheDocument()
    expect(within(item(/^Trivy 0.76.2$/)).getByText("Ready")).toBeInTheDocument()
    expect(within(item(/^Vulnerability database$/)).getByText("Failed")).toBeInTheDocument()
    expect(within(item(/^Signing key$/)).getByText("Ready")).toBeInTheDocument()
    expect(within(item(/^Signing key$/)).getByText(SHA)).toBeInTheDocument()
    expect(within(item(/^pnpm 10.34.5$/)).getByText("Preparing")).toBeInTheDocument()
    expect(within(item(/^uv 0.13.7$/)).getByText("Preparing")).toBeInTheDocument()
    expect(screen.getAllByRole("listitem")).toHaveLength(5)
  })

  it("shows a failed item's cause and its next try", () => {
    renderScreen()
    const db = item(/^Vulnerability database$/)
    expect(within(db).getByText(CAUSE)).toBeInTheDocument()
    expect(within(db).getByText(`Next try at ${new Date(NEXT_TRY).toLocaleTimeString()}.`)).toBeInTheDocument()
  })

  it("offers no button", () => {
    renderScreen()
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
  })

  it("announces changes in a polite status", () => {
    const update = renderScreen()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    const status = within(item(/^Vulnerability database$/)).getByRole("status")
    expect(status).toHaveTextContent("Failed")

    update(allReady)
    // The same node carries the change, so a screen reader hears it once.
    expect(within(item(/^Vulnerability database$/)).getByRole("status")).toBe(status)
    expect(status).toHaveTextContent("Vulnerability database: Ready")
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })

  it("puts a failed item's cause and next try in its status", () => {
    renderScreen()
    const status = within(item(/^Vulnerability database$/)).getByRole("status")
    expect(status).toHaveTextContent(CAUSE)
    expect(status).toHaveTextContent(`Next try at ${new Date(NEXT_TRY).toLocaleTimeString()}.`)
  })

  it("shows a reason that holds markup as text", () => {
    const reason = '<img src="x" onerror="alert(1)"><b>502 Bad Gateway</b>'
    renderScreen([{ name: "trivy", version: "0.76.2", state: "failed", reason }])
    const row = item(/^Trivy 0.76.2$/)
    expect(within(row).getByText(reason)).toBeInTheDocument()
    expect(row.querySelector("img, b")).toBeNull()
  })
})

function renderWhenReady() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <WhenReady>
        <p>Home</p>
      </WhenReady>
    </QueryClientProvider>,
  )
}

describe("WhenReady", () => {
  it("shows the children once the instance is ready", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.mocked(getInstance).mockResolvedValueOnce(instance(preparing)).mockResolvedValue(instance(allReady))
    render(
      <QueryClientProvider client={new QueryClient()}>
        <WhenReady>
          <p>Home</p>
        </WhenReady>
      </QueryClientProvider>,
    )

    expect(await screen.findByRole("heading", { name: "Preparing sealift" })).toBeInTheDocument()
    expect(screen.queryByText("Home")).not.toBeInTheDocument()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(await screen.findByText("Home")).toBeInTheDocument()
    expect(screen.queryByRole("heading", { name: "Preparing sealift" })).not.toBeInTheDocument()
    const calls = vi.mocked(getInstance).mock.calls.length

    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000)
    })
    expect(vi.mocked(getInstance).mock.calls.length).toBe(calls)
  })

  it("offers a retry when the first answer fails", async () => {
    vi.mocked(getInstance).mockRejectedValueOnce(new Error("network")).mockResolvedValue(instance(preparing))
    renderWhenReady()

    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach sealift.")
    fireEvent.click(screen.getByRole("button", { name: "Retry" }))
    expect(await screen.findByRole("heading", { name: "Preparing sealift" })).toBeInTheDocument()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })

  it("says sealift is unreachable when a later poll fails", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.mocked(getInstance).mockResolvedValueOnce(instance(preparing)).mockRejectedValue(new Error("network"))
    renderWhenReady()
    expect(await screen.findByRole("heading", { name: "Preparing sealift" })).toBeInTheDocument()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach sealift.")
    expect(screen.queryByText(CAUSE)).not.toBeInTheDocument()
  })

  it("announces that preparation ended", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.mocked(getInstance).mockResolvedValueOnce(instance(preparing)).mockResolvedValue(instance(allReady))
    renderWhenReady()
    expect(await screen.findByRole("heading", { name: "Preparing sealift" })).toBeInTheDocument()
    const before = screen.getAllByRole("status")

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    await screen.findByText("Home")
    const live = screen.getByRole("status")
    expect(live).toHaveTextContent("sealift is ready.")
    // Mounted while preparing, so the change is announced.
    expect(before).toContain(live)
  })
})
