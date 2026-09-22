import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getSettings, updateSettings, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { SetupScreen } from "@/components/setup-screen"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSettings: vi.fn(), updateSettings: vi.fn(), updateTrivy: vi.fn(), updateTrivyDB: vi.fn() }
})

const missing: ToolsState = {
  pnpmInstalled: [],
  trivyActive: "",
  trivyInstalled: [],
  trivyLatest: "0.74.0",
  trivyLatestAge: "912h0m0s",
  trivyDbDate: "0001-01-01T00:00:00Z",
  latestSizeBytes: 45_424_969,
  ready: false,
  missing: ["trivy", "trivy-db", "signature-key"],
}

function renderSetup(onContinue = vi.fn()) {
  const queryClient = new QueryClient()
  function Harness() {
    const { data } = useQuery({ queryKey: ["tools"], queryFn: () => missing, initialData: missing, staleTime: Infinity })
    return <SetupScreen tools={data} onContinue={onContinue} />
  }
  render(
    <QueryClientProvider client={queryClient}>
      <Harness />
    </QueryClientProvider>,
  )
  return onContinue
}

const card = (title: RegExp) => screen.getByRole("heading", { name: title }).closest("[data-tool]") as HTMLElement

beforeEach(() => {
  vi.mocked(getSettings).mockResolvedValue({ target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" }, signatureKey: "", minReleaseAgeDays: 14, resolveParallelism: 4, downloadParallelism: 16 })
})

describe("SetupScreen", () => {
  it("names each tool's version and size before anything installs", () => {
    renderSetup()
    expect(within(card(/Trivy 0.74.0/)).getByText(/Not installed · 43.3 MB/)).toBeInTheDocument()
    expect(within(card(/Vulnerability database/)).getByText(/Not installed · about 120 MB/)).toBeInTheDocument()
  })

  it("shows each tool downloading then ready, and waits for Continue", async () => {
    let finishTrivy: (s: ToolsState) => void = () => {}
    let finishDb: (s: ToolsState) => void = () => {}
    vi.mocked(updateTrivy).mockReturnValue(new Promise((r) => (finishTrivy = r)))
    vi.mocked(updateTrivyDB).mockReturnValue(new Promise((r) => (finishDb = r)))
    const onContinue = renderSetup()

    fireEvent.click(screen.getByRole("button", { name: /^Install Trivy/ }))
    await waitFor(() => expect(within(card(/Trivy/)).getByText("Downloading…")).toBeInTheDocument())

    finishTrivy({ ...missing, trivyActive: "0.74.0", trivyInstalled: ["0.74.0"], missing: ["trivy-db"] })
    await waitFor(() => expect(within(card(/Trivy/)).getByText("Ready")).toBeInTheDocument())
    expect(within(card(/Vulnerability database/)).getByText("Downloading…")).toBeInTheDocument()

    finishDb({ ...missing, trivyActive: "0.74.0", trivyInstalled: ["0.74.0"], trivyDbDate: "2026-09-22T07:00:00Z", ready: true, missing: [] })
    await waitFor(() => expect(screen.getByRole("button", { name: "Continue" })).toBeInTheDocument())
    expect(onContinue).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Continue" }))
    expect(onContinue).toHaveBeenCalledOnce()
  })

  it("saves the key on Enter", async () => {
    vi.mocked(updateSettings).mockResolvedValue({} as never)
    renderSetup()
    await waitFor(() => expect(getSettings).toHaveBeenCalled())
    const input = screen.getByLabelText("Signature key")
    fireEvent.change(input, { target: { value: "a-key" } })
    fireEvent.submit(input)
    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith(expect.objectContaining({ signatureKey: "a-key" })))
  })
})
