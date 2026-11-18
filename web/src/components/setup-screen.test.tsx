import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getSigningKey, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { SetupScreen } from "@/components/setup-screen"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSigningKey: vi.fn(), updateTrivy: vi.fn(), updateTrivyDB: vi.fn() }
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
  missing: ["trivy", "trivy-db"],
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

const SHA = "3f1c9a5e7b2d4c60a8e1f3b5d7c9a1e3f5b7d9c1e3a5b7d9f1c3e5a7b9d1f3c5"

beforeEach(() => {
  vi.mocked(getSigningKey).mockResolvedValue({ publicKeyPem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n", publicKeySha256: SHA })
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

  it("says the key is generated and shows its sha256, with no input", async () => {
    renderSetup()
    const keyCard = card(/^Signing key$/)
    expect(within(keyCard).getByText("Generated on this volume. Carry its public key once to the import side, over a channel you trust.")).toBeInTheDocument()
    expect(await within(keyCard).findByText(SHA)).toBeInTheDocument()
    expect(within(keyCard).getByRole("button", { name: "Copy public key" })).toBeInTheDocument()
    expect(within(keyCard).getByText("Ready")).toBeInTheDocument()
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument()
  })

  it("introduces the generated key", () => {
    renderSetup()
    expect(
      screen.getByText("sealift scans with Trivy and signs the manifest of each archive with a key it generated for this volume. Nothing downloads until you press Install."),
    ).toBeInTheDocument()
  })
})
