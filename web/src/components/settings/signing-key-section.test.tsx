import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { getSigningKey, regenerateSigningKey, type SigningKey } from "@/api/settings"
import { SigningKeySection } from "@/components/settings/signing-key-section"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSigningKey: vi.fn(), regenerateSigningKey: vi.fn() }
})

const PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAd9mqJUcpQsF4bTjHGXI2m1pL0nmRBGbm8CjQy2bJXcg=\n-----END PUBLIC KEY-----\n"
const SHA = "3f9a1c7e0b2d4f6a8c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5a"
const key: SigningKey = { publicKeyPem: PEM, publicKeySha256: SHA }
const COMMAND = "sealift signing-key regenerate"

function renderSection() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SigningKeySection />
    </QueryClientProvider>,
  )
}

const fingerprint = () => screen.findByRole("button", { name: "Public key sha256 3f9a1c7e…0b1d3f5a" })

beforeEach(() => {
  vi.mocked(getSigningKey).mockReset().mockResolvedValue(key)
  vi.mocked(regenerateSigningKey).mockReset()
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("SigningKeySection", () => {
  it("shows the public key as a fingerprint with its download", async () => {
    const createObjectURL = vi.fn().mockReturnValue("blob:sealift")
    const revokeObjectURL = vi.fn()
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }))
    const names: string[] = []
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      names.push(`${this.download} ${this.href}`)
    })
    renderSection()

    expect(screen.getByRole("heading", { name: "Signing key" })).toBeInTheDocument()
    expect(screen.getByText("Ed25519")).toBeInTheDocument()
    const button = await fingerprint()
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText(/BEGIN PUBLIC KEY/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Copy Public key sha256" }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(SHA))

    fireEvent.click(screen.getByRole("button", { name: "Download public key" }))
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(await blob.text()).toBe(PEM)
    expect(names).toEqual(["sealift-public-key.pem blob:sealift"])
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:sealift")
    click.mockRestore()
  })

  it("keeps How to regenerate closed until pressed", async () => {
    renderSection()
    await fingerprint()
    expect(screen.getByRole("button", { name: "How to regenerate" })).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText(COMMAND)).not.toBeInTheDocument()
    expect(screen.queryByText("In the container or pod")).not.toBeInTheDocument()
  })

  it("shows where to run the command and the command with a copy control once pressed", async () => {
    renderSection()
    await fingerprint()
    const toggle = screen.getByRole("button", { name: "How to regenerate" })
    fireEvent.click(toggle)

    expect(toggle).toHaveAttribute("aria-expanded", "true")
    expect(document.getElementById(toggle.getAttribute("aria-controls") ?? "")).toHaveTextContent(`In the container or pod${COMMAND}`)
    fireEvent.click(screen.getByRole("button", { name: "Copy command" }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(COMMAND))

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText(COMMAND)).not.toBeInTheDocument()
  })

  it("offers no control that changes the key", async () => {
    renderSection()
    await fingerprint()
    fireEvent.click(screen.getByRole("button", { name: "How to regenerate" }))

    const names = screen.getAllByRole("button").map((b) => b.getAttribute("aria-label") ?? b.querySelector(".sr-only")?.textContent ?? b.textContent)
    expect(names).toEqual(["Download public key", "Public key sha256 3f9a1c7e…0b1d3f5a", "Copy Public key sha256", "How to regenerate", "Copy command"])
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
    expect(document.querySelector("input, select, textarea, form")).toBeNull()
    expect(regenerateSigningKey).not.toHaveBeenCalled()
  })

  it("names a key that cannot be loaded", async () => {
    vi.mocked(getSigningKey).mockRejectedValue(new Error("boom"))
    renderSection()
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load the signing key: boom")
  })
})
