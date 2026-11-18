import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { getSigningKey, regenerateSigningKey, type SigningKey } from "@/api/settings"
import { SigningKeySection } from "@/components/settings/signing-key-section"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSigningKey: vi.fn(), regenerateSigningKey: vi.fn() }
})

const PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAd9mqJUcpQsF4bTjHGXI2m1pL0nmRBGbm8CjQy2bJXcg=\n-----END PUBLIC KEY-----\n"
const SHA = "a".repeat(64)
const key: SigningKey = { publicKeyPem: PEM, publicKeySha256: SHA }
const newKey: SigningKey = { publicKeyPem: PEM.replace("d9mq", "xxxx"), publicKeySha256: "b".repeat(64) }

function renderSection() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SigningKeySection />
    </QueryClientProvider>,
  )
}

async function opened() {
  renderSection()
  await screen.findByRole("heading", { name: "Signing key" })
  await screen.findByText(SHA)
  fireEvent.click(screen.getByRole("button", { name: "Regenerate key" }))
  return screen.getByRole("alertdialog", { name: "Regenerate the signing key" })
}

beforeEach(() => {
  vi.mocked(getSigningKey).mockReset().mockResolvedValue(key)
  vi.mocked(regenerateSigningKey).mockReset().mockResolvedValue(newKey)
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("SigningKeySection", () => {
  it("shows the public key and its sha256 in full, with the description and the private key line", async () => {
    renderSection()
    expect(await screen.findByRole("heading", { name: "Signing key" })).toBeInTheDocument()
    expect(
      screen.getByText("sealift signs the manifest of every archive with this key. The import side checks each signature with the public key below."),
    ).toBeInTheDocument()
    const pem = await screen.findByRole("group", { name: "Public key" })
    expect(pem.textContent).toContain("-----BEGIN PUBLIC KEY-----")
    expect(pem.textContent).toContain("MCowBQYDK2VwAyEAd9mqJUcpQsF4bTjHGXI2m1pL0nmRBGbm8CjQy2bJXcg=")
    const sha = screen.getByRole("group", { name: "Public key sha256" })
    expect(sha).toHaveTextContent(SHA)
    expect(screen.getByText("Compare it by eye with the one the import side shows before your first crossing.")).toBeInTheDocument()
    expect(screen.getByText("The private key stays in this sealift's data volume. No screen or API shows it.")).toBeInTheDocument()
  })

  it("wraps the key and the sha256 instead of scrolling sideways", async () => {
    renderSection()
    const pem = await screen.findByRole("group", { name: "Public key" })
    expect(pem.querySelector("pre")?.className).toContain("[overflow-wrap:anywhere]")
    expect(within(screen.getByRole("group", { name: "Public key sha256" })).getByText(SHA).className).toContain("[overflow-wrap:anywhere]")
  })

  it("copies the public key and the sha256", async () => {
    renderSection()
    await screen.findByText(SHA)
    fireEvent.click(screen.getByRole("button", { name: "Copy public key" }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(PEM))
    fireEvent.click(screen.getByRole("button", { name: "Copy public key sha256" }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(SHA))
  })

  it("keeps the copy fallback when there is no clipboard", async () => {
    vi.stubGlobal("navigator", { ...navigator, clipboard: undefined })
    renderSection()
    await screen.findByText(SHA)
    fireEvent.click(screen.getByRole("button", { name: "Copy public key sha256" }))
    expect(await screen.findByRole("textbox", { name: "Text of public key sha256" })).toHaveValue(SHA)
  })

  it("downloads the PEM as sealift-public-key.pem through an object URL", async () => {
    const createObjectURL = vi.fn().mockReturnValue("blob:sealift")
    const revokeObjectURL = vi.fn()
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }))
    const names: string[] = []
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      names.push(`${this.download} ${this.href}`)
    })
    renderSection()
    await screen.findByText(SHA)
    fireEvent.click(screen.getByRole("button", { name: "Download public key" }))

    expect(createObjectURL).toHaveBeenCalledTimes(1)
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(await blob.text()).toBe(PEM)
    expect(names).toEqual(["sealift-public-key.pem blob:sealift"])
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:sealift")
    click.mockRestore()
  })

  it("asks before regenerating, with the screen's words, and moves focus into the dialog", async () => {
    const dialog = await opened()
    expect(within(dialog).getByText("Regenerate the signing key?")).toBeInTheDocument()
    expect(
      within(dialog).getByText(
        "The import side refuses every new archive until it holds the new public key. Archives you already exported stay signed with the current key, which the import refuses once it trusts the new one.",
      ),
    ).toBeInTheDocument()
    expect(within(dialog).getByRole("button", { name: "Regenerate" })).toBeInTheDocument()
    expect(within(dialog).getByRole("button", { name: "Keep the current key" })).toBeInTheDocument()
    expect(dialog).toContainElement(document.activeElement as HTMLElement)
    expect(regenerateSigningKey).not.toHaveBeenCalled()
  })

  it("keeps the key and gives focus back to Regenerate key on Keep the current key", async () => {
    const dialog = await opened()
    fireEvent.click(within(dialog).getByRole("button", { name: "Keep the current key" }))
    expect(screen.queryByRole("alertdialog")).toBeNull()
    expect(screen.getByRole("button", { name: "Regenerate key" })).toHaveFocus()
    expect(regenerateSigningKey).not.toHaveBeenCalled()
  })

  it("keeps the key on Escape and gives focus back to Regenerate key", async () => {
    const dialog = await opened()
    fireEvent.keyDown(dialog, { key: "Escape" })
    expect(screen.queryByRole("alertdialog")).toBeNull()
    expect(screen.getByRole("button", { name: "Regenerate key" })).toHaveFocus()
    expect(regenerateSigningKey).not.toHaveBeenCalled()
    expect(screen.getByText(SHA)).toBeInTheDocument()
  })

  it("shows the new key and the notice in place after a regenerate", async () => {
    const dialog = await opened()
    vi.mocked(getSigningKey).mockResolvedValue(newKey)
    fireEvent.click(within(dialog).getByRole("button", { name: "Regenerate" }))

    expect(await screen.findByText("b".repeat(64))).toBeInTheDocument()
    expect(screen.queryByText(SHA)).toBeNull()
    expect(screen.getByRole("status")).toHaveTextContent("New key in use. Carry its public key to the import side before your next crossing.")
    expect(screen.queryByRole("alertdialog")).toBeNull()
    expect(screen.getByRole("button", { name: "Regenerate key" })).toHaveFocus()
    expect(regenerateSigningKey).toHaveBeenCalledTimes(1)
  })

  it("shows the cause and keeps showing the old key when the regenerate fails", async () => {
    vi.mocked(regenerateSigningKey).mockRejectedValue(
      new ProblemError(500, { type: "about:blank", title: "regenerate the signing key", status: 500, detail: "store: write signing key: permission denied" }),
    )
    const dialog = await opened()
    fireEvent.click(within(dialog).getByRole("button", { name: "Regenerate" }))

    expect(await screen.findByText("store: write signing key: permission denied")).toBeInTheDocument()
    expect(screen.getByText(SHA)).toBeInTheDocument()
    expect(screen.queryByText(/New key in use/)).toBeNull()
  })

  it("fetches the key again when the regenerate answer is lost", async () => {
    vi.mocked(regenerateSigningKey).mockRejectedValue(new TypeError("Failed to fetch"))
    const dialog = await opened()
    expect(getSigningKey).toHaveBeenCalledTimes(1)
    vi.mocked(getSigningKey).mockResolvedValue(newKey)
    fireEvent.click(within(dialog).getByRole("button", { name: "Regenerate" }))

    expect(await screen.findByText("b".repeat(64))).toBeInTheDocument()
    expect(screen.queryByText(SHA)).toBeNull()
    expect(getSigningKey).toHaveBeenCalledTimes(2)
  })

  it("names a key that cannot be loaded", async () => {
    vi.mocked(getSigningKey).mockRejectedValue(new Error("boom"))
    renderSection()
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load the signing key: boom")
  })
})
