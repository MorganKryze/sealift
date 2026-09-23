import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { updateSettings, type Settings } from "@/api/settings"
import { SettingsForm } from "@/components/settings/settings-form"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, updateSettings: vi.fn() }
})

const baseSettings: Settings = {
  target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
  signatureKey: "********",
  minReleaseAgeDays: 14,
  resolveParallelism: 4,
  downloadParallelism: 16,
}

function renderForm() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <SettingsForm settings={baseSettings} />
    </QueryClientProvider>,
  )
}

const save = () => screen.getByRole("button", { name: "Save" })

beforeEach(() => {
  vi.mocked(updateSettings).mockReset()
  vi.mocked(updateSettings).mockImplementation(async (s) => ({ ...s, signatureKey: s.signatureKey ? "********" : "" }))
})

describe("SettingsForm", () => {
  it("offers the target as one platform choice and saves its os, cpu and libc", async () => {
    renderForm()
    const platform = screen.getByLabelText("Platform") as HTMLSelectElement
    expect(platform.value).toBe("linux-x64-glibc")

    fireEvent.change(platform, { target: { value: "linux-arm64-musl" } })
    fireEvent.click(save())

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith(
        expect.objectContaining({ target: { os: "linux", cpu: "arm64", libc: "musl", node: "22.17.1", pnpmVer: "10.34.5" } }),
      ),
    )
    expect(await screen.findByText("Saved")).toBeInTheDocument()
  })

  it("shows Save and Discard only once something changes, and Discard restores", () => {
    renderForm()
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull()

    fireEvent.change(screen.getByLabelText("Node version"), { target: { value: "20.11.0" } })
    expect(save()).toBeEnabled()

    fireEvent.click(screen.getByRole("button", { name: "Discard changes" }))
    expect((screen.getByLabelText("Node version") as HTMLInputElement).value).toBe("22.17.1")
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull()
  })

  it("explains an inexact Node version next to the field and does not save it", () => {
    renderForm()
    fireEvent.change(screen.getByLabelText("Node version"), { target: { value: "22.x" } })

    expect(screen.getByText("Use an exact version, such as 22.17.1.")).toBeInTheDocument()
    expect(save()).toBeDisabled()
  })

  it("explains a limit out of range next to the field", () => {
    renderForm()
    fireEvent.change(screen.getByLabelText("Minimum release age"), { target: { value: "0" } })

    expect(screen.getByText("Between 1 and 90 days.")).toBeInTheDocument()
    expect(save()).toBeDisabled()
  })

  it("keeps the stored key untouched unless it is replaced", async () => {
    renderForm()
    fireEvent.change(screen.getByLabelText("Resolve parallelism"), { target: { value: "8" } })
    fireEvent.click(save())
    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith(expect.objectContaining({ signatureKey: "********" })))

    fireEvent.click(screen.getByRole("button", { name: "Replace" }))
    fireEvent.change(screen.getByLabelText("New signature key"), { target: { value: "real-key" } })
    fireEvent.click(save())
    await waitFor(() => expect(updateSettings).toHaveBeenLastCalledWith(expect.objectContaining({ signatureKey: "real-key" })))
  })

  it("clears the key only after confirming, and says what it blocks", async () => {
    renderForm()
    fireEvent.click(screen.getByRole("button", { name: "Clear" }))
    const dialog = screen.getByRole("alertdialog")
    expect(within(dialog).getByText(/Exports stay blocked/)).toBeInTheDocument()

    fireEvent.click(within(dialog).getByRole("button", { name: "Clear the key" }))
    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith(expect.objectContaining({ signatureKey: "" })))
  })

  it("shows a server refusal under the field it names", async () => {
    vi.mocked(updateSettings).mockRejectedValue(
      new ProblemError(400, { type: "about:blank", title: "update settings", status: 400, detail: "invalid target: node must be exact, such as 22.17.1, not \"23.0.0-x\"" }),
    )
    renderForm()
    fireEvent.change(screen.getByLabelText("Node version"), { target: { value: "23.0.0" } })
    fireEvent.click(save())

    const node = screen.getByLabelText("Node version").closest("[data-field]") as HTMLElement
    expect(await within(node).findByText(/node must be exact/)).toBeInTheDocument()
  })
})
