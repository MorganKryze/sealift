import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { updateSettings, type Settings } from "@/api/settings"
import { SettingsForm } from "@/components/settings/settings-form"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, updateSettings: vi.fn() }
})

const baseSettings: Settings = {
  target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
  signatureKey: "sk_***abcd",
  minReleaseAgeDays: 3,
  resolveParallelism: 4,
  downloadParallelism: 4,
}

function renderForm() {
  const queryClient = new QueryClient()
  const { container } = render(
    <QueryClientProvider client={queryClient}>
      <SettingsForm settings={baseSettings} />
    </QueryClientProvider>,
  )
  return container.querySelector("form") as HTMLFormElement
}

beforeEach(() => {
  vi.mocked(updateSettings).mockReset()
  vi.mocked(updateSettings).mockResolvedValue(baseSettings)
})

describe("SettingsForm", () => {
  it("refuses a release age of 0", () => {
    const form = renderForm()

    fireEvent.change(screen.getByLabelText("Min release age (days)"), { target: { value: "0" } })
    fireEvent.submit(form)

    expect(screen.getByText(/at least 1 day/)).toBeInTheDocument()
    expect(updateSettings).not.toHaveBeenCalled()
  })

  it("keeps the masked key untouched when left blank", async () => {
    const form = renderForm()

    fireEvent.submit(form)

    await waitFor(() => {
      expect(updateSettings).toHaveBeenCalledWith(expect.objectContaining({ signatureKey: "sk_***abcd" }))
    })
  })
})
