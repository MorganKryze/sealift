import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, within } from "@testing-library/react"
import { useState } from "react"
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import { SettingsSheet } from "./settings-sheet"

beforeAll(() => {
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "")
  }
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open")
  }
})

afterEach(() => vi.restoreAllMocks())

function Harness() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Settings
      </button>
      <SettingsSheet open={open} onClose={() => setOpen(false)} />
    </>
  )
}

function renderSheet(answer: () => Promise<Response>) {
  vi.spyOn(globalThis, "fetch").mockImplementation(answer)
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <Harness />
    </QueryClientProvider>,
  )
}

const meAnswer = () =>
  Promise.resolve(new Response(JSON.stringify({ user: "alice", minioConfigured: true, bucket: "user-alice", folder: "packages/npm/" }), { headers: { "Content-Type": "application/json" } }))

describe("SettingsSheet", () => {
  it("offers System, Light and Dark as a segmented control", () => {
    renderSheet(meAnswer)
    fireEvent.click(screen.getByRole("button", { name: "Settings" }))
    const group = screen.getByRole("radiogroup", { name: "Theme" })
    expect(within(group).getAllByRole("radio").map((r) => r.textContent)).toEqual(["System", "Light", "Dark"])
    fireEvent.click(within(group).getByRole("radio", { name: "Dark" }))
    expect(within(group).getByRole("radio", { name: "Dark" })).toHaveAttribute("aria-checked", "true")
    expect(document.documentElement).toHaveClass("dark")
  })

  it("shows the bucket and the folder, read only", async () => {
    renderSheet(meAnswer)
    fireEvent.click(screen.getByRole("button", { name: "Settings" }))
    const sheet = screen.getByRole("dialog", { name: "Settings" })
    expect(await within(sheet).findByText("user-alice")).toBeInTheDocument()
    expect(within(sheet).getByText("packages/npm/")).toBeInTheDocument()
    expect(within(sheet).queryByRole("textbox")).not.toBeInTheDocument()
  })

  it("says in words when the bucket cannot be read", async () => {
    renderSheet(() => Promise.reject(new TypeError("Failed to fetch")))
    fireEvent.click(screen.getByRole("button", { name: "Settings" }))
    const sheet = screen.getByRole("dialog", { name: "Settings" })
    expect(await within(sheet).findAllByText("Not read")).toHaveLength(2)
  })

  it("Escape closes the sheet and focus returns to Settings", () => {
    renderSheet(meAnswer)
    const opener = screen.getByRole("button", { name: "Settings" })
    opener.focus()
    fireEvent.click(opener)
    const sheet = screen.getByRole("dialog", { name: "Settings" })
    expect(sheet).toHaveAttribute("open")
    fireEvent.keyDown(sheet, { key: "Escape" })
    expect(sheet).not.toHaveAttribute("open")
    expect(opener).toHaveFocus()
  })

  it("the Close button closes it too", () => {
    renderSheet(meAnswer)
    const opener = screen.getByRole("button", { name: "Settings" })
    opener.focus()
    fireEvent.click(opener)
    fireEvent.click(screen.getByRole("button", { name: "Close settings" }))
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })
})
