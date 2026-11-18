import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { CopyControl } from "./copy-control"

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("copy control", () => {
  it("copies with the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } })
    render(<CopyControl text={"b".repeat(64)} label="manifest sha256" />)
    fireEvent.click(screen.getByRole("button", { name: "Copy manifest sha256" }))
    await waitFor(() => expect(screen.getByText("Copied")).toBeInTheDocument())
    expect(writeText).toHaveBeenCalledWith("b".repeat(64))
    expect(screen.queryByRole("textbox")).toBeNull()
  })

  it("no clipboard: selects the text and says how to copy with the keyboard", async () => {
    vi.stubGlobal("navigator", { ...navigator, clipboard: undefined })
    render(<CopyControl text={"c".repeat(64)} label="expected sha256" />)
    fireEvent.click(screen.getByRole("button", { name: "Copy expected sha256" }))
    const box = (await screen.findByRole("textbox", { name: "Text of expected sha256" })) as HTMLTextAreaElement
    expect(box.value).toBe("c".repeat(64))
    expect(box).toHaveFocus()
    expect(box.selectionStart).toBe(0)
    expect(box.selectionEnd).toBe(64)
    expect(screen.getByText(/Ctrl\+C, or Command\+C on a Mac/)).toBeInTheDocument()
    expect(screen.queryByText("Copied")).toBeNull()
  })

  it("a refused write falls back to the selected text", async () => {
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } })
    render(<CopyControl text="reason" label="reason" />)
    fireEvent.click(screen.getByRole("button", { name: "Copy reason" }))
    expect(await screen.findByRole("textbox", { name: "Text of reason" })).toHaveFocus()
    expect(screen.queryByText("Copied")).toBeNull()
  })
})
