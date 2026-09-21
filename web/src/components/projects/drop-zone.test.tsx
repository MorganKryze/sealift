import { fireEvent, render } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { DropZone } from "@/components/projects/drop-zone"

describe("DropZone", () => {
  it("refuses a non-JSON file before any request", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
    const onFile = vi.fn()
    const onInvalidFile = vi.fn()

    const { container } = render(<DropZone onFile={onFile} onInvalidFile={onInvalidFile} />)
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File(["not json"], "notes.txt", { type: "text/plain" })

    fireEvent.change(input, { target: { files: [file] } })

    expect(onFile).not.toHaveBeenCalled()
    expect(onInvalidFile).toHaveBeenCalledWith(expect.stringContaining("notes.txt"))
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it("accepts a .json file", () => {
    const onFile = vi.fn()
    const onInvalidFile = vi.fn()

    const { container } = render(<DropZone onFile={onFile} onInvalidFile={onInvalidFile} />)
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File(["{}"], "package.json", { type: "application/json" })

    fireEvent.change(input, { target: { files: [file] } })

    expect(onFile).toHaveBeenCalledWith(file)
    expect(onInvalidFile).not.toHaveBeenCalled()
  })
})
