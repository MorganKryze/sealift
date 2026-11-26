import { fireEvent, render } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { DropZone } from "@/components/projects/drop-zone"

function choose(files: File[]) {
  const onFiles = vi.fn()
  const { container } = render(<DropZone onFiles={onFiles} />)
  const input = container.querySelector('input[type="file"]') as HTMLInputElement
  fireEvent.change(input, { target: { files } })
  return onFiles
}

describe("DropZone", () => {
  it("reads files with no .json among them as requirements files, before any request", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
    const files = [new File(["Django==4.2.16\n"], "requirements.txt", { type: "text/plain" }), new File(["idna==3.10\n"], "constraints.in")]

    expect(choose(files)).toHaveBeenCalledWith({ kind: "pip", files })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it("accepts a .json file", () => {
    const file = new File(["{}"], "package.json", { type: "application/json" })

    expect(choose([file])).toHaveBeenCalledWith({ kind: "npm", file })
  })

  it("refuses a .json file chosen with other files", () => {
    const onFiles = choose([new File(["{}"], "package.json"), new File(["idna==3.10\n"], "requirements.txt")])

    expect(onFiles).toHaveBeenCalledWith({
      kind: "refused",
      message: "package.json and 1 requirements file dropped together",
      instead: "Drop the package.json alone, or the requirements files alone; nothing was sent.",
    })
  })

  it("says how many files are over it", () => {
    const { container, getByRole } = render(<DropZone onFiles={vi.fn()} />)
    const zone = container.querySelector("[data-drop-zone]") as HTMLElement

    fireEvent.dragOver(zone, { dataTransfer: { items: { length: 3 } } })
    expect(getByRole("heading")).toHaveTextContent("Drop to read 3 files")
    fireEvent.dragLeave(zone)
    expect(getByRole("heading")).toHaveTextContent("Drop a package.json or requirements files")
  })
})
