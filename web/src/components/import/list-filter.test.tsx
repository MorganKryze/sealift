import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ListFilter } from "./list-filter"

describe("ListFilter", () => {
  it("writes each count in weight 600", () => {
    render(<ListFilter value="all" onChange={() => {}} counts={{ all: 272, importable: 208 }} />)
    expect(screen.getByText("272")).toHaveClass("font-semibold")
    expect(screen.getByText("208")).toHaveClass("font-semibold")
  })
})
