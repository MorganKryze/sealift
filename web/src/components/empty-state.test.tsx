import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { EmptyState } from "@/components/empty-state"

describe("EmptyState", () => {
  it("renders its heading", () => {
    render(<EmptyState />)

    expect(screen.getByRole("heading", { name: "Nothing in the hold yet" })).toBeInTheDocument()
  })
})
