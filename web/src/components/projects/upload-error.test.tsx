import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ProjectUploadError } from "@/api/projects"
import { UploadError } from "@/components/projects/upload-error"

describe("UploadError", () => {
  it("shows every problem detail entry on a 400", () => {
    const error = new ProjectUploadError(400, {
      type: "about:blank",
      title: "Invalid manifest",
      status: 400,
      errors: [
        { field: "dependencies", name: "left-pad", value: "^99.0.0", reason: "no matching version" },
        { field: "dependencies", name: "chalk", value: "1.0.0-broken", reason: "not a valid semver" },
        { field: "pnpm.overrides", name: "lodash", value: "*", reason: "overrides every version" },
      ],
    })

    render(<UploadError error={error} />)

    expect(screen.getAllByRole("listitem")).toHaveLength(3)
    expect(screen.getByText(/left-pad/)).toBeInTheDocument()
    expect(screen.getByText(/chalk/)).toBeInTheDocument()
    expect(screen.getByText(/lodash/)).toBeInTheDocument()
  })

  it("shows the problem's title and detail for any other failure", () => {
    const error = new ProjectUploadError(500, {
      type: "about:blank",
      title: "Internal error",
      status: 500,
      detail: "the store is unavailable",
    })

    render(<UploadError error={error} />)

    expect(screen.getByText("Internal error")).toBeInTheDocument()
    expect(screen.getByText("the store is unavailable")).toBeInTheDocument()
  })
})
