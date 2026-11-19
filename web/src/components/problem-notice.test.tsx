import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { ProblemNotice } from "./problem-notice"

describe("problem notice", () => {
  it("names the status and the log when the response carried no problem", () => {
    render(<ProblemNotice status={500} problem={null} />)
    expect(screen.getByText("Request failed with HTTP 500")).toBeInTheDocument()
    expect(screen.getByText(/no detail reached the browser/)).toBeInTheDocument()
  })

  it("keeps the server's title and detail when there is one", () => {
    render(<ProblemNotice status={500} problem={{ type: "about:blank", title: "update trivy db", status: 500, detail: "operation not permitted" }} />)
    expect(screen.getByText("update trivy db")).toBeInTheDocument()
    expect(screen.getByText("operation not permitted")).toBeInTheDocument()
  })
})
