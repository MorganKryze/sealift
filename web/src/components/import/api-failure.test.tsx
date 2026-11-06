import { fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ImportApiError, SessionEnded } from "@/import/api/client"

import { ApiFailure } from "./api-failure"

afterEach(() => vi.unstubAllGlobals())

const problem = (status: number, detail: string) => ({ type: "about:blank", title: "Failed", status, detail })

describe("ApiFailure", () => {
  it("session ended offers Sign in again, which reloads the page", () => {
    const reload = vi.fn()
    vi.stubGlobal("location", { ...window.location, reload })
    render(<ApiFailure error={new SessionEnded()} />)
    expect(screen.getByRole("heading", { name: "Your session has ended" })).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Sign in again" }))
    expect(reload).toHaveBeenCalledOnce()
  })

  it("403 gives the cause and says to ask the administrator", () => {
    render(<ApiFailure error={new ImportApiError(403, problem(403, "the user name cannot name a bucket"))} onRetry={vi.fn()} />)
    expect(screen.getByText("the user name cannot name a bucket")).toBeInTheDocument()
    expect(screen.getByText(/Ask the administrator/)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument()
  })

  it("503 gives the cause and says to try again later", () => {
    render(<ApiFailure error={new ImportApiError(503, problem(503, "the realm's keys cannot be had"))} />)
    expect(screen.getByText("the realm's keys cannot be had")).toBeInTheDocument()
    expect(screen.getByText(/Try again later/)).toBeInTheDocument()
  })

  it("any other status shows its detail and Try again", () => {
    const onRetry = vi.fn()
    render(<ApiFailure error={new ImportApiError(502, problem(502, "MinIO refused the call"))} onRetry={onRetry} />)
    expect(screen.getByText("MinIO refused the call")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Try again" }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it("names what a failure left untouched", () => {
    render(<ApiFailure error={new ImportApiError(500, problem(500, "the data volume did not answer"))} untouched="The archives in MinIO are untouched." />)
    expect(screen.getByText("The archives in MinIO are untouched.")).toBeInTheDocument()
  })

  it("shows markup in a detail as text", () => {
    render(<ApiFailure error={new ImportApiError(502, problem(502, "<img src=x onerror=alert(1)>"))} />)
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument()
    expect(document.querySelector("img")).toBeNull()
  })

  it("a failure that is not the client's still says something", () => {
    render(<ApiFailure error={new Error("boom")} onRetry={vi.fn()} />)
    expect(screen.getByRole("alert")).toHaveTextContent("boom")
  })
})
