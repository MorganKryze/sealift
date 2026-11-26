import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { FailureBlock } from "@/components/failure-block"
import { BrandProvider, DEFAULT_BRAND, type Brand } from "@/components/frame/brand"

const RAW = "ERR_PNPM_NO_MATCHING_VERSION No matching version found for @typescript-eslint/eslint-plugin@8.46.9"

function logAnswer(text: string) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(new Response(text, { status: 200 })))
}

function renderBlock({ brand = DEFAULT_BRAND, tone = "failure", actions = <button>Retry</button>, withCause = true }: { brand?: Brand; tone?: "failure" | "neutral"; actions?: ReactNode; withCause?: boolean } = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <BrandProvider brand={brand}>
        <FailureBlock
          projectId="p1"
          analysisId="a1"
          heading="Analysis stopped"
          sub="After 48 s. Your package.json is kept."
          tone={tone}
          cause={
            withCause
              ? {
                  title: "A pinned version is not on npm",
                  count: "1 package",
                  items: [{ name: "@typescript-eslint/eslint-plugin", value: "8.46.9" }],
                  diagnosis: "A retry gives the same answer: the version comes from your package.json.",
                }
              : undefined
          }
          actions={actions}
        />
      </BrandProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe("FailureBlock", () => {
  it("titles the stop, then the cause in words with its action in the block", async () => {
    logAnswer("09:14:02 validate ok\n")
    renderBlock()

    expect(screen.getByRole("heading", { level: 1, name: "Analysis stopped" })).toBeInTheDocument()
    expect(screen.getByText("After 48 s. Your package.json is kept.")).toBeInTheDocument()
    const cause = screen.getByRole("alert")
    expect(within(cause).getByText("A pinned version is not on npm")).toBeInTheDocument()
    expect(within(cause).getByText("1 package")).toBeInTheDocument()
    expect(within(cause).getByText("@typescript-eslint/eslint-plugin")).toBeInTheDocument()
    expect(within(cause).getByText("8.46.9")).toBeInTheDocument()
    expect(within(cause).getByRole("button", { name: "Retry" })).toBeInTheDocument()
    await screen.findByRole("button", { name: "Log 1 line" })
  })

  it("folds the log behind its line count and opens it in place", async () => {
    const fetchSpy = logAnswer("09:14:02 validate ok\n09:14:04 resolve-project failed\n")
    renderBlock()

    const toggle = await screen.findByRole("button", { name: "Log 2 lines" })
    expect(toggle).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText("09:14:04 resolve-project failed")).not.toBeInTheDocument()

    fireEvent.click(toggle)

    expect(toggle).toHaveAttribute("aria-expanded", "true")
    expect(within(screen.getByRole("region", { name: "Log" })).getByText("09:14:04 resolve-project failed")).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith("/api/projects/p1/analyses/a1/log", undefined)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it("keeps the raw text in the log only", async () => {
    logAnswer(`09:14:04 resolve-project\npnpm: ${RAW}\n`)
    renderBlock()

    const toggle = await screen.findByRole("button", { name: "Log 2 lines" })
    expect(screen.queryByText(RAW, { exact: false })).not.toBeInTheDocument()

    fireEvent.click(toggle)

    expect(within(screen.getByRole("region", { name: "Log" })).getByText(`pnpm: ${RAW}`)).toBeInTheDocument()
  })

  it("says when the log does not load", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ title: "not found", status: 404 }), { status: 404, headers: { "content-type": "application/json" } }),
    )
    renderBlock()

    await waitFor(() => {
      expect(screen.getByText("The log did not load.")).toBeInTheDocument()
    })
  })

  it("ends with the deployment's contact, else See your administrators", async () => {
    logAnswer("")
    const { container, unmount } = renderBlock({ brand: { ...DEFAULT_BRAND, contact: { label: "Platform team, #sealift-help", url: "https://chat.example.com/sealift-help" } } })
    await screen.findByRole("button", { name: "Log 0 lines" })
    expect(container.lastElementChild?.lastElementChild).toHaveTextContent("Platform team, #sealift-help")
    unmount()

    const fallback = renderBlock()
    await screen.findByRole("button", { name: "Log 0 lines" })
    expect(fallback.container.lastElementChild?.lastElementChild).toHaveTextContent("See your administrators")
  })

  it("draws a stop the developer asked for with no red, no contact and its actions after the log", async () => {
    logAnswer("a\nb\n")
    const { container } = renderBlock({ tone: "neutral", withCause: false, actions: <button>Start again</button> })

    await screen.findByRole("button", { name: "Log 2 lines" })
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    expect(container.querySelector("[class*='bad']")).toBeNull()
    expect(screen.queryByText("See your administrators")).not.toBeInTheDocument()
    const order = [...container.querySelectorAll("button")].map((b) => b.textContent)
    expect(order.at(-1)).toBe("Start again")
  })
})
