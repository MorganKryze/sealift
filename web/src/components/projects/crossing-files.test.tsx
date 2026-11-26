import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import type { Export, Project } from "@/api/projects"
import { getSigningKey } from "@/api/settings"
import { CrossingFiles } from "@/components/projects/crossing-files"
import { readSeal } from "@/lib/crossings"

vi.mock("@/api/settings", () => ({ getSigningKey: vi.fn() }))
vi.mock("@/lib/crossings", async () => {
  const actual = await vi.importActual<typeof import("@/lib/crossings")>("@/lib/crossings")
  return { ...actual, readSeal: vi.fn() }
})

const project = { id: "demo", name: "kiosk-ui", createdAt: "2026-11-24T10:14:00Z" } as unknown as Project
const exportWith = (files: string[]) =>
  ({ id: "20261124T102000Z", projectId: "demo", analysisId: "20261124T101500Z", state: "done", createdAt: "2026-11-24T10:20:00Z", files }) as Export

function renderFiles(files: string[]) {
  const onDownload = vi.fn()
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <CrossingFiles project={project} exported={exportWith(files)} downloadAllPrimary onDownload={onDownload} />
    </QueryClientProvider>,
  )
  return onDownload
}

beforeEach(() => {
  vi.mocked(readSeal).mockReset().mockReturnValue(new Promise(() => {}))
  vi.mocked(getSigningKey).mockReset().mockReturnValue(new Promise(() => {}))
})

describe("CrossingFiles", () => {
  it("counts Download all as a download of a file to carry", () => {
    const onDownload = renderFiles(["manifest.json", "manifest.json.sig", "packages_npm.tar.gz", "summary.md"])
    fireEvent.click(screen.getByRole("button", { name: "Download all" }))
    expect(onDownload).toHaveBeenCalledTimes(1)
  })

  it("counts no download when Download all has no file to carry", () => {
    const onDownload = renderFiles(["summary.md", "findings.csv"])
    fireEvent.click(screen.getByRole("button", { name: "Download all" }))
    expect(onDownload).not.toHaveBeenCalled()
  })
})
