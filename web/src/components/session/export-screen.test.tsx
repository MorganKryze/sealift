import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { apiFetch } from "@/api/client"
import type { Analysis, Export, Project } from "@/api/projects"
import { getSigningKey } from "@/api/settings"
import { ExportScreen } from "@/components/session/export-screen"
import { useJobEvents } from "@/hooks/use-job-events"
import { initialAnalysisEventsState } from "@/lib/analysisEvents"

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client")
  return { ...actual, apiFetch: vi.fn() }
})
vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getSigningKey: vi.fn() }
})
vi.mock("@/hooks/use-job-events", () => ({ useJobEvents: vi.fn() }))
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  useNavigate: () => vi.fn(),
}))

const CURRENT = "a".repeat(64)
const OLD = "b".repeat(64)
const ARCHIVE_SHA = "c".repeat(64)
const ALL_FILES = [
  "findings.csv", "manifest.json", "manifest.json.sig", "packages_npm.tar.gz", "report.cdx.json", "report.trivy.json", "summary.md",
]

const project = { id: "demo", name: "demo", target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" } } as Project
const analysis = { id: "20260921T101500Z", projectId: "demo", state: "done", createdAt: "2026-09-21T10:15:00Z" } as Analysis

function exportRecord(over: Partial<Export>): Export {
  return { id: "20260921T102000Z", projectId: "demo", analysisId: analysis.id, state: "done", createdAt: "2026-09-21T10:20:00Z", files: ALL_FILES, ...over }
}

function renderScreen(record: Export) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ExportScreen project={project} analysis={analysis} relatedExport={record} onChanged={() => {}} onNavigateStep={() => {}} />
    </QueryClientProvider>,
  )
}

function serve(signature: () => Promise<unknown>) {
  vi.mocked(apiFetch).mockImplementation((path: string) => {
    if (path.endsWith("/files/manifest.json")) return Promise.resolve({ archive: { sha256: ARCHIVE_SHA, size: 1024 }, packages: [] }) as never
    if (path.endsWith("/files/manifest.json.sig")) return signature() as never
    return Promise.reject(new Error(`unexpected request ${path}`))
  })
}

const signatureNaming = (sha: string) => () => Promise.resolve({ algorithm: "ed25519", publicKeySha256: sha, signature: "AAAA" })

beforeEach(() => {
  vi.mocked(apiFetch).mockReset()
  vi.mocked(getSigningKey).mockReset().mockResolvedValue({ publicKeyPem: "pem", publicKeySha256: CURRENT })
  vi.mocked(useJobEvents).mockReset().mockReturnValue(initialAnalysisEventsState)
})

describe("the done screen", () => {
  it("says which files to carry together and describes the manifest and its signature", async () => {
    serve(signatureNaming(CURRENT))
    renderScreen(exportRecord({}))
    expect(
      await screen.findByText(
        "Carry the archive, manifest.json and manifest.json.sig through the kiosk, side by side: the import refuses the archive without the other two. The reports travel with them.",
      ),
    ).toBeInTheDocument()
    expect(screen.getByText("Every package with its sha512. The import needs it.")).toBeInTheDocument()
    expect(screen.getByText("The manifest's signature. The import needs it.")).toBeInTheDocument()
    expect(screen.getByText("manifest.json.sig")).toBeInTheDocument()
  })

  it("says the archive is signed with this sealift's key", async () => {
    serve(signatureNaming(CURRENT))
    renderScreen(exportRecord({}))
    const line = await screen.findByText(`Signed with this sealift's key, public key sha256 ${CURRENT}.`)
    expect(line.className).toContain("[overflow-wrap:anywhere]")
  })

  it("says the key was replaced since, and to export again", async () => {
    serve(signatureNaming(OLD))
    renderScreen(exportRecord({}))
    expect(
      await screen.findByText(
        `Signed with a key replaced since, public key sha256 ${OLD}. The import refuses this archive once it trusts the current key: export the selection again.`,
      ),
    ).toBeInTheDocument()
  })

  it("says an export without a signature is not signed, and reads no signature file", async () => {
    serve(signatureNaming(CURRENT))
    renderScreen(exportRecord({ files: ALL_FILES.filter((name) => name !== "manifest.json.sig") }))
    expect(
      await screen.findByText("Not signed: sealift 0.4.0 or earlier exported this archive, and the import refuses it. Export the selection again."),
    ).toBeInTheDocument()
    const paths = vi.mocked(apiFetch).mock.calls.map((call) => call[0])
    expect(paths.some((path) => path.endsWith("manifest.json.sig"))).toBe(false)
  })

  it.each([
    ["the signature file cannot be read", () => Promise.reject(new Error("boom"))],
    ["the signature file names no sha256", () => Promise.resolve({ algorithm: "ed25519" })],
  ])("says it could not read the signature when %s", async (_name, signature) => {
    serve(signature)
    renderScreen(exportRecord({}))
    expect(await screen.findByText("Could not read manifest.json.sig.")).toBeInTheDocument()
  })

  it("says it could not read the signature when the current key is unknown", async () => {
    serve(signatureNaming(CURRENT))
    vi.mocked(getSigningKey).mockRejectedValue(new Error("boom"))
    renderScreen(exportRecord({}))
    expect(await screen.findByText("Could not read manifest.json.sig.")).toBeInTheDocument()
  })
})

describe("the progress screen", () => {
  it("labels the steps that pack and sign", () => {
    vi.mocked(useJobEvents).mockReturnValue({
      ...initialAnalysisEventsState,
      steps: [
        { name: "archive", state: "done", durationMs: 1000 },
        { name: "reports", state: "running" },
      ],
    })
    renderScreen(exportRecord({ state: "running", files: undefined }))
    const list = screen.getByRole("list")
    expect(within(list).getByText("Pack the archive")).toBeInTheDocument()
    expect(within(list).getByText("Sign the manifest and write the reports")).toBeInTheDocument()
  })

  it("lists no file and reads no manifest for a failed export", () => {
    renderScreen(exportRecord({ state: "failed", files: undefined, failure: { step: "reports", message: "jobs: sign manifest.json: no key" } as Export["failure"] }))
    expect(screen.getByRole("heading", { name: "Export failed" })).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /download/i })).not.toBeInTheDocument()
    expect(screen.queryByText("manifest.json.sig")).not.toBeInTheDocument()
    expect(apiFetch).not.toHaveBeenCalled()
  })
})
