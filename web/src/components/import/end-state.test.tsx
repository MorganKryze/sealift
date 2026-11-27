import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { importPollInterval } from "@/import/api/queries"
import { latestAttempt, type Attempt, type Import, type ReportPackage } from "@/import/lib/outcome"

import { EndState } from "./end-state"
import { prComment } from "./pr-comment"

afterEach(() => {
  vi.unstubAllGlobals()
})

const pkg = (state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name: "left-pad", version: "1.3.0", file: "x", state, reason: "", note: "", ...over,
})
const many = (n: number, state: string, over: Partial<ReportPackage> = {}) => Array.from({ length: n }, () => pkg(state, over))

function attempt(outcome: string, packages: ReportPackage[], over: Partial<Attempt> = {}, reason = ""): Attempt {
  return {
    n: 1, status: "ended", outcome, endedAt: "2026-11-05T15:47:00Z",
    report: {
      outcome, reason, unencrypted: false, importVersion: "0.5.0", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages, archiveChecked: true,
    },
    ...over,
  }
}

const ARCHIVE_ETAG = "\"7c1d0a5e9b3f48d2a6e1c04b5f7a93d2-52\""
const SIGNATURE_ETAG = "\"5b2f8c19d0e347a6b1c8f20d93e47a15\""
const MANIFEST_ETAG = "\"e41b6d0c97a2358f1c6b0d94a7e35f82\""

function make(a: Attempt, over: Partial<Import> = {}): Import {
  return {
    id: "20261105T161200Z-a1000003", createdAt: "2026-11-05T16:12:00Z", expectedSha256: "", outcome: a.outcome, archiveRemoved: false, attempts: [a],
    archive: { key: "packages/npm/2026-11-05-hr-forms/packages_npm.tar.gz", etag: ARCHIVE_ETAG, size: 5_500_000 },
    manifest: { key: "packages/npm/2026-11-05-hr-forms/manifest.json", etag: MANIFEST_ETAG, size: 900 },
    signature: { key: "packages/npm/2026-11-05-hr-forms/manifest.json.sig", etag: SIGNATURE_ETAG, size: 300 },
    ...over,
  }
}

const ME = { user: "lea.martin", minioConfigured: true, bucket: "user-lea.martin", folder: "packages/npm/", publicKeySha256: "7".repeat(64) }

function renderEnd(imp: Import, me = ME) {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).endsWith("/me") ? me : {}), { status: 200, headers: { "Content-Type": "application/json" } })))
  const root = createRootRoute({ component: () => <><p>page</p><EndState imp={imp} /></> })
  const archives = createRoute({ getParentRoute: () => root, path: "/archives", component: () => null })
  const router = createRouter({ routeTree: root.addChildren([archives]), history: createMemoryHistory({ initialEntries: ["/start"] }) })
  return render(<QueryClientProvider client={new QueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
}

describe("EndState", () => {
  it("refused: gives the reason in full, both digests, nothing published, no package read, one action and no Retry", async () => {
    const computed = "c".repeat(64)
    const expected = "e".repeat(64)
    const reason = `the archive's sha256 is ${computed} but the expected sha256 is ${expected}`
    const a = attempt("refused", [], { report: { ...attempt("refused", [], {}, reason).report, archiveChecked: false } })
    renderEnd(make(a, { expectedSha256: expected }))
    expect(await screen.findByRole("heading", { name: "Refused before the first package" })).toBeInTheDocument()
    const cause = screen.getByText(reason)
    expect(cause).toHaveTextContent(computed)
    expect(cause).toHaveTextContent(expected)
    expect(screen.getByText("This attempt published nothing and read no package.")).toBeInTheDocument()
    expect(screen.queryByText(/Nothing was published/)).toBeNull()
    expect(screen.getByRole("link", { name: "Go to archives" })).toHaveAttribute("href", "/import")
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
  })

  it("a signature refusal: gives the reason in full as the cause, publishes nothing and offers Go to archives", async () => {
    const trusted = "a".repeat(64)
    const named = "d".repeat(64)
    const reason = `the manifest is signed by another key, public key sha256 ${named}; this import trusts ${trusted}. If the connected side regenerated its key, carry its new public key here; otherwise export the archive again`
    const a = attempt("refused", [], { report: { ...attempt("refused", [], {}, reason).report, archiveChecked: false, publicKeySha256: trusted } })
    renderEnd(make(a))
    expect(await screen.findByRole("heading", { name: "Refused before the first package" })).toBeInTheDocument()
    expect(screen.getByText(reason)).toBeInTheDocument()
    expect(screen.getByText("This attempt published nothing and read no package.")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Go to archives" })).toHaveAttribute("href", "/import")
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
  })

  it("refused: tints the panel red, as the refusal is the one end state that stops everything", async () => {
    const a = attempt("refused", [], { report: { ...attempt("refused", [], {}, "the archive's sha256 is x but the expected sha256 is y").report, archiveChecked: false } })
    renderEnd(make(a, { expectedSha256: "y" }))
    const panel = (await screen.findByRole("heading", { name: "Refused before the first package" })).closest("section") as HTMLElement
    expect(panel.className).toContain("bg-severity-critical/")
    expect(panel.className).toContain("border-severity-critical/")
  })

  it("interrupted: says the service stopped, when, how many it finished and how many it did not, and names no package in flight", async () => {
    const packages = [...many(52, "published"), ...many(4, "present"), ...many(45, "failed", { kind: "interrupted", reason: "interrupted" })]
    const a = attempt("interrupted", packages, {}, "interrupted")
    renderEnd(make(a))
    expect(await screen.findByRole("heading", { name: /^Stopped before it ended/ })).toBeInTheDocument()
    expect(screen.getByText(/The service stopped or restarted before this attempt ended/)).toBeInTheDocument()
    expect(screen.getByText(/at .*\d/)).toBeInTheDocument()
    expect(screen.getByText(/56 of 101 packages were finished/)).toBeInTheDocument()
    expect(screen.getByText(/45 were not finished/)).toBeInTheDocument()
    expect(screen.getByText(/counted apart from failures/)).toBeInTheDocument()
    expect(document.body.textContent ?? "").not.toMatch(/in flight|was uploading/)
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
  })

  it("interrupted: names a missing end time in words", async () => {
    const a = attempt("interrupted", many(2, "published"), { endedAt: undefined })
    renderEnd(make(a))
    const heading = await screen.findByRole("heading", { name: /^Stopped before it ended/ })
    expect(within(heading).getByText(/Not recorded/)).toBeInTheDocument()
  })

  it.each([
    ["queued", attempt("", [], { status: "queued" })],
    ["running", attempt("", many(2, "published"), { status: "running" })],
  ])("shows nothing for a %s attempt", async (_name, a) => {
    const { container } = renderEnd(make(a))
    await screen.findByText("page")
    expect(container.textContent).toBe("page")
  })
})

const mb = (n: number) => Math.round(n * 1024 * 1024)
const MB = mb(1)
const sha = (c: string) => c.repeat(128)
const conflictReason = (shipped: string, nexus: string) => `nexus holds this file with other bytes: shipped sha512 ${shipped}, nexus sha512 ${nexus}`
const PIP_NAMES = ["Charset_Normalizer", "zope.interface", "plone.namedfile", "pandas", "SQLAlchemy", "pydantic_core", "pydantic", "requests", "urllib3", "certifi", "tenacity", "pytz", "six", "typing_extensions", "fsspec", "s3fs", "botocore", "boto3", "jmespath", "kombu", "Jinja2", "MarkupSafe", "attrs", "packaging", "setuptools", "celery", "backports.zoneinfo", "aiobotocore", "python-dateutil", "apache-airflow-providers-amazon", "opentelemetry-exporter-otlp-proto-grpc"]
const TOO_LARGE = [
  ["torch", "2.5.1", "torch-2.5.1-cp311-cp311-manylinux1_x86_64.whl", mb(906.4)],
  ["nvidia-cudnn-cu12", "9.1.0.70", "nvidia_cudnn_cu12-9.1.0.70-py3-none-manylinux2014_x86_64.whl", mb(664.8)],
  ["tensorflow", "2.18.0", "tensorflow-2.18.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", mb(615.4)],
  ["nvidia-cublas-cu12", "12.4.5.8", "nvidia_cublas_cu12-12.4.5.8-py3-none-manylinux2014_x86_64.whl", mb(363.4)],
  ["pyarrow", "18.0.0", "pyarrow-18.0.0-cp311-cp311-manylinux_2_28_x86_64.whl", mb(40)],
  ["numpy", "2.1.3", "numpy-2.1.3-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", mb(16.3)],
] as const

/** 40 failures in 3 causes on a pip import: 31 with no answer, 6 too large, 3 conflicts with what Nexus says of its copy. */
function worstPip(uploader = "ci-publish"): Import {
  const failed: ReportPackage[] = [
    ...PIP_NAMES.map((name, i) => pkg("failed", { name, version: `1.${i}.0`, file: `${name}-1.${i}.0-py3-none-any.whl`, kind: "nexus", reason: "upload failed: nexus unreachable: i/o timeout", size: 2 * MB })),
    ...TOO_LARGE.map(([name, version, file, size]) => pkg("failed", { name, version, file, kind: "nexus", nexusStatus: 413, reason: "upload failed: nexus answered 413", size })),
    pkg("failed", { name: "idna", version: "3.10", file: "idna-3.10-py3-none-any.whl", kind: "conflict", reason: conflictReason(sha("a"), sha("b")), nexusUploader: uploader, nexusUploadedAt: "2025-10-03T09:12:44Z" }),
    pkg("failed", { name: "PyYAML", version: "6.0.2", file: "PyYAML-6.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", kind: "conflict", reason: conflictReason(sha("c"), sha("d")), nexusUploadedAt: "2025-01-14T10:00:00Z" }),
    pkg("failed", { name: "zope.deprecation", version: "5.0", file: "zope.deprecation-5.0-py3-none-any.whl", kind: "conflict", reason: conflictReason(sha("e"), sha("f")) }),
  ]
  const done = [pkg("published", { name: "biggest", file: "biggest-1.0-py3-none-any.whl", size: mb(15.9) }), ...many(1832, "present", { size: MB })]
  const a = attempt("incomplete", [...done, ...failed])
  a.report.ecosystem = "pip"
  a.report.nexus = { url: "https://nexus.example", repository: "pypi-hosted" }
  return make(a, { archive: { key: "packages/pip/2026-11-26-analytics/packages_pip.tar.gz", etag: ARCHIVE_ETAG, size: 5_500_000 } })
}

function fetchAnswer(status: number, body: unknown) {
  const fetch = vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" } }))
  vi.stubGlobal("fetch", fetch)
  return fetch
}

const uploadedLine = (_: string, el: Element | null) => el?.tagName === "P" && /^Uploaded/.test(el.textContent ?? "")
const block = (title: string) => screen.getByRole("region", { name: title })

describe("EndState, packages not in Nexus", () => {
  it("names each cause with its action", async () => {
    const npm = attempt("incomplete", [
      ...many(1280, "present"),
      pkg("failed", { name: "@types/node", version: "22.10.2", file: "types-node-22.10.2.tgz", kind: "nexus", reason: "nexus unreachable: EOF" }),
      pkg("failed", { name: "@next/swc-linux-x64-gnu", version: "15.5.6", file: "next-swc-linux-x64-gnu-15.5.6.tgz", kind: "nexus", nexusStatus: 413, reason: "upload failed: nexus answered 413", size: mb(118.2) }),
      pkg("failed", { name: "is-number", version: "7.0.0", file: "is-number-7.0.0.tgz", kind: "conflict", reason: conflictReason(sha("a"), sha("b")) }),
      pkg("failed", { name: "lodash", version: "4.17.21", file: "lodash-4.17.21.tgz", kind: "mismatch", reason: "the tarball is x" }),
    ])
    renderEnd(make(npm))
    expect(await screen.findByRole("heading", { name: "4 packages not in Nexus" })).toBeInTheDocument()
    expect(screen.getByText(/packages in Nexus\. The archive stays in MinIO until all are in\./).textContent).toBe("1,280 of 1,284 packages in Nexus. The archive stays in MinIO until all are in.")
    expect(within(block("No answer from Nexus")).getByRole("button", { name: "Retry 1 package: No answer from Nexus" })).toBeInTheDocument()
    const large = block("Too large for Nexus")
    expect(within(large).getByRole("button", { name: /Copy request/ })).toBeInTheDocument()
    expect(within(large).getByRole("button", { name: "Retry 1 package: Too large for Nexus" })).toBeInTheDocument()
    expect(within(large).getByText("Once the limit is raised")).toBeInTheDocument()
    const conflict = block("Another file under the same version")
    expect(within(conflict).getByRole("button", { name: "Compare" })).toBeInTheDocument()
    expect(within(conflict).getByRole("button", { name: /Copy its path/ })).toBeInTheDocument()
    expect(within(conflict).getByText("Once the copy is removed")).toBeInTheDocument()
    const mismatch = block("Not the package the manifest names")
    expect(within(mismatch).queryByRole("button", { name: /Retry/ })).toBeNull()
    expect(within(mismatch).getByText(/Bring the archive again from Online/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /Log/ })).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByText("Still blocked after these steps?")).toBeInTheDocument()
  })

  it("tints a retryable cause amber and a change-first cause red", async () => {
    renderEnd(worstPip())
    await screen.findByRole("heading", { name: "40 packages not in Nexus" })
    expect(block("No answer from Nexus")).toHaveClass("tinted-warn")
    expect(block("Too large for Nexus")).toHaveClass("tinted-bad")
    expect(block("Another file under the same version")).toHaveClass("tinted-bad")
    // The form says it too: the amber cause has one action, the red ones numbered steps.
    expect(within(block("No answer from Nexus")).queryByRole("list", { name: "Steps" })).toBeNull()
    expect(within(within(block("Too large for Nexus")).getByRole("list", { name: "Steps" })).getAllByRole("listitem")).toHaveLength(2)
    expect(within(within(block("Another file under the same version")).getByRole("list", { name: "Steps" })).getAllByRole("listitem")).toHaveLength(3)
  })

  it("names a pip file cause by its wheel", async () => {
    renderEnd(worstPip())
    await screen.findByRole("heading", { name: "40 packages not in Nexus" })
    const large = block("Too large for Nexus")
    for (const [, , file] of TOO_LARGE) expect(within(large).getByText(file)).toBeInTheDocument()
    expect(within(large).getByText("906.4 MB")).toBeInTheDocument()
    expect(large.textContent).toContain("The largest file that went through is 15.9 MB, so the limit sits below the smallest of them.")
    expect(within(block("Another file under the same version")).getByText("idna-3.10-py3-none-any.whl")).toBeInTheDocument()
    expect(within(block("No answer from Nexus")).getByText("Charset_Normalizer")).toBeInTheDocument()
  })

  it("shows Uploaded and by under Nexus's copy only when Nexus says so", async () => {
    renderEnd(worstPip())
    const conflict = await screen.findByRole("region", { name: "Another file under the same version" })
    expect(within(conflict).queryByText(uploadedLine)).toBeNull()
    fireEvent.click(within(conflict).getByRole("button", { name: "Compare" }))
    expect(within(conflict).getByRole("button", { name: "Compare" })).toHaveAttribute("aria-expanded", "true")
    const said = within(conflict).getAllByText(uploadedLine).map((n) => n.textContent)
    expect(said).toEqual(["Uploaded 3 Oct 2025 by ci-publish", "Uploaded 14 Jan 2025"])
    expect(within(conflict).getAllByText("In Nexus")).toHaveLength(3)
  })

  it("opens a grid of 9 names, then Show all", async () => {
    renderEnd(worstPip())
    const quiet = await screen.findByRole("region", { name: "No answer from Nexus" })
    expect(within(quiet).getAllByRole("listitem")).toHaveLength(9)
    const more = within(quiet).getByRole("button", { name: "Show all 31 packages" })
    expect(more).toHaveAttribute("aria-expanded", "false")
    fireEvent.click(more)
    expect(within(quiet).getAllByRole("listitem")).toHaveLength(31)
    expect(within(quiet).getByRole("button", { name: "Show fewer" })).toHaveAttribute("aria-expanded", "true")
  })

  it("sends the cause's files on Retry", async () => {
    const imp = worstPip()
    renderEnd(imp)
    const large = await screen.findByRole("region", { name: "Too large for Nexus" })
    const fetch = fetchAnswer(202, imp)
    fireEvent.click(within(large).getByRole("button", { name: "Retry 6 packages: Too large for Nexus" }))
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled())
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toMatch(/\/imports\/20261105T161200Z-a1000003\/retry$/)
    expect(JSON.parse(init.body as string)).toEqual({ packages: TOO_LARGE.map(([, , file]) => file) })
  })

  it("says why a refused retry was refused", async () => {
    renderEnd(worstPip())
    const quiet = await screen.findByRole("region", { name: "No answer from Nexus" })
    fetchAnswer(409, { title: "Import busy", status: 409, detail: "an attempt of this import is queued or running" })
    fireEvent.click(within(quiet).getByRole("button", { name: "Retry 31 packages: No answer from Nexus" }))
    const alert = await within(quiet).findByRole("alert")
    expect(alert.textContent).toContain("The retry was refused: an attempt of this import is queued or running")
    expect(screen.getByRole("heading", { name: "40 packages not in Nexus" })).toBeInTheDocument()
    expect(block("Too large for Nexus")).toBeInTheDocument()
  })

  it("renders Nexus's text as text", async () => {
    const hostile = "<img src=x onerror=alert(1)>"
    const imp = worstPip(hostile)
    latestAttempt(imp).report.packages.push(pkg("failed", { name: "old", version: "1.0.0", file: "old-1.0.0.tgz", reason: "<b>nexus said</b>" }))
    const { container } = renderEnd(imp)
    const conflict = await screen.findByRole("region", { name: "Another file under the same version" })
    fireEvent.click(within(conflict).getByRole("button", { name: "Compare" }))
    expect(within(conflict).getAllByText(uploadedLine)[0].textContent).toBe(`Uploaded 3 Oct 2025 by ${hostile}`)
    expect(within(block("Not in Nexus")).getByText("<b>nexus said</b>")).toBeInTheDocument()
    expect(container.querySelector("img")).toBeNull()
    expect([...container.querySelectorAll("b")].some((b) => b.textContent === "nexus said")).toBe(false)
  })

  it("names the status Nexus answered to a refused package", async () => {
    const a = attempt("incomplete", [
      ...many(3, "present"),
      pkg("failed", { name: "left-pad", version: "1.3.0", file: "left-pad-1.3.0.tgz", kind: "nexus", nexusStatus: 500, reason: "upload failed: nexus answered 500" }),
      pkg("failed", { name: "is-odd", version: "3.0.1", file: "is-odd-3.0.1.tgz", kind: "nexus", nexusStatus: 401, reason: "upload failed: nexus answered 401" }),
    ])
    renderEnd(make(a))
    const refused = await screen.findByRole("region", { name: "Nexus refused it" })
    expect(refused.textContent).toContain("Nexus answered 401 and 500 to these 2 packages. Its words are in the log.")
  })

  it("copies the request and the paths the steps name", async () => {
    const writeText = vi.fn(async () => {})
    renderEnd(worstPip())
    const large = await screen.findByRole("region", { name: "Too large for Nexus" })
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } })
    fireEvent.click(within(large).getByRole("button", { name: "Copy request" }))
    await within(large).findByText("Copied")
    expect(writeText).toHaveBeenLastCalledWith(`Raise the upload limit of pypi-hosted above 906.4 MB: ${TOO_LARGE.map(([, , file]) => file).join(", ")} were refused as too large.`)
    const conflict = block("Another file under the same version")
    fireEvent.click(within(conflict).getByRole("button", { name: "Copy 3 paths" }))
    await within(conflict).findByText("Copied")
    expect(writeText).toHaveBeenLastCalledWith(
      [
        "packages/idna/3.10/idna-3.10-py3-none-any.whl",
        "packages/pyyaml/6.0.2/PyYAML-6.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "packages/zope-deprecation/5.0/zope.deprecation-5.0-py3-none-any.whl",
      ].join("\n"),
    )
  })

  it("copies the one path of a single conflict", async () => {
    const writeText = vi.fn(async () => {})
    renderEnd(make(attempt("incomplete", [pkg("failed", { name: "@types/node", version: "22.10.2", file: "types-node-22.10.2.tgz", kind: "conflict", reason: conflictReason(sha("a"), sha("b")) })])))
    const conflict = await screen.findByRole("region", { name: "Another file under the same version" })
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } })
    fireEvent.click(within(conflict).getByRole("button", { name: "Copy its path" }))
    await within(conflict).findByText("Copied")
    expect(writeText).toHaveBeenCalledWith("@types/node/-/node-22.10.2.tgz")
  })

  it("names the uploader alone when Nexus gives no date", async () => {
    renderEnd(make(attempt("incomplete", [pkg("failed", { name: "is-number", version: "7.0.0", file: "is-number-7.0.0.tgz", kind: "conflict", reason: conflictReason(sha("a"), sha("b")), nexusUploader: "jo" })])))
    const conflict = await screen.findByRole("region", { name: "Another file under the same version" })
    fireEvent.click(within(conflict).getByRole("button", { name: "Compare" }))
    expect(within(conflict).getAllByText(uploadedLine).map((n) => n.textContent)).toEqual(["Uploaded by jo"])
  })

  it("never counts a package already there as the largest file that went through", async () => {
    const a = attempt("incomplete", [
      pkg("published", { name: "small", file: "small-1.0.0.tgz", size: mb(2) }),
      pkg("present", { name: "huge", file: "huge-1.0.0.tgz", size: mb(500) }),
      pkg("failed", { name: "big", version: "1.0.0", file: "big-1.0.0.tgz", kind: "nexus", nexusStatus: 413, reason: "upload failed: nexus answered 413", size: mb(120) }),
    ])
    renderEnd(make(a))
    const large = await screen.findByRole("region", { name: "Too large for Nexus" })
    expect(large.textContent).toContain("The largest file that went through is 2.0 MB, so the limit sits between the two sizes.")
    expect(large.textContent).not.toContain("500 MB")
  })

  it("leads with the first retryable cause's Retry and keeps the others secondary", async () => {
    const a = attempt("incomplete", [
      pkg("failed", { name: "a", version: "1.0.0", file: "a-1.0.0.tgz", kind: "nexus", reason: "nexus unreachable: EOF" }),
      pkg("failed", { name: "b", version: "1.0.0", file: "b-1.0.0.tgz", kind: "nexus", nexusStatus: 500, reason: "upload failed: nexus answered 500" }),
      pkg("failed", { name: "c", version: "1.0.0", file: "c-1.0.0.tgz", kind: "source", reason: "minio: read failed" }),
      pkg("failed", { name: "d", version: "1.0.0", file: "d-1.0.0.tgz", kind: "nexus", nexusStatus: 413, reason: "upload failed: nexus answered 413", size: MB }),
    ])
    renderEnd(make(a))
    await screen.findByRole("heading", { name: "4 packages not in Nexus" })
    const primary = (title: string) => within(block(title)).getByRole("button", { name: `Retry 1 package: ${title}` }).classList.contains("bg-ink")
    expect(primary("No answer from Nexus")).toBe(true)
    expect(primary("Nexus refused it")).toBe(false)
    expect(primary("Could not read the archive from MinIO")).toBe(false)
    expect(primary("Too large for Nexus")).toBe(false)
  })
})

const KEY = "7".repeat(64)
const ARCHIVE_SHA = "fca8560dd0d96461064dad07a7f18269aff31847b39febe7df471bbd16b4861a"
const REVIEW = { updated: 17, cvesBefore: [2, 8, 10, 5], cvesAfter: [0, 0, 2, 0], carried: 1, jumps: 3 }

/** A complete import of web-portal, created on 26 Nov from a manifest sealed on 20 Oct. */
function done(over: { published?: number; present?: number; removal?: Attempt["removal"]; crossing?: Attempt["report"]["crossing"] | null; name?: string } = {}): Import {
  const packages = [...many(over.published ?? 1271, "published"), ...many(over.present ?? 13, "present")]
  const a = attempt("complete", packages, { removal: over.removal === undefined ? { removed: true, reason: "" } : over.removal })
  a.report.archive = { file: "web-portal-2026-11-25.tar.gz", sha256: ARCHIVE_SHA, size: mb(96.5) }
  a.report.publicKeySha256 = KEY
  a.report.nexus = { url: "https://nexus.example", repository: "npm-internal" }
  if (over.crossing !== null) a.report.crossing = over.crossing ?? { project: over.name ?? "web-portal", sealedAt: "2026-10-20T09:00:00Z", packages: packages.length, review: REVIEW }
  return make(a, { createdAt: "2026-11-26T09:00:00Z", archiveRemoved: a.removal?.removed ?? false })
}

const cells = (markdown: string) => markdown.split("\n").map((line) => line.split("|").slice(1, -1).map((c) => c.trim()))
const day = (at: string) => new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", ...(new Date(at).getFullYear() === new Date().getFullYear() ? {} : { year: "numeric" as const }) }).format(new Date(at))

describe("EndState, every package in Nexus", () => {
  it("shows Done only when every package is in Nexus", async () => {
    renderEnd(done())
    expect(await screen.findByRole("heading", { level: 1, name: "1,284 packages in Nexus" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Done" })).toBeInTheDocument()
    expect(screen.getByText("packages published").parentElement?.textContent).toContain("1,271")
    expect(screen.getByText("already there").parentElement?.textContent).toContain("13")
    expect(screen.getByText("npm-internal")).toBeInTheDocument()
  })

  it.each([
    ["incomplete", attempt("incomplete", [...many(3, "published"), pkg("failed", { kind: "nexus", reason: "nexus unreachable: EOF" })])],
    ["interrupted", attempt("interrupted", many(2, "published"))],
    ["cancelled", attempt("cancelled", many(2, "published"))],
  ])("shows no Done on a %s attempt", async (_name, a) => {
    renderEnd(make(a))
    await screen.findByText("page")
    expect(screen.queryByRole("link", { name: "Done" })).toBeNull()
    expect(screen.queryByText(/^Add this comment/)).toBeNull()
  })

  it("names the crossing by the day of the import", async () => {
    renderEnd(done())
    const by = await screen.findByText(/imported by lea\.martin/)
    expect(by.textContent).toBe(`web-portal · ${day("2026-11-26T09:00:00Z")} · imported by lea.martin`)
    expect(by.textContent).not.toContain(day("2026-10-20T09:00:00Z"))
  })

  it("names a 0.7.0 import by its folder", async () => {
    renderEnd(done({ crossing: null }))
    expect((await screen.findByText(/imported by lea\.martin/)).textContent).toBe("2026-11-05-hr-forms/ · imported by lea.martin")
  })

  it("says whether the archive left the folder", async () => {
    const { unmount } = renderEnd(done())
    const left = await screen.findByText("removed from your folder")
    expect(left.closest("[data-archive-row]")?.textContent).toContain("web-portal-2026-11-25.tar.gz")
    expect(left.closest("[data-archive-row]")?.textContent).toContain("96.5 MB")
    expect(screen.queryByText("Kept in your folder")).toBeNull()
    unmount()

    const kept = renderEnd(done({ removal: { removed: false, reason: "a newer upload replaced it" } }))
    const row = (await screen.findByText("Kept in your folder")).closest("[data-archive-row]") as HTMLElement
    expect(row).toHaveClass("tinted-info")
    expect(row.textContent).toContain("a newer upload replaced it")
    expect(screen.queryByText("removed from your folder")).toBeNull()
    kept.unmount()

    renderEnd(done({ removal: { removed: true, reason: "the archive was removed, but manifest.json.sig could not be and stays in the folder: access denied" } }))
    expect(await screen.findByText("removed from your folder")).toBeInTheDocument()
    expect(screen.getByText(/manifest\.json\.sig could not be/)).toBeInTheDocument()
  })

  it("says the archive's removal is being checked until it is recorded", async () => {
    const imp = done({ removal: undefined })
    latestAttempt(imp).removal = undefined
    renderEnd(imp)
    expect(await screen.findByText("Checking whether it left your folder")).toBeInTheDocument()
    expect(screen.queryByText("removed from your folder")).toBeNull()
    expect(importPollInterval(imp)).toBe(2000)
  })

  it("shows the three checks with their fingerprints", async () => {
    renderEnd(done())
    expect(await screen.findByText("3 passed", { exact: false })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^signing key's sha256/ })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^archive's sha256/ })).toBeInTheDocument()
    expect(screen.getByText("1,284 of 1,284")).toBeInTheDocument()
  })

  it("builds the comment from the signed review", () => {
    const markdown = prComment({ instance: "sealift", crossing: "web-portal · 26 Nov", inNexus: 1284, review: REVIEW, archiveSha256: ARCHIVE_SHA })
    expect(cells(markdown)).toEqual([
      ["sealift", "web-portal · 26 Nov"],
      [expect.stringMatching(/^-+$/), expect.stringMatching(/^-+$/)],
      ["Packages in Nexus", "1,284"],
      ["Packages updated", "17"],
      ["Known CVEs", "25 → 2"],
      ["Carried with a reason", "1"],
      ["Major jumps", "3"],
      ["Archive sha256", ARCHIVE_SHA],
    ])
    expect(new Set(markdown.split("\n").map((line) => line.length)).size).toBe(1)
    expect(markdown).not.toMatch(/Signals/)
    const unchecked = prComment({ instance: "sealift", crossing: "x", inNexus: 1, review: { ...REVIEW, cvesAfter: undefined }, archiveSha256: ARCHIVE_SHA })
    expect(cells(unchecked)[4]).toEqual(["Known CVEs", "25 → not checked together"])
  })

  it("writes not carried by this archive for a 0.7.0 manifest", async () => {
    const markdown = prComment({ instance: "sealift", crossing: "2026-11-05-hr-forms/", inNexus: 12, archiveSha256: ARCHIVE_SHA })
    expect(cells(markdown).slice(2)).toEqual([
      ["Packages in Nexus", "12"],
      ["Packages updated", "not carried by this archive"],
      ["Known CVEs", "not carried by this archive"],
      ["Carried with a reason", "not carried by this archive"],
      ["Major jumps", "not carried by this archive"],
      ["Archive sha256", ARCHIVE_SHA],
    ])
    renderEnd(done({ crossing: null }))
    fireEvent.click(await screen.findByRole("button", { name: "Preview" }))
    expect(screen.getByTestId("pr-comment").textContent).toContain("not carried by this archive")
  })

  it("shows no report row and no Open the report", async () => {
    renderEnd(done())
    fireEvent.click(await screen.findByRole("button", { name: "Preview" }))
    expect(screen.getByRole("button", { name: "Preview" })).toHaveAttribute("aria-expanded", "true")
    const preview = screen.getByTestId("pr-comment").textContent ?? ""
    expect(preview).toContain(`| sealift`)
    expect(preview).toContain(`web-portal · ${day("2026-11-26T09:00:00Z")}`)
    expect(preview).not.toMatch(/Import report|https?:/)
    expect(screen.queryByText(/Open the report/)).toBeNull()
  })

  it("folds the comment and makes Copy the only primary", async () => {
    const { container } = renderEnd(done())
    expect(await screen.findByText("Add this comment to your PR")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Preview" })).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByTestId("pr-comment")).toBeNull()
    expect([...container.querySelectorAll("button, a")].filter((el) => el.classList.contains("bg-ink")).map((el) => el.textContent)).toEqual(["Copy"])
  })

  it("copies the comment and announces Copied", async () => {
    const writeText = vi.fn(async () => {})
    renderEnd(done())
    const copy = await screen.findByRole("button", { name: "Copy the comment" })
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } })
    fireEvent.click(copy)
    const said = await screen.findByText("Copied")
    expect(said.closest("[aria-live=polite]")).not.toBeNull()
    expect(writeText).toHaveBeenCalledWith(prComment({ instance: "sealift", crossing: `web-portal · ${day("2026-11-26T09:00:00Z")}`, inNexus: 1284, review: REVIEW, archiveSha256: ARCHIVE_SHA }))
  })

  it("keeps Done enabled and leading Home", async () => {
    renderEnd(done())
    const link = await screen.findByRole("link", { name: "Done" })
    expect(link).toHaveAttribute("href", "/")
    expect(link).not.toHaveAttribute("aria-disabled")
  })

  it("ends a one-package import in the singular", async () => {
    renderEnd(done({ published: 1, present: 0 }))
    expect(await screen.findByRole("heading", { level: 1, name: "1 package in Nexus" })).toBeInTheDocument()
    expect(screen.getByText("1 of 1")).toBeInTheDocument()
  })

  it("keeps the worst case readable", async () => {
    const name = "customer-onboarding-portal-frontend-next"
    const imp = done({ published: 0, present: 1284, name, removal: { removed: false, reason: "a newer upload replaced it" } })
    const long = { ...ME, user: "Aleksandra Wiśniewska-Kowalczyk" }
    renderEnd(imp, long)
    expect(await screen.findByRole("heading", { level: 1, name: "1,284 packages in Nexus" })).toBeInTheDocument()
    expect(await screen.findByText(/imported by Aleksandra Wiśniewska-Kowalczyk$/)).toBeInTheDocument()
    expect(screen.getByText("packages published").parentElement?.textContent).toContain("0")
    expect(screen.getByText(new RegExp(`^${name} · `))).toHaveClass("[overflow-wrap:anywhere]")
    expect(screen.getByText("Kept in your folder")).toBeInTheDocument()
  })

  it("explains sha512 in a conflict cause", async () => {
    renderEnd(make(attempt("incomplete", [pkg("failed", { name: "is-number", version: "7.0.0", file: "is-number-7.0.0.tgz", kind: "conflict", reason: conflictReason(sha("a"), sha("b")) })])))
    const conflict = await screen.findByRole("region", { name: "Another file under the same version" })
    const info = within(conflict).getByRole("button", { name: "What a sha512 is" })
    expect(info).toHaveAttribute("aria-expanded", "false")
    fireEvent.click(info)
    expect(info).toHaveAttribute("aria-expanded", "true")
    expect(screen.getByText("Each package's own fingerprint, listed in the manifest.")).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: "Read more" })).toBeNull()
  })
})

