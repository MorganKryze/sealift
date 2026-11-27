import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { useState } from "react"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Archive } from "@/import/api/queries"
import type { Attempt, Import } from "@/import/lib/outcome"

import { RefusedDetails, RefusedPanel } from "./refused-panel"

afterEach(() => {
  vi.unstubAllGlobals()
})

const TRUSTED = "c4a81e07b95d3f62a0e8174cd29b5f03e6a7c18d40b2f95e7d36a01c8b4e2f75"
const SIGNED = "7d3f0a9c51e28b64c0f7a13d9e5b2846f1c08a7d3e6b9205a4d71c8e0f3b6a92"
const WANT = "3b9e14c7a05d82f6e1c4b7a930d58e21f6a0c39b7d42e815c0f9a3d6b28e71a4"
const GOT = "e80f5c21d7a94b36c2e1f08d5a7b39c46d0e2a81f5b7c93e04a6d18c2f7b5e09"

const FOLDER = "packages/npm/billing-api-2026-11-24/"

function archive(over: Partial<Archive> = {}): Archive {
  return {
    key: `${FOLDER}packages_npm.tar.gz`, ecosystem: "npm", size: 225_023_590, modified: "2026-11-24T16:38:00Z", importable: false,
    reason: "its signature does not match its manifest", signature: "mismatch",
    files: [
      { name: "packages_npm.tar.gz", size: 225_023_590, modified: "2026-11-24T16:38:00Z" },
      { name: "manifest.json", size: 421_888, modified: "2026-11-24T16:52:00Z" },
      { name: "manifest.json.sig", size: 214, modified: "2026-11-24T16:40:00Z" },
    ],
    ...over,
  }
}

function refusedImport(reason: string, over: Partial<Import> = {}): Import {
  const a: Attempt = {
    n: 1, status: "ended", outcome: "refused", endedAt: "2026-11-26T11:52:00Z",
    report: {
      outcome: "refused", reason, unencrypted: false, importVersion: "0.8.0", archive: { file: "packages_npm.tar.gz", sha256: WANT, size: 1_200_000_000 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages: [], archiveChecked: false,
    },
  }
  return {
    id: "20261126T115200Z-a3000001", createdAt: "2026-11-26T11:52:00Z", expectedSha256: "", outcome: "refused", archiveRemoved: false, attempts: [a],
    archive: { key: `${FOLDER}packages_npm.tar.gz`, etag: '"a"', size: 1_200_000_000 },
    manifest: { key: `${FOLDER}manifest.json`, etag: '"b"', size: 2_400_000 },
    signature: { key: `${FOLDER}manifest.json.sig`, etag: '"c"', size: 214 },
    ...over,
  }
}

const rows = () => within(screen.getByRole("list", { name: "Files" })).getAllByRole("listitem")

describe("the refused panel", () => {
  it("titles the panel by its row's name", () => {
    render(<RefusedPanel archive={archive()} trusted={TRUSTED} name="billing-api-2026-11-24/" open onClose={() => {}} />)
    const dialog = screen.getByRole("dialog")
    expect(within(dialog).getByRole("heading", { name: "Refused" })).toBeInTheDocument()
    expect(within(dialog).getByRole("heading", { level: 3 })).toHaveTextContent("billing-api-2026-11-24/")
    expect(dialog).toHaveTextContent(`${FOLDER} · 3 files`)
    expect(dialog).toHaveTextContent("The signature does not match the manifest.")
    expect(dialog).toHaveTextContent("Nothing reached Nexus. Stopped at the signature check.")
  })

  it("lists the three files in Sealed's order with their states", () => {
    render(<RefusedDetails archive={archive()} trusted={TRUSTED} />)
    expect(rows().map((r) => r.querySelector("[data-file-name]")?.textContent)).toEqual(["packages_npm.tar.gz", "manifest.json", "manifest.json.sig"])
    expect(rows()[0]).toHaveTextContent("Not checked")
    // The two files to bring again share one closed red shape and one state.
    const pair = screen.getByTestId("bring-again")
    expect(pair).toHaveClass("tinted-bad")
    expect(within(pair).getAllByRole("listitem")).toHaveLength(2)
    expect(pair).toHaveTextContent("Do not match")
    expect(rows()[1]).toHaveTextContent("412.0 KB")
    expect(screen.getByText("What to do").nextElementSibling).toHaveTextContent("Download the files marked Do not match again from Online.")
    expect(screen.getByText("If the new copy is refused too")).toBeInTheDocument()
  })

  it("keeps the key line neutral", () => {
    render(<RefusedDetails archive={archive()} trusted={TRUSTED} />)
    const line = screen.getByTestId("named-key")
    expect(line).toHaveTextContent("manifest.json.sig names the key trusted here")
    expect(line.querySelector(".lucide-key-round")).not.toBeNull()
    expect(line.querySelector(".lucide-check, .lucide-circle-check, .text-ok")).toBeNull()
    expect(within(line).getByRole("button", { name: /^Key named in manifest.json.sig/ })).toBeInTheDocument()
  })

  it("shows the manifest's size and the expected sha256", () => {
    const short = archive({ reason: "the archive does not match its manifest", signature: "verified", declaredSize: 100_977_869, size: 85_773_517, crossing: { project: "notifications-worker", sealedAt: "2026-11-25T09:00:00Z", packages: 840 } })
    render(<RefusedDetails archive={short} imp={refusedImport("archive size is 81800000 bytes, the manifest says 96300000", { expectedSha256: WANT })} trusted={TRUSTED} />)
    expect(screen.getByText("The archive does not match its manifest.")).toBeInTheDocument()
    expect(rows()[0]).toHaveTextContent("Differs")
    expect(rows()[0]).toHaveTextContent("The manifest says 96.3 MB")
    expect(within(rows()[0]).getByRole("button", { name: /^Expected sha256/ })).toBeInTheDocument()
    expect(rows()[1]).toHaveTextContent("Passed")
    expect(rows()[2]).toHaveTextContent("Passed")
  })

  it("shows both keys with the characters that differ", () => {
    render(<RefusedDetails archive={archive({ reason: "signed with a key this side does not trust", signature: "unknown-key", signerKeySha256: SIGNED })} trusted={TRUSTED} />)
    expect(screen.getByText("Signed with a key this side does not trust.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^Signed with/ })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^Trusted here/ })).toBeInTheDocument()
    const differ = [...SIGNED].filter((c, i) => c !== TRUSTED[i]).length
    expect(screen.getByText(/characters differ/).closest("p")).toHaveTextContent(`${differ} of 64 characters differ`)
    expect(screen.queryByRole("list", { name: "Files" })).toBeNull()
    expect(screen.getByText(/^Uploaded/)).toBeInTheDocument()
    expect(screen.getByText("What to do").nextElementSibling).toHaveTextContent("Send your administrators the details, then remove the three files from your folder.")
    expect(screen.getByText("To trust another key")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Compare" }))
    expect(screen.getByRole("textbox", { name: "sha256 from the connected side" })).toBeInTheDocument()
  })

  it("names an unknown key only by a fingerprint of 64 hex", () => {
    render(<RefusedDetails archive={archive({ reason: "signed with a key this side does not trust", signature: "unknown-key", signerKeySha256: "<b>not a key</b>" })} trusted={TRUSTED} />)
    expect(screen.queryByRole("button", { name: /^Signed with/ })).toBeNull()
    expect(screen.getByText("Not named in manifest.json.sig")).toBeInTheDocument()
  })

  it("copies the details", async () => {
    const writeText = vi.fn(async () => {})
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } })
    render(<RefusedDetails archive={archive()} trusted={TRUSTED} />)
    fireEvent.click(screen.getByRole("button", { name: "Copy details" }))
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    const text = (writeText.mock.calls[0] as unknown as [string])[0]
    expect(text).toMatch(/^Refused archive on Offline, /)
    expect(text).toContain(`Folder: ${FOLDER}`)
    expect(text).toContain("Reason: the signature does not match the manifest.")
    expect(text).toContain("Nothing reached Nexus. Stopped at the signature check.")
    expect(text).toContain(`Key named in manifest.json.sig: sha256 ${TRUSTED} (the key trusted here)`)
    expect(text).toMatch(/packages_npm\.tar\.gz +214\.6 MB +uploaded .+ +not checked/)
    expect(text).toMatch(/manifest\.json +412\.0 KB +uploaded .+ +do not match/)
    expect(text).toContain("Download again from Online: manifest.json, manifest.json.sig")
    expect(await screen.findByRole("status")).toHaveTextContent("Copied")
    expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument()
  })

  it("gives the focus back to the row", async () => {
    function Home() {
      const [open, setOpen] = useState(false)
      const [row, setRow] = useState<HTMLButtonElement | null>(null)
      return (
        <>
          <button ref={setRow} type="button" onClick={() => setOpen(true)}>
            Open billing-api-2026-11-24/
          </button>
          <RefusedPanel archive={archive()} trusted={TRUSTED} open={open} onClose={() => setOpen(false)} returnFocus={row} />
        </>
      )
    }
    render(<Home />)
    const opener = screen.getByRole("button", { name: "Open billing-api-2026-11-24/" })
    opener.focus()
    fireEvent.click(opener)
    const dialog = await screen.findByRole("dialog")
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(opener).toHaveFocus()
  })

  it("shows the same content on a refused import's page", () => {
    render(<RefusedDetails imp={refusedImport(`archive sha256 ${GOT} differs from the manifest's ${WANT}`)} trusted={TRUSTED} />)
    expect(screen.getByText("The archive does not match its manifest.")).toBeInTheDocument()
    expect(screen.getByText(/Nothing reached Nexus/).closest("p")).toHaveTextContent("Nothing reached Nexus. Stopped at the archive check.")
    expect(rows().map((r) => r.querySelector("[data-file-name]")?.textContent)).toEqual(["packages_npm.tar.gz", "manifest.json", "manifest.json.sig"])
    expect(rows()[0]).toHaveTextContent("Differs")
    expect(rows()[0]).toHaveTextContent("Same size as the manifest says")
    expect(screen.getByText("What to do").nextElementSibling).toHaveTextContent("Download the file marked Differs again from Online.")
    expect(screen.getByRole("button", { name: "Copy details" })).toBeInTheDocument()
  })

  it("tells a typed sha256 that differs from an archive that differs from its manifest", () => {
    render(<RefusedDetails imp={refusedImport(`archive sha256 ${GOT} differs from the expected sha256 ${WANT}`, { expectedSha256: WANT })} trusted={TRUSTED} />)
    expect(screen.getByText("The archive matches its manifest. The sha256 you typed differs.")).toBeInTheDocument()
    expect(screen.queryByText("The archive does not match its manifest.")).toBeNull()
    expect(rows().map((r) => r.textContent?.includes("Passed"))).toEqual([true, true, true])
    expect(screen.getByTestId("sha256-compare")).toHaveTextContent("Typed")
    expect(screen.getByText("What to do").nextElementSibling).toHaveTextContent("Check the value you copied from the Sealed page.")
    expect(screen.getByText("What to do").nextElementSibling).not.toHaveTextContent("again from")
  })

  it("reads two sha256 only from the archive check's own words", () => {
    const { unmount } = render(<RefusedDetails imp={refusedImport(`archive sha256 ${GOT} differs from the manifest's ${WANT}`)} trusted={TRUSTED} />)
    const pair = screen.getByTestId("sha256-compare")
    expect(within(pair).getByTestId("in-minio")).toHaveTextContent(GOT.match(/.{8}/g)!.join(" "))
    expect(within(pair).getByTestId("expected")).toHaveTextContent(WANT.match(/.{8}/g)!.join(" "))
    expect(pair.querySelectorAll("mark").length).toBe([...GOT].filter((c, i) => c !== WANT[i]).length * 2)
    unmount()
    for (const reason of [
      `the archive's sha256 is ${GOT} but the expected sha256 is ${WANT}`,
      `a note: archive sha256 ${GOT} differs from the manifest's ${WANT}`,
      `archive sha256 ${GOT.toUpperCase()} differs from the manifest's ${WANT}`,
    ]) {
      const view = render(<RefusedDetails imp={refusedImport(reason)} trusted={TRUSTED} />)
      expect(screen.queryByTestId("sha256-compare")).toBeNull()
      expect(screen.getByText(`${reason.charAt(0).toUpperCase()}${reason.slice(1)}.`)).toBeInTheDocument()
      view.unmount()
    }
  })
})
