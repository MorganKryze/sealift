import { afterEach, describe, expect, it, vi } from "vitest"

import type { Analysis, Export } from "@/api/projects"
import { byName, crossingDay, crossingName, crossingState, readSeal } from "@/lib/crossings"

const NOW = new Date(2026, 10, 25, 12, 0)
const local = (month: number, day: number, hour = 10, minute = 0, year = 2026) => new Date(year, month - 1, day, hour, minute).toISOString()
const run = (id: string, createdAt: string) => ({ id, createdAt })

const SHA = "9c1e4b7a3f5d2c8e1a6b0d4f7c2e9a5b3d8f1c6e0a4b7d2f9c5e8a1b3d6f1a3b"
const KEY = `b7e3d1a9${"0".repeat(48)}36f4c218`

function analysis(state: Analysis["state"], failure?: Analysis["failure"]): Analysis {
  return { id: "20261120T101500Z", projectId: "web-portal", state, createdAt: local(11, 20), failure }
}

function exported(state: Export["state"], failure?: Export["failure"]): Export {
  return { id: "20261120T102000Z", projectId: "web-portal", analysisId: "20261120T101500Z", state, createdAt: local(11, 20, 10, 20), failure }
}

function answer(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }))
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("crossing names", () => {
  it("names a crossing by project and day", () => {
    const one = run("a", local(11, 20))
    expect(crossingName("web-portal", one, [one], NOW)).toBe("web-portal · 20 Nov")
  })

  it("names a second analysis of the same day with · 2", () => {
    const first = run("a", local(11, 23, 9))
    const second = run("b", local(11, 23, 15))
    const other = run("c", local(11, 22, 15))
    const all = [second, other, first]
    expect(crossingName("web-portal", first, all, NOW)).toBe("web-portal · 23 Nov")
    expect(crossingName("web-portal", second, all, NOW)).toBe("web-portal · 23 Nov · 2")
    expect(crossingName("web-portal", other, all, NOW)).toBe("web-portal · 22 Nov")
  })

  it("counts the day in local time", () => {
    const late = run("a", local(11, 20, 23, 50))
    const early = run("b", local(11, 21, 0, 10))
    expect(crossingName("web-portal", early, [late, early], NOW)).toBe("web-portal · 21 Nov")
    const morning = run("c", local(11, 22, 0, 5))
    const night = run("d", local(11, 22, 23, 55))
    expect(crossingName("web-portal", night, [morning, night], NOW)).toBe("web-portal · 22 Nov · 2")
  })

  it("adds the year outside the current year", () => {
    expect(crossingDay(local(11, 28, 10, 0, 2025), NOW)).toBe("28 Nov 2025")
    expect(crossingDay(local(12, 4, 10, 0, 2025), NOW)).toBe("4 Dec 2025")
    expect(crossingDay(local(10, 28), NOW)).toBe("28 Oct")
  })

  it("never shows an hour", () => {
    const at = run("a", local(11, 20, 14, 7))
    const name = crossingName("web-portal", at, [at], NOW)
    expect(name).not.toMatch(/\d{1,2}:\d{2}/)
    expect(name).not.toMatch(/14|07/)
  })
})

describe("crossing states", () => {
  it("reads every analysis and export state in words", () => {
    expect(crossingState()).toEqual({ label: "Not analysed yet", kind: "new" })
    expect(crossingState(analysis("queued"))).toEqual({ label: "Queued", kind: "queued" })
    expect(crossingState(analysis("running"))).toEqual({ label: "Analysing", kind: "running" })
    expect(crossingState(analysis("cancelled"))).toEqual({ label: "Cancelled", kind: "cancelled" })
    expect(crossingState(analysis("done"))).toEqual({ label: "Review waits", kind: "waits" })
    expect(crossingState(analysis("done"), exported("queued"))).toEqual({ label: "Queued", kind: "queued" })
    expect(crossingState(analysis("done"), exported("running"))).toEqual({ label: "Sealing", kind: "running" })
    expect(crossingState(analysis("done"), exported("done"))).toEqual({ label: "Sealed", kind: "sealed" })
    expect(crossingState(analysis("done"), exported("cancelled"))).toEqual({ label: "Cancelled", kind: "cancelled" })
  })

  it("reads a failed analysis as failed at Analyse", () => {
    expect(crossingState(analysis("failed", { step: "scan", message: "trivy exited 1" }))).toEqual({ label: "Failed at Analyse", kind: "failed" })
    expect(crossingState(analysis("interrupted"))).toEqual({ label: "Failed at Analyse", kind: "failed" })
  })

  it("reads a failed export as failed and names the step", () => {
    const failed = exported("failed", { step: "download", message: "lodash-4.17.21.tgz: sha512 mismatch" })
    expect(crossingState(analysis("done"), failed)).toEqual({ label: "Failed at Seal", kind: "failed" })
    expect(crossingState(analysis("done"), exported("interrupted"))).toEqual({ label: "Failed at Seal", kind: "failed" })
  })
})

describe("readSeal", () => {
  it("reads the archive's sha256 and the signature's key from the seal files", async () => {
    const fetch = vi.fn((url: string) =>
      url.endsWith("/manifest.json")
        ? answer({ analysisId: "a", archive: { sha256: SHA, size: 4096 }, packages: [] })
        : answer({ algorithm: "ed25519", publicKeySha256: KEY, signature: "c2ln" }),
    )
    vi.stubGlobal("fetch", fetch)
    await expect(readSeal("web-portal", "20261120T102000Z")).resolves.toEqual({ archiveSha256: SHA, keySha256: KEY, figures: { packages: 0, size: 4096 } })
    expect(fetch.mock.calls.map(([url]) => url).sort()).toEqual([
      "/api/projects/web-portal/exports/20261120T102000Z/files/manifest.json",
      "/api/projects/web-portal/exports/20261120T102000Z/files/manifest.json.sig",
    ])
  })

  it("reads the package count and size from the manifest", async () => {
    const packages = Array.from({ length: 1284 }, (_, i) => ({ name: `lib-${i}`, version: "1.0.0" }))
    vi.stubGlobal("fetch", (url: string) =>
      url.endsWith("/manifest.json") ? answer({ archive: { sha256: SHA, size: 96_500_000 }, packages }) : answer({ publicKeySha256: KEY }),
    )
    await expect(readSeal("p", "e")).resolves.toMatchObject({ figures: { packages: 1284, size: 96_500_000 } })
  })

  it("reads a manifest that lacks them as unknown, never zero", async () => {
    for (const manifest of [
      { archive: { sha256: SHA } },
      { archive: { sha256: SHA, size: -1 }, packages: "1284" },
      { archive: { sha256: SHA, size: 12.5 }, packages: { length: 3 } },
      { archive: { sha256: SHA, size: "4096" }, packages: null },
    ]) {
      vi.stubGlobal("fetch", (url: string) => (url.endsWith("/manifest.json") ? answer(manifest) : answer({ publicKeySha256: KEY })))
      const seal = await readSeal("p", "e")
      expect(seal.figures).toEqual({})
      expect(seal.figures.packages).toBeUndefined()
      expect(seal.figures.size).toBeUndefined()
    }
  })

  it("refuses a sha256 that is not 64 lowercase hex characters", async () => {
    for (const bad of [SHA.toUpperCase(), SHA.slice(1), `${SHA}0`, `${SHA.slice(0, 63)}g`, ""]) {
      vi.stubGlobal("fetch", (url: string) =>
        url.endsWith("/manifest.json") ? answer({ archive: { sha256: bad } }) : answer({ publicKeySha256: KEY }),
      )
      await expect(readSeal("p", "e")).rejects.toThrow("manifest.json")
      vi.stubGlobal("fetch", (url: string) => (url.endsWith("/manifest.json") ? answer({ archive: { sha256: SHA } }) : answer({ publicKeySha256: bad })))
      await expect(readSeal("p", "e")).rejects.toThrow("manifest.json.sig")
    }
  })

  it("names the server's cause when a seal file does not read", async () => {
    vi.stubGlobal("fetch", () => answer({ title: "Not Found", status: 404, detail: "no file manifest.json in this export" }, 404))
    await expect(readSeal("p", "e")).rejects.toThrow("no file manifest.json in this export")
  })
})

describe("byName", () => {
  it("sorts names without case or punctuation", () => {
    const names = ["web-portal", "@acme/x", "Billing_api", "admin-console", "billing-api-2", "Reporting_Jobs", "plone.intranet"]
    expect([...names].sort(byName)).toEqual(["@acme/x", "admin-console", "Billing_api", "billing-api-2", "plone.intranet", "Reporting_Jobs", "web-portal"])
  })
})
