import { afterEach, describe, expect, it, vi } from "vitest"

import { ImportApiError, importFetch, SessionEnded } from "./client"

afterEach(() => vi.restoreAllMocks())

const json = (body: unknown, init: ResponseInit = {}, type = "application/json") =>
  new Response(JSON.stringify(body), { ...init, headers: { "Content-Type": type } })

describe("the import client", () => {
  it("calls only the import contract", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(json({})))
    await importFetch("/me")
    await importFetch("/archives")
    await importFetch("/imports")
    await importFetch("/imports/20261106T101500Z-3f9a0c1d")
    await importFetch("/imports/20261106T101500Z-3f9a0c1d/retry", { method: "POST" })
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/me",
      "/api/archives",
      "/api/imports",
      "/api/imports/20261106T101500Z-3f9a0c1d",
      "/api/imports/20261106T101500Z-3f9a0c1d/retry",
    ])
    for (const path of ["/projects", "/settings", "/tools", "/jobs/current/events", "/imports/../projects", "/imports/a/b", "/imports/x?y=1"]) {
      await expect(importFetch(path as "/me")).rejects.toThrow("not part of the import contract")
    }
    expect(fetchMock).toHaveBeenCalledTimes(5)
  })

  it("401 ends the session", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ title: "Token rejected", status: 401 }, { status: 401 }, "application/problem+json"))
    await expect(importFetch("/me")).rejects.toBeInstanceOf(SessionEnded)
  })

  it("a redirect to the gateway's sign-in ends the session", async () => {
    // A browser withholds the answer of a redirect it was told not to follow: type "opaqueredirect", status 0.
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ type: "opaqueredirect", status: 0, ok: false, headers: new Headers() } as Response)
    await expect(importFetch("/archives")).rejects.toBeInstanceOf(SessionEnded)
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: "manual" })
  })

  it("an HTML 200 ends the session", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("<html><title>Sign in</title></html>", { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }))
    await expect(importFetch("/me")).rejects.toBeInstanceOf(SessionEnded)
  })

  it.each([
    [502, "<html>bad gateway</html>", "text/html"],
    [503, "Service Unavailable", "text/plain"],
    [504, "", ""],
    [500, "<html>oops</html>", "text/html; charset=utf-8"],
  ])("a %i answer that is not JSON is an API failure, not the end of the session", async (status, body, type) => {
    const headers = type ? { "Content-Type": type } : undefined
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(body, { status, headers }))
    const error = await importFetch("/imports").catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ImportApiError)
    expect(error).not.toBeInstanceOf(SessionEnded)
    expect((error as ImportApiError).status).toBe(status)
    expect((error as ImportApiError).problem?.detail).toMatch(/could not reach the import service/)
  })

  it("a redirect that the browser did report, and a non-JSON answer below 500, still end the session", async () => {
    const redirect = { type: "basic", status: 302, ok: false, headers: new Headers({ Location: "/oauth2/sign_in" }) } as Response
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(redirect)
    await expect(importFetch("/archives")).rejects.toBeInstanceOf(SessionEnded)
    fetchMock.mockResolvedValue(new Response("<html>forbidden</html>", { status: 403, headers: { "Content-Type": "text/html" } }))
    await expect(importFetch("/archives")).rejects.toBeInstanceOf(SessionEnded)
    fetchMock.mockResolvedValue(new Response("<html>missing</html>", { status: 404, headers: { "Content-Type": "text/html" } }))
    await expect(importFetch("/archives")).rejects.toBeInstanceOf(SessionEnded)
  })

  it("a Problem keeps its status and detail", async () => {
    const problem = { type: "about:blank", title: "Archive list failed", status: 502, detail: "MinIO refused the call" }
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json(problem, { status: 502 }, "application/problem+json"))
    const error = await importFetch("/archives").catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ImportApiError)
    expect((error as ImportApiError).status).toBe(502)
    expect((error as ImportApiError).problem?.detail).toBe("MinIO refused the call")
    expect((error as ImportApiError).message).toBe("MinIO refused the call")
  })

  it("keeps a JSON body of an import as is", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ user: "alice" }))
    await expect(importFetch("/me")).resolves.toEqual({ user: "alice" })
  })

  it("a network failure", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"))
    const error = await importFetch("/me").catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ImportApiError)
    expect((error as ImportApiError).status).toBe(0)
    expect((error as ImportApiError).problem?.detail).toMatch(/did not reach the server/)
  })
})
