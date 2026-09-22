import { afterEach, describe, expect, it, vi } from "vitest"

import { ApiError, apiFetch, apiFetchProblem, ProblemError } from "./client"
import { createProject, ProjectUploadError } from "./projects"

afterEach(() => vi.restoreAllMocks())

// fetch rejects with a TypeError when the server cannot be reached; every
// screen only displays typed errors, so this must never leak as is.
describe("an unreachable server", () => {
  it("reaches apiFetch callers as an ApiError that says so", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"))
    const error = await apiFetch("/projects").catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).problem?.title).toBe("sealift is not reachable")
  })

  it("reaches apiFetchProblem callers as a ProblemError", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"))
    await expect(apiFetchProblem("/settings", { method: "PUT" })).rejects.toBeInstanceOf(ProblemError)
  })

  it("reaches an upload as a ProjectUploadError", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"))
    await expect(createProject(new File(["{}"], "package.json"))).rejects.toBeInstanceOf(ProjectUploadError)
  })
})
