import { describe, expect, it } from "vitest"

import { nextAction } from "./kinds"

describe("next action per kind", () => {
  it.each([
    ["interrupted", "as-is", /Retry the import/],
    ["source", "as-is", /Retry the import/],
    ["conflict", "change-first", /delete it in Nexus.*then retry/i],
    ["mismatch", "change-first", /Export the archive again/],
    ["nexus", "change-first", /import account may upload.*then retry/i],
    ["local", "change-first", /Ask the administrator.*data volume.*settings file/i],
  ])("%s is in group %s", (kind, group, words) => {
    const got = nextAction(kind)
    expect(got.group).toBe(group)
    expect(got.words).toMatch(words)
  })

  it.each([[undefined], [""], ["something-new"]])("no known kind (%s) gives the general words", (kind) => {
    expect(nextAction(kind)).toEqual({ group: "unknown", words: "Read the reason: it names what failed. Fix that, then retry." })
  })
})
