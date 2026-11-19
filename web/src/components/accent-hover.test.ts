import { describe, expect, it } from "vitest"

const sources = import.meta.glob(["./**/*.tsx", "!./**/*.test.tsx"], { query: "?raw", import: "default", eager: true }) as Record<string, string>

describe("accent buttons", () => {
  it("keep the label contrast on hover", () => {
    // hover:opacity blends the accent fill with the page and drops the label below AA.
    const offenders = Object.entries(sources)
      .filter(([, text]) => text.split("\n").some((line) => /\bbg-accent\b/.test(line) && /\bhover:opacity-/.test(line)))
      .map(([file]) => file)
    expect(Object.keys(sources).length).toBeGreaterThan(10)
    expect(offenders).toEqual([])
  })
})
