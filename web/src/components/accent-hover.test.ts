import { readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sources(path)
    return /\.tsx$/.test(name) && !/\.test\.tsx$/.test(name) ? [path] : []
  })
}

describe("accent buttons", () => {
  it("keep the label contrast on hover", () => {
    // hover:opacity blends the accent fill with the page and drops the label below AA.
    const offenders = sources(__dirname).filter((file) => !file.endsWith("imports-list.tsx") &&
      readFileSync(file, "utf8")
        .split("\n")
        .some((line) => /\bbg-accent\b/.test(line) && /\bhover:opacity-/.test(line)),
    )
    expect(offenders).toEqual([])
  })
})
