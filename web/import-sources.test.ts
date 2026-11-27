// @vitest-environment node
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { dirname, join, normalize, relative, resolve } from "node:path"

import { expect, test } from "vitest"

// The import build's root is web/import, so Tailwind generates a class only
// from the files index.css names with @source. A shared component the screens
// import but the list misses renders without its sizes and colours.
const here = resolve(import.meta.dirname, "src/import")
const src = resolve(here, "..")

function sources(): string[] {
  const css = readFileSync(join(here, "index.css"), "utf8")
  return [...css.matchAll(/@source "([^"]+)";/g)].map((m) => resolve(here, m[1]))
}

function resolveImport(from: string, spec: string): string | undefined {
  let base: string
  if (spec.startsWith("@/")) base = join(src, spec.slice(2))
  else if (spec.startsWith(".")) base = resolve(dirname(from), spec)
  else return undefined
  for (const ext of [".tsx", ".ts", "/index.tsx", "/index.ts"]) {
    if (existsSync(base + ext)) return normalize(base + ext)
  }
  return undefined
}

function entries(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return entries(path)
    return /\.tsx?$/.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

function reached(): Set<string> {
  const seen = new Set<string>()
  const todo = entries(here)
  while (todo.length > 0) {
    const file = todo.pop()!
    if (seen.has(file)) continue
    seen.add(file)
    for (const m of readFileSync(file, "utf8").matchAll(/from "([^"]+)"/g)) {
      const next = resolveImport(file, m[1])
      if (next) todo.push(next)
    }
  }
  return seen
}

test("every component the import screens reach is a Tailwind source of their build", () => {
  const roots = sources()
  const covered = (file: string) => roots.some((root) => file === root || !relative(root, file).startsWith(".."))
  const missing = [...reached()].filter((f) => f.endsWith(".tsx") && !covered(f)).map((f) => relative(src, f))
  expect(missing).toEqual([])
})
