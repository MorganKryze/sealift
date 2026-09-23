// Checks that every relative link and anchor in the repository's Markdown resolves.
// Usage: node scripts/check-docs.mjs [root]
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { dirname, join, relative, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const SKIP = new Set(["node_modules", ".git", ".atelier", "graphify-out", "dist"])

// GitHub's heading anchor rule: lowercase, drop punctuation, spaces to hyphens.
export function slug(heading) {
  return heading
    .toLowerCase()
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-")
}

function markdownFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    if (SKIP.has(name)) return []
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return markdownFiles(path)
    return name.endsWith(".md") ? [path] : []
  })
}

// Yields the lines outside fenced code blocks, with their 1-based numbers.
function* prose(text) {
  let fence = null
  for (const [i, line] of text.split("\n").entries()) {
    const open = line.match(/^\s*(```|~~~)/)
    if (open) {
      if (fence === null) fence = open[1]
      else if (open[1] === fence) fence = null
      continue
    }
    if (fence === null) yield [i + 1, line]
  }
}

function anchors(text) {
  const seen = new Map()
  const out = new Set()
  for (const [, line] of prose(text)) {
    const h = line.match(/^#{1,6}\s+(.*?)\s*#*\s*$/)
    if (!h) continue
    const base = slug(h[1])
    const n = seen.get(base) ?? 0
    seen.set(base, n + 1)
    out.add(n === 0 ? base : `${base}-${n}`)
  }
  return out
}

export function checkLinks(root) {
  const cache = new Map()
  const anchorsOf = (file) => {
    if (!cache.has(file)) cache.set(file, anchors(readFileSync(file, "utf8")))
    return cache.get(file)
  }
  const failures = []
  for (const file of markdownFiles(root).sort()) {
    for (const [line, raw] of prose(readFileSync(file, "utf8"))) {
      const text = raw.replace(/`[^`]*`/g, "")
      const targets = [
        ...[...text.matchAll(/\]\(<?([^)\s>]+)>?(?:\s+"[^"]*")?\)/g)].map((m) => m[1]),
        ...[...text.matchAll(/<a\s[^>]*href="([^"]+)"/g)].map((m) => m[1]),
        ...[...text.matchAll(/<img\s[^>]*src="([^"]+)"/g)].map((m) => m[1]),
      ]
      for (const target of targets) {
        if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue
        const [path, fragment] = target.split("#")
        const dest = path === "" ? file : resolve(dirname(file), decodeURI(path))
        const ok = existsSync(dest) && (!fragment || !dest.endsWith(".md") || anchorsOf(dest).has(fragment))
        if (!ok) failures.push({ file: relative(root, file), line, target })
      }
    }
  }
  return failures
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ?? "."
  const failures = checkLinks(root)
  for (const f of failures) console.error(`${f.file}:${f.line}: ${f.target}`)
  process.exit(failures.length ? 1 : 0)
}
