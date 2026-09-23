// Checks that every relative link and anchor in the repository's Markdown resolves,
// or, with --run, runs the sh blocks marked <!-- run --> against a live sealift.
// Usage: node scripts/check-docs.mjs [root]
//        node scripts/check-docs.mjs --run <url> [root]
import { spawnSync } from "node:child_process"
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

// Yields each fenced block with its language, code, and the comment markers
// on the lines above it, blank lines allowed in between.
function* blocks(text) {
  const lines = text.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const open = lines[i].match(/^(```|~~~)(\S*)/)
    if (!open) continue
    const markers = []
    for (let j = i - 1; j >= 0; j--) {
      const m = lines[j].match(/^<!--\s*(.*?)\s*-->$/)
      if (m) markers.unshift(m[1])
      else if (lines[j].trim() !== "") break
    }
    let end = i + 1
    while (end < lines.length && !lines[end].startsWith(open[1])) end++
    yield { line: i + 1, lang: open[2], code: lines.slice(i + 1, end).join("\n"), markers }
    i = end
  }
}

export function runExamples(root, url) {
  let ran = 0
  const failures = []
  for (const file of markdownFiles(root).sort()) {
    for (const block of blocks(readFileSync(file, "utf8"))) {
      if (block.lang !== "sh" || !block.markers.includes("run")) continue
      ran++
      const code = block.code.replaceAll("http://localhost:8080", url)
      const r = spawnSync("sh", ["-e", "-c", code], { encoding: "utf8", timeout: 60_000 })
      const output = `${r.stdout ?? ""}${r.stderr ?? ""}`
      const expects = block.markers.filter((m) => m.startsWith("expect:")).map((m) => m.slice(7).trim())
      const missing = expects.find((e) => !output.includes(e))
      if (r.status !== 0 || missing !== undefined) {
        const reason = r.status !== 0 ? `exit ${r.status ?? r.signal}` : `output lacks "${missing}"`
        failures.push({ file: relative(root, file), line: block.line, reason, output })
      }
    }
  }
  return { ran, failures }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  if (args[0] === "--run") {
    const { ran, failures } = runExamples(args[2] ?? ".", args[1])
    for (const f of failures) console.error(`${f.file}:${f.line}: ${f.reason}\n${f.output}`)
    console.log(`${ran} examples run, ${failures.length} failed`)
    process.exit(failures.length ? 1 : 0)
  }
  const failures = checkLinks(args[0] ?? ".")
  for (const f of failures) console.error(`${f.file}:${f.line}: ${f.target}`)
  process.exit(failures.length ? 1 : 0)
}
