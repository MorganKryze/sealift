// Checks that every relative link and anchor in the repository's Markdown resolves,
// or, with --run, runs the sh blocks marked <!-- run --> against a live sealift.
// Usage: node scripts/check-docs.mjs [root]
//        node scripts/check-docs.mjs --run <url> [root]
import { spawnSync } from "node:child_process"
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { dirname, join, relative, resolve } from "node:path"
import { fileURLToPath } from "node:url"

// GitHub's heading anchor rule: lowercase, drop punctuation, spaces to hyphens.
export function slug(heading) {
  return heading
    .toLowerCase()
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-")
}

// Lists the Markdown files git would track under root, or walks root when it
// is not a git work tree, skipping dot-directories, node_modules and dist.
function markdownFiles(root) {
  const git = spawnSync("git", ["-C", root, "ls-files", "-co", "--exclude-standard", "*.md"], { encoding: "utf8" })
  if (git.status === 0) return git.stdout.split("\n").filter(Boolean).map((f) => join(root, f))
  const walk = (dir) =>
    readdirSync(dir).flatMap((name) => {
      if (name.startsWith(".") || name === "node_modules" || name === "dist") return []
      const path = join(dir, name)
      if (statSync(path).isDirectory()) return walk(path)
      return name.endsWith(".md") ? [path] : []
    })
  return walk(root)
}

// Splits a page into prose lines and fenced blocks. A fence closes on a line
// of the same character, at least as long, with nothing after it. Comment
// markers such as <!-- run --> attach to the next block when only blank
// lines or other markers sit between; a run marker that reaches prose first
// is reported as orphaned.
function parse(text) {
  const prose = []
  const blocks = []
  const orphans = []
  let markers = []
  let open = null
  for (const [i, line] of text.split("\n").entries()) {
    if (open) {
      const close = line.match(/^\s*(`{3,}|~{3,})\s*$/)
      if (close && close[1][0] === open.fence[0] && close[1].length >= open.fence.length) {
        blocks.push({ line: open.line, lang: open.lang, code: open.body.join("\n"), markers: open.markers })
        open = null
      } else {
        open.body.push(line)
      }
      continue
    }
    const start = line.match(/^\s*(`{3,}|~{3,})\s*([^\s`]*)/)
    if (start) {
      open = { line: i + 1, fence: start[1], lang: start[2], body: [], markers }
      markers = []
      continue
    }
    prose.push([i + 1, line])
    const marker = line.match(/^\s*<!--\s*(.*?)\s*-->\s*$/)
    if (marker) markers.push({ text: marker[1], line: i + 1 })
    else if (line.trim() !== "") {
      orphans.push(...markers.filter((m) => m.text === "run").map((m) => m.line))
      markers = []
    }
  }
  orphans.push(...markers.filter((m) => m.text === "run").map((m) => m.line))
  return { prose, blocks, orphans }
}

function anchors(text) {
  const seen = new Map()
  const out = new Set()
  for (const [, line] of parse(text).prose) {
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
    for (const [line, raw] of parse(readFileSync(file, "utf8")).prose) {
      const text = raw.replace(/`[^`]*`/g, "")
      const targets = [
        ...[...text.matchAll(/\]\(<?([^)\s>]+)>?(?:\s+"[^"]*")?\)/g)].map((m) => m[1]),
        ...[...text.matchAll(/<a\s[^>]*href="([^"]+)"/g)].map((m) => m[1]),
        ...[...text.matchAll(/<img\s[^>]*src="([^"]+)"/g)].map((m) => m[1]),
        ...[...text.matchAll(/<source\s[^>]*srcset="([^"]+)"/g)].flatMap((m) => m[1].split(",").map((c) => c.trim().split(/\s+/)[0])),
      ]
      for (const target of targets) {
        if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue
        const [path, fragment] = target.split("#")
        let dest
        try {
          dest = path === "" ? file : resolve(dirname(file), decodeURI(path))
        } catch {
          failures.push({ file: relative(root, file), line, target })
          continue
        }
        const ok = existsSync(dest) && (!fragment || !dest.endsWith(".md") || anchorsOf(dest).has(fragment))
        if (!ok) failures.push({ file: relative(root, file), line, target })
      }
    }
  }
  return failures
}

export function runExamples(root, url) {
  let ran = 0
  const failures = []
  for (const file of markdownFiles(root).sort()) {
    const { blocks, orphans } = parse(readFileSync(file, "utf8"))
    for (const line of orphans) {
      failures.push({ file: relative(root, file), line, reason: "run marker with no block below it", output: "" })
    }
    for (const block of blocks) {
      const texts = block.markers.map((m) => m.text)
      if (!texts.includes("run")) continue
      if (block.lang !== "sh") {
        failures.push({ file: relative(root, file), line: block.line, reason: "run marker on a block that is not sh", output: "" })
        continue
      }
      ran++
      const code = block.code.replaceAll("http://localhost:8080", url)
      const r = spawnSync("sh", ["-e", "-c", code], { encoding: "utf8", timeout: 60_000 })
      const output = `${r.stdout ?? ""}${r.stderr ?? ""}`
      const expects = texts.filter((m) => m.startsWith("expect:")).map((m) => m.slice(7).trim())
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
