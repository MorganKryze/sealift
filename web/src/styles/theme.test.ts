import { describe, expect, it } from "vitest"

// Vitest empties every .css import, ?raw included, so the stylesheets are read from disk. The app's
// types leave Node out, hence the narrow shape.
type Node = { process: { getBuiltinModule(id: "node:fs"): { readFileSync(path: string, encoding: "utf8"): string } } }
const { readFileSync } = (globalThis as unknown as Node).process.getBuiltinModule("node:fs")
const here = (import.meta as ImportMeta & { dirname: string }).dirname
const read = (name: string) => readFileSync(`${here}/${name}`, "utf8").replace(/\/\*[\s\S]*?\*\//g, "")

const theme = read("theme.css")
const index = read("index.css")

// The body of the first block opened by exactly this selector, nested blocks included.
function block(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const start = new RegExp(`(^|[\\s{};])${escaped}\\s*\\{`).exec(css)
  if (!start) throw new Error(`no block for ${selector}`)
  let depth = 1
  let i = start.index + start[0].length
  const from = i
  for (; i < css.length && depth > 0; i++) {
    if (css[i] === "{") depth++
    if (css[i] === "}") depth--
  }
  return css.slice(from, i - 1)
}

// Every body opened by this at-rule prelude, such as "@media (prefers-reduced-motion: reduce)".
function blocks(css: string, prelude: string): string[] {
  const found: string[] = []
  let rest = css
  for (;;) {
    const at = rest.indexOf(prelude)
    if (at < 0) return found
    const body = block(rest.slice(at), prelude)
    found.push(body)
    rest = rest.slice(at + prelude.length + body.length)
  }
}

const declarations = (body: string) =>
  Object.fromEntries([...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]))

const light = declarations(block(theme, ":root"))
const darkOnly = declarations(block(theme, ".dark"))
const dark = { ...light, ...darkOnly }
const themes = { light, dark } as Record<string, Record<string, string>>

function colour(tokens: Record<string, string>, name: string): string {
  let value = tokens[name]
  for (let hops = 0; value && hops < 10; hops++) {
    const ref = /^var\((--[\w-]+)(?:,\s*(.+))?\)$/.exec(value)
    if (!ref) break
    value = tokens[ref[1]] ?? ref[2]
  }
  if (!value || !/^#[0-9a-f]{6}$/i.test(value)) throw new Error(`${name} is not a six-digit colour: ${value}`)
  return value.toLowerCase()
}

const luminance = (hex: string) =>
  [1, 3, 5]
    .map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0)

function ratio(a: string, b: string) {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (high + 0.05) / (low + 0.05)
}

// Each pair under its floor, named with its theme and measured ratio, so a failure says which one.
function shortfalls(pairs: [string, string][], floor: number) {
  const short: string[] = []
  for (const [name, tokens] of Object.entries(themes)) {
    for (const [fg, bg] of pairs) {
      const measured = ratio(colour(tokens, fg), colour(tokens, bg))
      if (measured < floor) short.push(`${name} ${fg} on ${bg}: ${measured.toFixed(2)}:1`)
    }
  }
  return short
}

const PAGES = ["--bg", "--canvas", "--hover", "--sel"]
const STATES = ["ok", "warn", "bad", "info"]
const cross = (fgs: string[], bgs: string[]) => fgs.flatMap((fg) => bgs.map((bg) => [fg, bg] as [string, string]))

describe("theme tokens", () => {
  it("every text token reaches 4.5:1 on each page colour in light and dark", () => {
    expect(shortfalls(cross(["--ink", "--ink-2", "--muted", "--faint"], PAGES), 4.5)).toEqual([])
    expect(shortfalls([["--bg", "--ink"], ["--ink", "--selection"], ["--disabled", "--hover"], ["--ink", "--seg-on"]], 4.5)).toEqual([])
  })

  it("each state's word reaches 4.5:1 on its tint and its line 3:1 on the page", () => {
    const words = STATES.flatMap((s) => cross([`--${s}`, "--ink", "--ink-2"], [`--${s}-tint`]))
    expect(shortfalls(words, 4.5)).toEqual([])
    expect(shortfalls(cross(STATES.map((s) => `--${s}`), PAGES), 4.5)).toEqual([])
    expect(shortfalls(cross(STATES.map((s) => `--${s}-line`), ["--bg", "--canvas"]), 3)).toEqual([])
  })

  it("field borders and severity marks reach 3:1", () => {
    expect(shortfalls(cross(["--field"], ["--bg", "--canvas"]), 3)).toEqual([])
    expect(shortfalls(cross(["--sev-critical", "--sev-high", "--sev-medium", "--sev-low"], PAGES), 3)).toEqual([])
  })

  it("keeps today's names as aliases on the new values", () => {
    expect(light["--accent"]).toBe("var(--ink)")
    expect(light["--background"]).toBe("var(--bg)")
    expect(light["--line"]).toBe("var(--rule)")
    expect(light["--card"]).toBe("var(--canvas)")
  })

  it("draws the deployment's accent in the ink until the deployment sets one per theme", () => {
    expect(light["--brand"]).toBe("var(--brand-light, var(--ink))")
    expect(darkOnly["--brand"]).toBe("var(--brand-dark, var(--ink))")
    expect(light["--brand-light"]).toBeUndefined()
    expect(dark["--brand-dark"]).toBeUndefined()
  })

  it("gives the system's dark theme the values of the dark class", () => {
    const system = declarations(block(block(theme, "@media (prefers-color-scheme: dark)"), ":root:not(.light):not(.dark)"))
    expect(system).toEqual(darkOnly)
    expect(block(theme, ".dark")).toMatch(/color-scheme:\s*dark/)
  })
})

describe("state rows and figures", () => {
  it("a tinted row draws its line on all four sides with radius 8", () => {
    for (const state of STATES) {
      const rule = block(index, `.tinted-${state}`)
      expect(rule, state).toMatch(new RegExp(`(^|;)\\s*border:\\s*1px solid var\\(--${state}-line\\)`))
      expect(rule, state).toMatch(/border-radius:\s*8px/)
      expect(rule, state).toMatch(new RegExp(`background-color:\\s*var\\(--${state}-tint\\)`))
      expect(rule, state).not.toMatch(/border-(top|right|bottom|left|block|inline)[\w-]*\s*:/)
    }
  })

  it("sets a figure in weight 600", () => {
    const rule = block(index, ".figure")
    expect(rule).toMatch(/font-weight:\s*600/)
    expect(rule).toMatch(/font-variant-numeric:\s*tabular-nums/)
  })
})

describe("browser surfaces", () => {
  it("themes selection, caret, focus ring and scrollbars", () => {
    expect(block(index, "::selection")).toMatch(/background-color:\s*var\(--selection\)/)
    expect(block(index, "::selection")).toMatch(/color:\s*var\(--ink\)/)
    expect(block(index, "html")).toMatch(/caret-color:\s*var\(--ink\)/)
    expect(block(index, "html")).toMatch(/scrollbar-color:\s*var\(--rule-2\) transparent/)
    const ring = block(index, ":focus-visible")
    expect(ring).toMatch(/outline:\s*2px solid var\(--ink\)/)
    expect(ring).toMatch(/outline-offset:\s*2px/)
  })

  it("sets tabular figures on the body", () => {
    expect(block(index, "body")).toMatch(/font-variant-numeric:\s*tabular-nums/)
  })
})

describe("motion", () => {
  const sources = { "index.css": index, "theme.css": theme }

  it("no transition or animation uses ease-in, width, left or 300 ms or more", () => {
    const offenders: string[] = []
    for (const [file, css] of Object.entries(sources)) {
      for (const m of css.matchAll(/(?:^|[;{\s])((?:transition|animation)[\w-]*)\s*:\s*([^;}]+)/g)) {
        const [, property, value] = m
        const durations = [...value.matchAll(/(\d*\.?\d+)(ms|s)\b/g)].map((d) => Number(d[1]) * (d[2] === "s" ? 1000 : 1))
        if (/\bease-in\b/.test(value)) offenders.push(`${file} ${property}: ${value} eases in`)
        if (/\b(width|left)\b/.test(value)) offenders.push(`${file} ${property}: ${value} moves width or left`)
        if (durations.some((d) => d >= 300)) offenders.push(`${file} ${property}: ${value} lasts 300 ms or more`)
      }
      for (const m of css.matchAll(/@keyframes\s+([\w-]+)\s*\{/g)) {
        const body = block(css.slice(m.index), `@keyframes ${m[1]}`)
        const properties = [...body.matchAll(/([\w-]+)\s*:/g)].map((p) => p[1])
        for (const p of properties.filter((p) => p !== "transform" && p !== "opacity")) offenders.push(`${file} @keyframes ${m[1]} animates ${p}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it("reduced motion keeps no transform", () => {
    const reduced = blocks(index, "@media (prefers-reduced-motion: reduce)").join("\n")
    expect(reduced).not.toBe("")
    expect(reduced).not.toMatch(/transform\s*:\s*(?!none)/)
    expect(reduced).toMatch(/transition-property:\s*(?![^;]*transform)[^;]*opacity/)
    const moving = [...index.matchAll(/@keyframes\s+([\w-]+)\s*\{/g)]
      .filter((m) => /transform/.test(block(index.slice(m.index), `@keyframes ${m[1]}`)))
      .map((m) => m[1])
    expect(moving.length).toBeGreaterThan(0)
    for (const name of moving) {
      const users = [...index.matchAll(new RegExp(`(\\.[\\w-]+)\\s*\\{[^}]*animation:\\s*${name}\\b`, "g"))].map((m) => m[1])
      for (const selector of users) {
        expect(reduced, `${selector} keeps ${name} under reduced motion`).toMatch(new RegExp(`\\${selector}\\b[^{]*\\{[^}]*animation-name:\\s*fade`))
      }
    }
    expect(block(index, "@keyframes fade")).not.toMatch(/transform/)
  })
})
