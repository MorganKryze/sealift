// Reads dropped requirements files in the browser with the line rules of pip/requirements.go, so Check names
// what the server would refuse before anything is sent. The server stays the authority: it reads the files
// again, with the refusals this reader leaves to it (markers, variables, sizes per line, include cycles).

/** The most files and bytes per file a pip project takes, as the server bounds them. */
export const MAX_REQUIREMENTS_FILES = 32
export const MAX_REQUIREMENTS_BYTES = 1 << 20

export type PipCheckId = "exact" | "pypi" | "options" | "included" | "one-version"

/** One line of a file as written: `name` and `value` split it where a check names a part. */
export interface RequirementsLine {
  file: string
  line: number
  text: string
  name?: string
  /** "no version", ">=4.2,<5", or the second version of a package pinned twice. */
  value?: string
}

export interface RequirementsCheck {
  id: PipCheckId
  label: string
  passed: boolean
  evidence: string
  fix: string
  offenders: RequirementsLine[]
}

export interface RequirementsFilePreview {
  name: string
  pins: { name: string; version: string }[]
  /** How many of its pins are constraints: all of them in a file reached through -c, none otherwise. */
  constraints: number
  includes: { option: "-r" | "-c"; target: string }[]
  /** The plain names of included files that were not dropped. */
  missing: string[]
}

export interface RequirementsPreview {
  files: RequirementsFilePreview[]
  pins: number
  hashed: number
  checks: RequirementsCheck[]
}

const COMMENT = /(^|\s)#.*$/
const OPTION_START = /\s--?[A-Za-z]/
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//
const VCS = /^(git|hg|svn|bzr)\+/i
const PATH_START = /^(?:[./~]|[^\s=<>!~;[@]*[/\\])/
const LEADING_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/
const HASH_HEX = /^[0-9a-fA-F]{64}$/
// name==version with sha256 hashes or none: most lines of a pinned set, read in one match.
const SIMPLE_PIN = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([0-9][0-9A-Za-z.!_-]*)((?:\s+--hash[=\s]sha256:[0-9a-fA-F]{64})*)$/
const SHA256_HASHES = /^(?:\s+--hash[=\s]sha256:[0-9a-fA-F]{64})+\s*$/
const USERINFO = /(:\/\/)[^/\s@]*@/g
const HIDDEN = /[\p{Cc}\p{Cf}]/gu
const SPACES = /\s+/g
const PLAIN_BREAK = /[^\x21-\x7e ]| {2}|:\/\//
const VERSION =
  /^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?$/i
const MAX_TEXT = 200
const MAX_VERSION_BYTES = 128

const figure = (n: number) => n.toLocaleString("en-US")
const plural = (n: number, one: string, many: string) => `${figure(n)} ${n === 1 ? one : many}`

/** A line made safe to show, as the server's cleanText does: no control or format character, no URL credentials, 200 characters. */
function clean(text: string): string {
  // Most lines are printable ASCII with single spaces and no address: they read as written.
  if (text.length <= MAX_TEXT && !PLAIN_BREAK.test(text) && text.trim() === text) return text
  const flat = text.replace(USERINFO, "$1").replace(HIDDEN, (c) => (/\s/.test(c) ? " " : "")).replace(SPACES, " ").trim()
  const chars = [...flat]
  return chars.length > MAX_TEXT ? chars.slice(0, MAX_TEXT).join("") : flat
}

// Most names are lowercase with single dashes already, so the pattern runs only where a dot, an underscore or two dashes sit.
const normalize = (name: string) => {
  const lower = name.toLowerCase()
  return lower.includes(".") || lower.includes("_") || lower.includes("--") ? lower.replace(/[-_.]+/g, "-") : lower
}

// PEP 440 equality on public versions: 1.0 equals 1.0.0; anything else compares as written.
function canonicalVersion(version: string): string {
  const m = version.length <= MAX_VERSION_BYTES ? VERSION.exec(version.toLowerCase()) : null
  if (!m) return version
  const number = (s: string | undefined) => String(Number(s || "0"))
  const release = m[2].split(".").map(number)
  while (release.length > 1 && release[release.length - 1] === "0") release.pop()
  const pre = m[3] ? `-${{ alpha: "a", a: "a", beta: "b", b: "b" }[m[3]] ?? "rc"}${number(m[4])}` : ""
  const post = m[5] ? `-post${number(m[5])}` : m[6] ? `-post${number(m[7])}` : ""
  const dev = m[8] ? `-dev${number(m[9])}` : ""
  return `${number(m[1])}!${release.join(".")}${pre}${post}${dev}`
}

const isExactVersion = (version: string) => version.length <= MAX_VERSION_BYTES && !version.includes("+") && VERSION.test(version)

interface Pin {
  file: string
  line: number
  text: string
  name: string
  /** The specifier as written after the name, empty for a bare name. */
  spec: string
  /** Set when the line is name==version with a public PEP 440 version. */
  version?: string
  hashed: boolean
}

interface Include {
  option: "-r" | "-c"
  target: string
  plain: string
  at: RequirementsLine
}

interface ReadFile {
  name: string
  pins: Pin[]
  includes: Include[]
}

interface Found {
  offPyPI: RequirementsLine[]
  options: RequirementsLine[]
  seen: Set<"-r" | "-c">
}

// Each logical line with the number it starts on: comments dropped, continuations joined, as parseFile does.
function logicalLines(text: string, each: (line: number, content: string) => void) {
  if (text === "") return
  const lines = text.replace(/^\uFEFF/, "").replace(/\r/g, "").replace(/\n$/, "").split("\n")
  for (let i = 0; i < lines.length; i++) {
    const start = i + 1
    let joined = ""
    for (; i < lines.length; i++) {
      const part = (lines[i].includes("#") ? lines[i].replace(COMMENT, "") : lines[i]).trimEnd()
      if (part.endsWith("\\") && i + 1 < lines.length) {
        joined += part.slice(0, -1)
        continue
      }
      joined += part.endsWith("\\") ? part.slice(0, -1) : part
      break
    }
    const line = joined.trim()
    if (line !== "") each(start, line)
  }
}

function readOption(file: string, line: number, text: string, found: Found, includes: Include[]) {
  const fields = text.split(SPACES)
  const token = fields[0]
  const at: RequirementsLine = { file, line, text: clean(text) }
  const [option] = token.split("=", 1)
  if (option === "-e" || option === "--editable") {
    found.offPyPI.push(at)
    return
  }
  let kind: "-r" | "-c" | undefined
  let value = ""
  if (option === "--requirement" || option === "--constraint") {
    kind = option === "--requirement" ? "-r" : "-c"
    value = token.includes("=") ? token.slice(token.indexOf("=") + 1) : (fields[1] ?? "")
  } else if (/^-[rc]/.test(token)) {
    kind = token[1] === "c" ? "-c" : "-r"
    value = token.length > 2 ? token.slice(2).replace(/^=/, "") : (fields[1] ?? "")
  }
  if (!kind) {
    const rest = token.includes("=") ? [token.slice(token.indexOf("=") + 1), ...fields.slice(1)] : fields.slice(1)
    found.options.push({ ...at, name: clean(option), value: clean(rest.join(" ")) || undefined })
    return
  }
  found.seen.add(kind)
  // An option with no file name is the server's to refuse; it includes nothing.
  if (value === "") return
  includes.push({ option: kind, target: clean(value), plain: value.replace(/^\.\//, ""), at: { ...at, name: kind, value: clean(value) } })
}

// One requirement line; a line off PyPI or with an unsupported option is recorded there and is no pin.
function readRequirement(file: string, line: number, text: string, found: Found): Pin | undefined {
  const simple = SIMPLE_PIN.exec(text)
  if (simple && isExactVersion(simple[2])) return { file, line, text, name: simple[1], spec: `==${simple[2]}`, version: simple[2], hashed: simple[3] !== "" }
  const optionAt = OPTION_START.exec(text)
  const body = (optionAt ? text.slice(0, optionAt.index) : text).trim()
  const optionPart = optionAt ? text.slice(optionAt.index) : ""
  // A name starting the line with no slash or colon in it is no URL or path; most lines are such, so the patterns wait.
  const plainName = !body.includes("/") && !body.includes("\\") && !body.includes(":") && !body.startsWith(".") && !body.startsWith("~")
  if (VCS.test(body) || (!plainName && (SCHEME.test(body) || PATH_START.test(body)))) {
    found.offPyPI.push({ file, line, text: clean(text) })
    return undefined
  }
  const specPart = body.split(";", 1)[0].trim()
  const name = LEADING_NAME.exec(specPart)?.[0]
  // A line with no name is the server's to refuse: it is no requirement this reader can place.
  if (!name) return undefined
  let rest = specPart.slice(name.length).trim()
  if (rest.startsWith("[")) {
    const end = rest.indexOf("]")
    rest = end < 0 ? rest : rest.slice(end + 1).trim()
  }
  if (rest.startsWith("@")) {
    found.offPyPI.push({ file, line, text: clean(text), name: clean(name), value: clean(rest) })
    return undefined
  }
  const unsupported = unsupportedHashOption(optionPart)
  if (unsupported !== undefined) {
    found.options.push({ file, line, text: clean(text), name: clean(name), value: clean(unsupported) })
    return undefined
  }
  const exact = rest.startsWith("==") && !rest.startsWith("===") ? rest.slice(2).trim() : undefined
  const version = exact !== undefined && !exact.includes(",") && !exact.includes("*") && isExactVersion(exact) ? exact : undefined
  // The name matched letters, digits and . _ - only, and a version matched PEP 440, so neither needs cleaning.
  return { file, line, text, name, spec: version === undefined ? clean(rest) : rest, version, hashed: optionPart.includes("--hash") }
}

// The options after a requirement that the server refuses as options: anything but --hash, or a hash that is not sha256.
// A sha256 value of the wrong length is the server's to refuse.
function unsupportedHashOption(optionPart: string): string | undefined {
  if (optionPart === "" || SHA256_HASHES.test(optionPart)) return undefined
  const tokens = optionPart.trim() === "" ? [] : optionPart.trim().split(SPACES)
  for (let i = 0; i < tokens.length; i++) {
    const [option, ...valueParts] = tokens[i].split("=")
    if (option !== "--hash") return tokens.slice(i).join(" ")
    const value = valueParts.length > 0 ? valueParts.join("=") : tokens[++i]
    if (value === undefined) return undefined
    const [algorithm, digest = ""] = value.split(":", 2)
    if (algorithm.toLowerCase() !== "sha256") return tokens.slice(valueParts.length > 0 ? i : i - 1).join(" ")
    if (!HASH_HEX.test(digest)) return undefined
  }
  return undefined
}

function readFile(name: string, text: string, found: Found): ReadFile {
  const read: ReadFile = { name, pins: [], includes: [] }
  logicalLines(text, (line, content) => {
    if (content.startsWith("-")) {
      readOption(name, line, content, found, read.includes)
      return
    }
    const pin = readRequirement(name, line, content, found)
    if (pin) read.pins.push(pin)
  })
  return read
}

// The files reached through -c, and whatever they include, hold constraints, as the server's walk decides.
function constraintFiles(files: ReadFile[]): Set<string> {
  const byName = new Map(files.map((f) => [f.name, f]))
  const queue = files.flatMap((f) => f.includes.filter((inc) => inc.option === "-c").map((inc) => inc.plain))
  const constraints = new Set<string>()
  while (queue.length > 0) {
    const name = queue.shift() as string
    const file = byName.get(name)
    if (constraints.has(name) || !file) continue
    constraints.add(name)
    queue.push(...file.includes.map((inc) => inc.plain))
  }
  return constraints
}

const pinVersion = (pin: Pin) => pin.version ?? (pin.spec === "" ? "no version" : pin.spec)

/**
 * Reads requirements files as the server reads them on upload: each file's pins, constraints and includes, and
 * the five checks the server makes, each failing line kept as written with its file and line. Each line stays
 * text; nothing here builds an address from it.
 */
export function parseRequirementsPreview(files: { name: string; text: string }[]): RequirementsPreview {
  if (files.length > MAX_REQUIREMENTS_FILES) throw new RangeError(`at most ${MAX_REQUIREMENTS_FILES} requirements files`)
  // A string never holds fewer UTF-8 bytes than characters, so a longer one is over the bound; the drop measures bytes.
  const over = files.find((f) => f.text.length > MAX_REQUIREMENTS_BYTES)
  if (over) throw new RangeError(`${over.name} is over ${MAX_REQUIREMENTS_BYTES} bytes`)

  const found: Found = { offPyPI: [], options: [], seen: new Set() }
  const read = files.map((f) => readFile(f.name, f.text, found))
  const names = new Set(files.map((f) => f.name))
  const constraints = constraintFiles(read)
  const pins = read.flatMap((f) => f.pins)
  const total = pins.length
  const includes = read.flatMap((f) => f.includes)
  const notDropped = includes.filter((inc) => !names.has(inc.plain))

  // One pass over the pins, which may number hundreds of thousands: a package seen once, the common case, costs
  // one map entry; a list starts only on its second pin.
  let hashed = 0
  const unpinned: RequirementsLine[] = []
  const first = new Map<string, Pin>()
  const repeated = new Map<string, Pin[]>()
  for (const pin of pins) {
    if (pin.hashed) hashed++
    if (pin.version === undefined) {
      unpinned.push({ file: pin.file, line: pin.line, text: clean(pin.text), name: pin.name, value: pin.spec === "" ? "no version" : pin.spec })
      continue
    }
    const key = normalize(pin.name)
    const seenFirst = first.get(key)
    if (!seenFirst) first.set(key, pin)
    else repeated.set(key, [...(repeated.get(key) ?? [seenFirst]), pin])
  }
  const twice = [...repeated.values()].filter((list) => new Set(list.map((p) => canonicalVersion(p.version as string))).size > 1)

  const seen = (["-r", "-c"] as const).filter((option) => found.seen.has(option))
  const optionsSeen = [...seen, hashed > 0 ? `--hash on ${plural(hashed, "pin", "pins")}` : ""].filter(Boolean).join(" · ")

  const checks: RequirementsCheck[] = [
    {
      id: "exact",
      label: "Exact versions",
      passed: unpinned.length === 0,
      evidence: unpinned.length === 0 ? `${figure(total)} of ${figure(total)} pinned with ==` : `${figure(unpinned.length)} of ${figure(total)} not pinned with ==`,
      fix: "Pin the version you run, such as Django==4.2.16; pip freeze prints them.",
      offenders: unpinned,
    },
    {
      id: "pypi",
      label: "PyPI only",
      passed: found.offPyPI.length === 0,
      evidence: found.offPyPI.length === 0 ? `${figure(total)} of ${figure(total)} on PyPI` : `${plural(found.offPyPI.length, "line", "lines")} off PyPI`,
      fix: "Pin a version published on PyPI, or remove the line.",
      offenders: found.offPyPI,
    },
    {
      id: "options",
      label: "Supported options",
      passed: found.options.length === 0,
      evidence: found.options.length === 0 ? optionsSeen || "No option used" : `${plural(found.options.length, "option", "options")} not supported`,
      fix: "Remove these options; -r, -c and --hash=sha256 are the only ones read.",
      offenders: found.options,
    },
    {
      id: "included",
      label: "Included files",
      passed: notDropped.length === 0,
      evidence:
        includes.length === 0
          ? "No file includes another"
          : notDropped.length === 0
            ? `${figure(includes.length)} of ${figure(includes.length)} dropped`
            : `${figure(notDropped.length)} of ${figure(includes.length)} not dropped`,
      fix: notDropped.length === 1 ? "Add the file it names, with the others." : "Add the files they name, with the others.",
      offenders: notDropped.map((inc) => inc.at),
    },
    {
      id: "one-version",
      label: "One version each",
      passed: twice.length === 0,
      evidence: twice.length === 0 ? (files.length === 1 ? "1 file agrees" : `${figure(files.length)} files agree`) : `${plural(twice.length, "package", "packages")} at two versions`,
      fix: "Pin one version in every file that names it.",
      offenders: twice.flatMap((list) => list.map(({ file, line, text, name, version }) => ({ file, line, text: clean(text), name, value: version }))),
    },
  ]

  return {
    files: read.map((f) => ({
      name: f.name,
      pins: f.pins.map((p) => ({ name: p.name, version: pinVersion(p) })),
      constraints: constraints.has(f.name) ? f.pins.length : 0,
      includes: f.includes.map(({ option, target }) => ({ option, target })),
      missing: [...new Set(f.includes.filter((inc) => !names.has(inc.plain)).map((inc) => inc.plain))],
    })),
    pins: total,
    hashed,
    checks,
  }
}
