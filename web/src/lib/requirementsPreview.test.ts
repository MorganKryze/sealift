import { describe, expect, it } from "vitest"

import { MAX_REQUIREMENTS_BYTES, MAX_REQUIREMENTS_FILES, parseRequirementsPreview, type PipCheckId, type RequirementsPreview } from "@/lib/requirementsPreview"

const check = (preview: RequirementsPreview, id: PipCheckId) => {
  const found = preview.checks.find((c) => c.id === id)
  if (!found) throw new Error(`no ${id} check`)
  return found
}

const lines = (...rows: string[]) => `${rows.join("\n")}\n`

// The usual project: a run file, a dev file that includes it and pins under constraints, and the constraints.
const USUAL = [
  { name: "requirements.txt", text: lines("Django==4.2.16", "celery==5.4.0", "requests==2.32.3") },
  { name: "requirements-dev.txt", text: lines("-r requirements.txt", "-c constraints.txt", "pytest==8.3.3") },
  { name: "constraints.txt", text: lines("urllib3==2.2.3", "idna==3.10") },
]

describe("parseRequirementsPreview", () => {
  it("names five checks with their evidence", () => {
    const preview = parseRequirementsPreview(USUAL)
    expect(preview.checks.map((c) => [c.id, c.label, c.passed, c.evidence])).toEqual([
      ["exact", "Exact versions", true, "6 of 6 pinned with =="],
      ["pypi", "PyPI only", true, "6 of 6 on PyPI"],
      ["options", "Supported options", true, "-r · -c"],
      ["included", "Included files", true, "2 of 2 dropped"],
      ["one-version", "One version each", true, "3 files agree"],
    ])
    expect(preview.pins).toBe(6)
    expect(preview.files.map((f) => [f.name, f.pins.length, f.constraints, f.includes, f.missing])).toEqual([
      ["requirements.txt", 3, 0, [], []],
      [
        "requirements-dev.txt",
        1,
        0,
        [
          { option: "-r", target: "requirements.txt" },
          { option: "-c", target: "constraints.txt" },
        ],
        [],
      ],
      ["constraints.txt", 2, 2, [], []],
    ])
    expect(preview.files[0].pins[0]).toEqual({ name: "Django", version: "4.2.16" })
  })

  it("says when no file includes another and when no option is used", () => {
    const preview = parseRequirementsPreview([{ name: "requirements.txt", text: lines("Django==4.2.16") }])
    expect(check(preview, "included").evidence).toBe("No file includes another")
    expect(check(preview, "options").evidence).toBe("No option used")
    expect(check(preview, "one-version").evidence).toBe("1 file agrees")
  })

  it("counts lines not pinned with == and lists each as written with file and line", () => {
    const preview = parseRequirementsPreview([
      { name: "requirements.txt", text: lines("--index-url https://pypi.internal.example.com/simple", "", "Django>=4.2,<5", "celery~=5.4.0", "numpy==2.1.*", "torch==2.5.1+cpu", "attrs===24.2.0", "idna==3.10", "flask>=3.0") },
    ])
    const exact = check(preview, "exact")
    expect(exact.passed).toBe(false)
    expect(exact.evidence).toBe("6 of 7 not pinned with ==")
    expect(exact.fix).toBe("Pin the version you run, such as Django==4.2.16; pip freeze prints them.")
    expect(exact.offenders).toEqual([
      { file: "requirements.txt", line: 3, text: "Django>=4.2,<5", name: "Django", value: ">=4.2,<5" },
      { file: "requirements.txt", line: 4, text: "celery~=5.4.0", name: "celery", value: "~=5.4.0" },
      { file: "requirements.txt", line: 5, text: "numpy==2.1.*", name: "numpy", value: "==2.1.*" },
      { file: "requirements.txt", line: 6, text: "torch==2.5.1+cpu", name: "torch", value: "==2.5.1+cpu" },
      { file: "requirements.txt", line: 7, text: "attrs===24.2.0", name: "attrs", value: "===24.2.0" },
      { file: "requirements.txt", line: 9, text: "flask>=3.0", name: "flask", value: ">=3.0" },
    ])
  })

  it("reads a bare name as no version", () => {
    const preview = parseRequirementsPreview([{ name: "requirements.in", text: lines("Django", "requests[socks] ; python_version >= '3.8'") }])
    expect(check(preview, "exact").offenders.map((o) => [o.name, o.value])).toEqual([
      ["Django", "no version"],
      ["requests", "no version"],
    ])
    expect(preview.files[0].pins).toEqual([
      { name: "Django", version: "no version" },
      { name: "requests", version: "no version" },
    ])
  })

  it("counts lines off PyPI: URL, VCS, local path, editable", () => {
    const preview = parseRequirementsPreview([
      {
        name: "requirements.txt",
        text: lines(
          "-e git+https://github.com/acme/billing-sdk.git@v2.3.1#egg=billing-sdk",
          "internal-auth @ git+ssh://git@gitlab.example.com/platform/internal-auth.git@4f2a91c",
          "https://files.example.com/pkg-1.0.tar.gz",
          "git+https://github.com/acme/tool.git",
          "./libs/shared-models",
          "--editable ../widgets",
          "Django==4.2.16",
        ),
      },
    ])
    const pypi = check(preview, "pypi")
    expect(pypi.passed).toBe(false)
    expect(pypi.evidence).toBe("6 lines off PyPI")
    expect(pypi.offenders.map((o) => [o.line, o.name, o.value ?? o.text])).toEqual([
      [1, "billing-sdk", "-e git+https://github.com/acme/billing-sdk.git@v2.3.1#egg=billing-sdk"],
      [2, "internal-auth", "@ git+ssh://gitlab.example.com/platform/internal-auth.git@4f2a91c"],
      [3, undefined, "https://files.example.com/pkg-1.0.tar.gz"],
      [4, undefined, "git+https://github.com/acme/tool.git"],
      [5, undefined, "./libs/shared-models"],
      [6, "../widgets", "--editable ../widgets"],
    ])
    expect(check(preview, "options").passed).toBe(true)
    expect(check(preview, "exact").evidence).toBe("1 of 1 pinned with ==")
  })

  it("names an unsupported option", () => {
    const preview = parseRequirementsPreview([
      {
        name: "requirements.txt",
        text: lines("--index-url https://pypi.internal.example.com/simple", "--extra-index-url=https://download.pytorch.org/whl/cpu", "--no-binary :all:", "Django==4.2.16 --hash=md5:0123"),
      },
    ])
    const options = check(preview, "options")
    expect(options.passed).toBe(false)
    expect(options.evidence).toBe("4 options not supported")
    expect(options.offenders.map((o) => [o.line, o.name, o.value])).toEqual([
      [1, "--index-url", "https://pypi.internal.example.com/simple"],
      [2, "--extra-index-url", "https://download.pytorch.org/whl/cpu"],
      [3, "--no-binary", ":all:"],
      [4, "Django", "--hash=md5:0123"],
    ])
  })

  it("counts --hash pins", () => {
    const hash = "a".repeat(64)
    const preview = parseRequirementsPreview([
      { name: "requirements.txt", text: lines(`Django==4.2.16 --hash=sha256:${hash} \\`, `    --hash=sha256:${"b".repeat(64)}`, `idna==3.10 --hash sha256:${hash}`, "celery==5.4.0") },
    ])
    expect(preview.hashed).toBe(2)
    expect(check(preview, "options").evidence).toBe("--hash on 2 pins")
    expect(check(preview, "options").passed).toBe(true)
  })

  it("finds an include that names a file not dropped", () => {
    const preview = parseRequirementsPreview([
      { name: "requirements-dev.txt", text: lines("-r requirements-base.txt", "-r requirements.txt", "--constraint ./constraints.txt", "pytest==8.3.3") },
      { name: "requirements.txt", text: lines("Django==4.2.16") },
    ])
    const included = check(preview, "included")
    expect(included.passed).toBe(false)
    expect(included.evidence).toBe("2 of 3 not dropped")
    expect(included.fix).toBe("Add the files they name, with the others.")
    expect(included.offenders.map((o) => [o.file, o.line, o.name, o.value])).toEqual([
      ["requirements-dev.txt", 1, "-r", "requirements-base.txt"],
      ["requirements-dev.txt", 3, "-c", "./constraints.txt"],
    ])
    expect(preview.files[0].missing).toEqual(["requirements-base.txt", "constraints.txt"])
    expect(preview.files[0].includes).toEqual([
      { option: "-r", target: "requirements-base.txt" },
      { option: "-r", target: "requirements.txt" },
      { option: "-c", target: "./constraints.txt" },
    ])
  })

  it("finds a package pinned at two versions across files", () => {
    const preview = parseRequirementsPreview([
      { name: "requirements.txt", text: lines("requests==2.32.3", "Django==4.2.16") },
      { name: "constraints.txt", text: lines("idna==3.10", "", "", "", "", "", "", "", "Requests==2.31.0", "django==4.2.16.0") },
    ])
    const one = check(preview, "one-version")
    expect(one.passed).toBe(false)
    expect(one.evidence).toBe("1 package at two versions")
    expect(one.offenders.map((o) => [o.file, o.line, o.name, o.value])).toEqual([
      ["requirements.txt", 1, "requests", "2.32.3"],
      ["constraints.txt", 9, "Requests", "2.31.0"],
    ])
  })

  it("joins continuation lines and drops comments as pip does", () => {
    const preview = parseRequirementsPreview([
      {
        name: "requirements.txt",
        text: "\uFEFF# the run set\r\nDjango==4.2.16 \\\r\n  # a comment ends the continued line\r\ncelery>=5 # a range\r\nattrs==24.2.0#no-space-so-no-comment\r\n\\\nidna==3.10\n",
      },
    ])
    const exact = check(preview, "exact")
    expect(exact.offenders.map((o) => [o.line, o.text, o.value])).toEqual([
      [4, "celery>=5", ">=5"],
      [5, "attrs==24.2.0#no-space-so-no-comment", "==24.2.0#no-space-so-no-comment"],
    ])
    expect(preview.files[0].pins).toEqual([
      { name: "Django", version: "4.2.16" },
      { name: "celery", version: ">=5" },
      { name: "attrs", version: "==24.2.0#no-space-so-no-comment" },
      { name: "idna", version: "3.10" },
    ])
    expect(preview.pins).toBe(4)
  })

  it("keeps a line as text", () => {
    const text = `pkg<img src=x onerror=alert(1)>\nevil\u202Ename\u0007>=1 ; python_version < "3.13"\n`
    const preview = parseRequirementsPreview([{ name: "requirements.txt", text }])
    const offenders = check(preview, "exact").offenders
    expect(offenders.map((o) => o.text)).toEqual(["pkg<img src=x onerror=alert(1)>", 'evilname>=1 ; python_version < "3.13"'])
    expect(offenders.every((o) => typeof o.text === "string" && !/^https?:/.test(o.text))).toBe(true)
    const long = parseRequirementsPreview([{ name: "requirements.txt", text: `pkg>=${"1".repeat(400)}\n` }])
    expect([...check(long, "exact").offenders[0].text]).toHaveLength(200)
  })

  it("refuses more files or more bytes than the server takes", () => {
    const many = Array.from({ length: MAX_REQUIREMENTS_FILES + 1 }, (_, i) => ({ name: `r${i}.txt`, text: "" }))
    expect(() => parseRequirementsPreview(many)).toThrow(RangeError)
    expect(() => parseRequirementsPreview([{ name: "big.txt", text: "a".repeat(MAX_REQUIREMENTS_BYTES + 1) }])).toThrow(RangeError)
  })

  it("reads 32 files of 1 MiB within a second", () => {
    const line = (i: number, f: number) => `package-${f}-${String(i).padStart(6, "0")}==1.${i % 50}.${i % 7} --hash=sha256:${"c".repeat(64)}\n`
    const files = Array.from({ length: MAX_REQUIREMENTS_FILES }, (_, f) => {
      const rows: string[] = []
      let size = 0
      for (let i = 0; size + line(i, f).length <= MAX_REQUIREMENTS_BYTES; i++) {
        rows.push(line(i, f))
        size += line(i, f).length
      }
      return { name: `requirements-${f}.txt`, text: rows.join("") }
    })
    // The second counts this test process's own processor time, so the test files the suite runs beside it in
    // other processes do not count against the reader; a browser reads the files alone.
    const usage = (globalThis as unknown as { process: { cpuUsage: (since?: { user: number; system: number }) => { user: number; system: number } } }).process
    const started = usage.cpuUsage()
    const preview = parseRequirementsPreview(files)
    const { user, system } = usage.cpuUsage(started)
    expect(preview.files).toHaveLength(32)
    expect(preview.pins).toBeGreaterThan(320_000)
    expect(preview.hashed).toBe(preview.pins)
    expect((user + system) / 1000).toBeLessThan(1000)
  })
})
