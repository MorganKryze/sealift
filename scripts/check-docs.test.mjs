import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { checkLinks, runExamples, slug } from "./check-docs.mjs"

test("slug follows GitHub's rule", () => {
  assert.equal(slug("Get started"), "get-started")
  assert.equal(slug("GET /api/tools"), "get-apitools")
  assert.equal(slug("What crosses the kiosk?"), "what-crosses-the-kiosk")
  assert.equal(slug("The `signature.key` file"), "the-signaturekey-file")
})

test("checkLinks reports missing files and anchors only", () => {
  const root = mkdtempSync(join(tmpdir(), "check-docs-"))
  writeFileSync(
    join(root, "a.md"),
    "# A\n\n## Get started\n\n## GET /api/tools\n\n## What crosses the kiosk?\n\n## Get started\n\n```md\n## Inside a fence\n[x](nowhere.md)\n```\n",
  )
  writeFileSync(
    join(root, "b.md"),
    [
      "[ok](a.md#get-started)",
      "[ok](a.md#get-started-1)",
      "[ok](a.md#get-apitools)",
      "[ok](a.md#what-crosses-the-kiosk)",
      "[ok](#local)",
      "[ok](https://example.com/missing.md)",
      "[bad](a.md#missing)",
      "[bad](a.md#inside-a-fence)",
      '<a href="missing.md">bad</a>',
      "",
      "## Local",
    ].join("\n"),
  )
  const failures = checkLinks(root).map((f) => `${f.file}:${f.line}: ${f.target}`)
  assert.deepEqual(failures, ["b.md:7: a.md#missing", "b.md:8: a.md#inside-a-fence", "b.md:9: missing.md"])
})

test("runExamples runs the marked blocks and checks their output", () => {
  const root = mkdtempSync(join(tmpdir(), "check-docs-"))
  const fence = "```"
  writeFileSync(
    join(root, "page.md"),
    [
      "<!-- run -->",
      "<!-- expect: http://sealift:8080/api -->",
      `${fence}sh`,
      "echo http://localhost:8080/api",
      fence,
      "",
      "<!-- run -->",
      `${fence}sh`,
      "false",
      fence,
      "",
      "<!-- run -->",
      "<!-- expect: b -->",
      "",
      `${fence}sh`,
      "echo a",
      fence,
      "",
      "<!-- illustrative -->",
      `${fence}sh`,
      "exit 1",
      fence,
      "",
      `${fence}sh`,
      "exit 1",
      fence,
    ].join("\n"),
  )
  const { ran, failures } = runExamples(root, "http://sealift:8080")
  assert.equal(ran, 3)
  assert.deepEqual(
    failures.map((f) => `${f.file}:${f.line}`),
    ["page.md:8", "page.md:15"],
  )
})

test("checkLinks handles long fences, srcset and malformed escapes", () => {
  const root = mkdtempSync(join(tmpdir(), "check-docs-"))
  writeFileSync(join(root, "img.png"), "")
  writeFileSync(
    join(root, "a.md"),
    [
      "````md",
      "```",
      "[inside](nope-inside.md)",
      "```",
      "````",
      '<source srcset="img.png 1x, missing.png 2x">',
      "[bad](%E0%A4%A.md)",
    ].join("\n"),
  )
  const failures = checkLinks(root).map((f) => `${f.file}:${f.line}: ${f.target}`)
  assert.deepEqual(failures, ["a.md:6: missing.png", "a.md:7: %E0%A4%A.md"])
})

test("runExamples reports a run marker that reaches no sh block", () => {
  const root = mkdtempSync(join(tmpdir(), "check-docs-"))
  const fence = "```"
  writeFileSync(
    join(root, "page.md"),
    ["- step", "", "  <!-- run -->", "  text in between", "", "<!-- run -->", `${fence}json`, "{}", fence].join("\n"),
  )
  const { ran, failures } = runExamples(root, "http://sealift:8080")
  assert.equal(ran, 0)
  assert.deepEqual(
    failures.map((f) => `${f.file}:${f.line}: ${f.reason}`),
    ["page.md:3: run marker with no block below it", "page.md:7: run marker on a block that is not sh"],
  )
})
