import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { checkLinks, slug } from "./check-docs.mjs"

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
