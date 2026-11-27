import { cleanup, fireEvent, render, screen, within } from "@testing-library/react"
import { beforeEach, describe, expect, it } from "vitest"

import { PipWheels, wheelPlatform } from "@/components/session/pip-wheels"
import type { PipAnalysisResult, PipPackage } from "@/lib/pipReview"

const target = { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" }
const MANYLINUX = "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64"

function pkg(name: string, tag: string, size: number): PipPackage {
  return { name, version: "1.0.0", files: [], cves: [], wheel: { file: `${name}-1.0.0-${tag}.whl`, url: `https://files.example/${name}`, sha256: "a".repeat(64), size } }
}
const resultOf = (packages: PipPackage[]): PipAnalysisResult => ({ target, files: ["requirements.txt"], packages, blocking: [], warnings: [] })

// 3 pure wheels of 1 MiB, 7 manylinux 2.17 wheels of 2 MiB (2 of them under the manylinux2014 alias alone), 1 of 2.28 of 4 MiB.
const MIB = 1024 * 1024
const SET = resultOf([
  ...Array.from({ length: 3 }, (_, i) => pkg(`pure${i}`, "py3-none-any", MIB)),
  ...Array.from({ length: 5 }, (_, i) => pkg(`native${i}`, MANYLINUX, 2 * MIB)),
  ...Array.from({ length: 2 }, (_, i) => pkg(`old${i}`, "cp311-cp311-manylinux2014_x86_64", 2 * MIB)),
  pkg("newer", "cp311-cp311-manylinux_2_28_x86_64", 4 * MIB),
])

const block = () => screen.getByRole("region", { name: /^Wheels for/ })
const rows = () => Array.from(block().querySelectorAll("[data-platform]")) as HTMLElement[]
const platform = (words: string) => within(block()).getByRole("button", { name: new RegExp(`^${words.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`) })

beforeEach(() => cleanup())

describe("wheelPlatform", () => {
  it("groups wheels by platform in words with their tag", () => {
    expect(wheelPlatform("attrs-24.2.0-py3-none-any.whl")).toEqual({ key: "any", words: "Any platform", tag: "py3-none-any" })
    expect(wheelPlatform("six-1.16.0-py2.py3-none-any.whl")).toEqual({ key: "any", words: "Any platform", tag: "py2.py3-none-any" })
    expect(wheelPlatform(`numpy-2.1.3-${MANYLINUX}.whl`)).toEqual({ key: "manylinux_2_17_x86_64", words: "Linux x86_64, glibc 2.17 and later", tag: "manylinux_2_17_x86_64" })
    expect(wheelPlatform("psycopg_binary-3.2.3-1-cp311-cp311-manylinux_2_28_aarch64.whl")).toEqual({ key: "manylinux_2_28_aarch64", words: "Linux aarch64, glibc 2.28 and later", tag: "manylinux_2_28_aarch64" })

    render(<PipWheels result={SET} />)
    expect(rows().map((row) => row.querySelector("[data-words]")?.textContent)).toEqual(["Any platform", "Linux x86_64, glibc 2.17 and later", "Linux x86_64, glibc 2.28 and later"])
    expect(rows().map((row) => row.querySelector("[data-tag]")?.textContent)).toEqual(["py3-none-any", "manylinux_2_17_x86_64", "manylinux_2_28_x86_64"])
    expect(rows()[0].querySelector("[data-tag]")).toHaveClass("font-mono")
  })

  it("reads manylinux aliases as their glibc", () => {
    expect(wheelPlatform("a-1-cp311-cp311-manylinux1_x86_64.whl")).toEqual({ key: "manylinux_2_5_x86_64", words: "Linux x86_64, glibc 2.5 and later", tag: "manylinux_2_5_x86_64" })
    expect(wheelPlatform("a-1-cp311-cp311-manylinux2010_x86_64.whl")).toEqual({ key: "manylinux_2_12_x86_64", words: "Linux x86_64, glibc 2.12 and later", tag: "manylinux_2_12_x86_64" })
    expect(wheelPlatform("a-1-cp311-cp311-manylinux2014_aarch64.whl")).toEqual({ key: "manylinux_2_17_aarch64", words: "Linux aarch64, glibc 2.17 and later", tag: "manylinux_2_17_aarch64" })
    // A wheel with several platform tags counts under its first.
    expect(wheelPlatform("a-1-cp311-cp311-manylinux2014_x86_64.manylinux_2_28_x86_64.whl").key).toBe("manylinux_2_17_x86_64")

    render(<PipWheels result={SET} />)
    // The 2 manylinux2014 wheels join the 5 that name manylinux_2_17 first.
    expect(within(platform("Linux x86_64, glibc 2.17 and later")).getByText("7")).toBeDefined()
  })

  it("names a platform outside manylinux by its tag", () => {
    expect(wheelPlatform("a-1-cp311-cp311-musllinux_1_2_x86_64.whl")).toEqual({ key: "musllinux_1_2_x86_64", words: "Linux x86_64, musl 1.2 and later", tag: "musllinux_1_2_x86_64" })
    expect(wheelPlatform("a-1-cp311-cp311-win_amd64.whl")).toEqual({ key: "win_amd64", words: "win_amd64", tag: "win_amd64" })
  })
})

describe("the wheels block", () => {
  it("counts source distributions at 0", () => {
    render(<PipWheels result={SET} />)
    const sdists = within(block()).getByText("Source distributions").closest("[data-sdists]") as HTMLElement
    expect(sdists).toHaveTextContent(/^Source distributions\s*0$/)
    expect(sdists.querySelector(".lucide-circle-check")).not.toBeNull()
    expect(sdists.querySelector("button")).toBeNull()
  })

  it("totals wheels and size", () => {
    render(<PipWheels result={SET} />)
    expect(platform("Any platform")).toHaveTextContent(/3\s*wheels\s*3\.0 MB/)
    expect(platform("Linux x86_64, glibc 2.17 and later")).toHaveTextContent(/7\s*wheels\s*14\.0 MB/)
    const total = within(block()).getByText("Total").closest("[data-total]") as HTMLElement
    expect(total).toHaveTextContent("what Seal downloads")
    expect(total).toHaveTextContent(/11\s*wheels\s*21\.0 MB/)
    expect(within(total).getByText("11")).toHaveClass("figure")
  })

  it("opens a platform's wheels, 5 then Show all", () => {
    render(<PipWheels result={SET} />)
    const row = platform("Linux x86_64, glibc 2.17 and later")
    expect(row).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText(`native0-1.0.0-${MANYLINUX}.whl`)).toBeNull()
    fireEvent.click(row)
    expect(row).toHaveAttribute("aria-expanded", "true")
    const list = row.closest("[data-platform]")?.querySelector("[data-wheel-list]") as HTMLElement
    expect(list.querySelectorAll("[data-wheel]")).toHaveLength(5)
    const first = within(list).getByText(`native0-1.0.0-${MANYLINUX}.whl`)
    expect(first).toHaveClass("[overflow-wrap:anywhere]")
    expect(first.closest("[data-wheel]")).toHaveTextContent("2.0 MB")
    fireEvent.click(within(list).getByRole("button", { name: "Show all 7 wheels" }))
    expect(list.querySelectorAll("[data-wheel]")).toHaveLength(7)
    expect(within(list).queryByRole("button", { name: /^Show all/ })).toBeNull()
    fireEvent.click(row)
    expect(row).toHaveAttribute("aria-expanded", "false")
  })

  it("lists every wheel of a platform with 5 or fewer, with no Show all", () => {
    render(<PipWheels result={SET} />)
    fireEvent.click(platform("Any platform"))
    expect(within(block()).getAllByText(/^pure\d-1\.0\.0-py3-none-any\.whl$/)).toHaveLength(3)
    expect(within(block()).queryByRole("button", { name: /^Show all/ })).toBeNull()
  })

  it("explains wheel from the block's head", () => {
    render(<PipWheels result={SET} />)
    const head = within(block()).getByRole("heading", { name: /^Wheels for/ })
    expect(head.textContent).toMatch(/Wheels for Python 3\.11\.2 · linux x86_64 · glibc 2\.28/)
    const terms = screen.getAllByRole("button", { name: "What a wheel is" })
    expect(terms).toHaveLength(1)
    expect(head.parentElement).toContainElement(terms[0])
    expect(terms[0]).toHaveAttribute("aria-expanded", "false")
  })

  it("draws 5 platforms and 1,284 wheels", () => {
    const tags = ["py3-none-any", "cp311-cp311-manylinux_2_5_x86_64.manylinux1_x86_64", MANYLINUX, "cp311-cp311-manylinux_2_24_x86_64", "cp311-cp311-manylinux_2_28_x86_64"]
    const counts = [1046, 41, 168, 6, 23]
    const longest = "acme_ledger_reconciliation_opentelemetry_exporter_postgresql-1.4.0-cp311-cp311-manylinux_2_5_x86_64.manylinux1_x86_64.whl"
    const packages = tags.flatMap((tag, t) => Array.from({ length: counts[t] }, (_, i) => pkg(`lib${t}-${i}`, tag, 1_800_000)))
    packages[1046] = { ...packages[1046], wheel: { ...packages[1046].wheel!, file: longest } }
    render(<PipWheels result={resultOf(packages)} />)
    expect(rows()).toHaveLength(5)
    expect(rows().map((row) => row.querySelector("[data-words]")?.textContent)).toEqual([
      "Any platform",
      "Linux x86_64, glibc 2.5 and later",
      "Linux x86_64, glibc 2.17 and later",
      "Linux x86_64, glibc 2.24 and later",
      "Linux x86_64, glibc 2.28 and later",
    ])
    const total = within(block()).getByText("Total").closest("[data-total]") as HTMLElement
    expect(total).toHaveTextContent(/1,284\s*wheels\s*2\.2 GB/)
    fireEvent.click(platform("Linux x86_64, glibc 2.5 and later"))
    expect(within(block()).getByText(longest)).toHaveClass("[overflow-wrap:anywhere]")
    fireEvent.click(within(block()).getByRole("button", { name: "Show all 41 wheels" }))
    expect(block().querySelectorAll("[data-wheel]")).toHaveLength(41)
  })
})
