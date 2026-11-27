import { ChevronDown, CircleCheck, List, Package } from "lucide-react"
import { useId, useState } from "react"

import { Button } from "@/components/ui/button"
import { Term } from "@/components/ui/term"
import type { PipAnalysisResult } from "@/lib/pipReview"
import { cn, formatBytes } from "@/lib/utils"

// The glibc each legacy manylinux tag stands for, as PEP 600 maps them.
const ALIASES: Record<string, string> = { manylinux1: "2_5", manylinux2010: "2_12", manylinux2014: "2_17" }
// A platform lists this many wheels before Show all.
const FIRST_WHEELS = 5

/**
 * A wheel's platform, read from its file name: the key its row groups by, the words a reader knows and the
 * tag in PEP 600 form. A file with several platform tags counts under its first.
 */
export function wheelPlatform(file: string): { key: string; words: string; tag: string } {
  const parts = file.replace(/\.whl$/, "").split("-")
  const platform = (parts.at(-1) ?? "").split(".")[0]
  if (platform === "any") return { key: "any", words: "Any platform", tag: parts.slice(-3).join("-") }
  const alias = platform.match(/^(manylinux1|manylinux2010|manylinux2014)_(.+)$/)
  const tag = alias ? `manylinux_${ALIASES[alias[1]]}_${alias[2]}` : platform
  const linux = tag.match(/^(manylinux|musllinux)_(\d+)_(\d+)_(.+)$/)
  if (!linux) return { key: tag, words: tag, tag }
  const libc = linux[1] === "manylinux" ? "glibc" : "musl"
  return { key: tag, words: `Linux ${linux[4]}, ${libc} ${linux[2]}.${linux[3]} and later`, tag }
}

const COUNT = new Intl.NumberFormat("en-US")
const COLUMNS = "grid grid-cols-[minmax(0,1fr)_4.5rem_5.5rem_1rem] items-center gap-x-3 sm:grid-cols-[minmax(0,1fr)_6rem_7rem_1rem]"
const mono = "font-mono text-[12.5px] [font-variant-ligatures:none] [overflow-wrap:anywhere]"

interface Platform {
  key: string
  words: string
  tags: string[]
  wheels: { file: string; size: number }[]
  size: number
}

function platformsOf(result: PipAnalysisResult): Platform[] {
  const byKey = new Map<string, Platform>()
  for (const pkg of result.packages) {
    if (!pkg.wheel) continue
    const { key, words, tag } = wheelPlatform(pkg.wheel.file)
    const platform = byKey.get(key) ?? { key, words, tags: [], wheels: [], size: 0 }
    if (!platform.tags.includes(tag)) platform.tags.push(tag)
    platform.wheels.push({ file: pkg.wheel.file, size: pkg.wheel.size })
    platform.size += pkg.wheel.size
    byKey.set(key, platform)
  }
  // Any platform first, then each tag in order, its glibc read as numbers: 2.5 before 2.17.
  return [...byKey.values()].sort((a, b) => (a.key === "any" ? -1 : b.key === "any" ? 1 : a.key.localeCompare(b.key, "en", { numeric: true })))
}

/**
 * What Seal downloads, before it does: a row per platform with its wheels and their size, opening on its
 * wheels, the source distributions at 0, since none crosses, and the total.
 */
export function PipWheels({ result }: { result: PipAnalysisResult }) {
  const headId = useId()
  const platforms = platformsOf(result)
  const [open, setOpen] = useState<Set<string>>(new Set())
  const wheels = platforms.reduce((sum, platform) => sum + platform.wheels.length, 0)
  const size = platforms.reduce((sum, platform) => sum + platform.size, 0)
  const target = result.target

  function toggle(key: string) {
    setOpen((was) => {
      const next = new Set(was)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  return (
    <section aria-labelledby={headId} className="mb-3 overflow-hidden rounded-xl border border-rule bg-bg">
      <div className="flex min-h-12 items-center gap-2.5 border-b border-rule bg-canvas px-4 py-2">
        <Package aria-hidden="true" className="size-4 flex-none text-ink-2" />
        <h2 id={headId} className="min-w-0 flex-1 text-[15px] font-normal text-ink-2 [overflow-wrap:anywhere]">
          Wheels for Python <span className="figure text-ink">{target.python}</span> · {target.os} {target.cpu} · glibc <span className="figure text-ink">{target.glibc}</span>
        </h2>
        <Term id="wheel" prefer="above" />
      </div>
      <div aria-hidden="true" className={cn(COLUMNS, "border-b border-rule px-4 py-2 text-xs font-semibold text-muted")}>
        <span>Platform</span>
        <span className="text-right">Wheels</span>
        <span className="text-right">Size</span>
        <span />
      </div>
      <ul>
        {platforms.map((platform) => (
          <PlatformRow key={platform.key} platform={platform} open={open.has(platform.key)} onToggle={() => toggle(platform.key)} />
        ))}
        <li data-sdists className={cn(COLUMNS, "min-h-12 border-b border-rule px-4 py-2.5 text-[15px] text-ink")}>
          <span className="flex items-center gap-2">
            <CircleCheck aria-hidden="true" className="size-4 flex-none text-ok" />
            Source distributions
          </span>
          <span className="text-right text-ink-2 tabular-nums">0</span>
        </li>
        <li data-total className={cn(COLUMNS, "border-t border-rule px-4 py-3")}>
          <span>
            <span className="block font-semibold text-ink">Total</span>
            <span className="block text-[13px] text-muted">what Seal downloads</span>
          </span>
          <span className="text-right">
            <span className="figure text-ink">{COUNT.format(wheels)}</span>
            <span className="sr-only"> wheels</span>
          </span>
          <span className="figure text-right text-ink">{formatBytes(size)}</span>
        </li>
      </ul>
    </section>
  )
}

function PlatformRow({ platform, open, onToggle }: { platform: Platform; open: boolean; onToggle: () => void }) {
  const [all, setAll] = useState(false)
  const shown = all ? platform.wheels : platform.wheels.slice(0, FIRST_WHEELS)
  return (
    <li data-platform={platform.key} className="border-b border-rule">
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className={cn(COLUMNS, "min-h-14 w-full px-4 py-2 text-left transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover")}
      >
        <span className="min-w-0">
          <span data-words className="block text-[15px] text-ink [overflow-wrap:anywhere]">
            {platform.words}
          </span>
          <span data-tag className={cn(mono, "block text-muted")}>
            {platform.tags.join(", ")}
          </span>
        </span>
        <span className="text-right">
          <span className="figure text-ink">{COUNT.format(platform.wheels.length)}</span>
          <span className="sr-only"> wheels</span>
        </span>
        <span className="figure text-right text-ink">{formatBytes(platform.size)}</span>
        <ChevronDown aria-hidden="true" className={cn("size-4 flex-none text-muted transition-transform duration-200 ease-out motion-reduce:transition-none", !open && "-rotate-90")} />
      </button>
      {open ? (
        <div data-wheel-list className="animate-fade px-4 pb-3">
          <ul>
            {shown.map((wheel) => (
              <li key={wheel.file} data-wheel className="grid grid-cols-[minmax(0,1fr)_auto] items-baseline gap-x-3 border-t border-rule py-2">
                <span className={cn(mono, "text-ink-2")}>{wheel.file}</span>
                <span className="text-[13px] text-ink-2 tabular-nums">{formatBytes(wheel.size)}</span>
              </li>
            ))}
          </ul>
          {platform.wheels.length > FIRST_WHEELS && !all ? (
            <Button type="button" variant="outline" size="sm" className="mt-1" onClick={() => setAll(true)}>
              <List aria-hidden="true" />
              {`Show all ${COUNT.format(platform.wheels.length)} wheels`}
            </Button>
          ) : null}
        </div>
      ) : null}
    </li>
  )
}
