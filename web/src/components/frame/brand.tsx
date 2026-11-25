import { Globe, Unplug, Users } from "lucide-react"
import { createContext, type ReactNode, useContext, useEffect } from "react"

import type { components } from "@/api/schema"
import { Mark } from "@/components/brand/Mark"

export type Brand = components["schemas"]["Brand"]

/** What the interface shows when the deployment sets nothing: the only place these values are written. */
export const DEFAULT_BRAND: Brand = { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false }

/** The page colours of the light and dark themes, which the accent must reach 3:1 against. */
export const PAGE = { light: "#ffffff", dark: "#111113" }

const BrandContext = createContext<Brand>(DEFAULT_BRAND)

/** Gives the deployment's brand to the screens, names the document after it and sets the accent per theme where it reads. */
export function BrandProvider({ brand, children }: { brand: Brand; children: ReactNode }) {
  useEffect(() => {
    document.title = brand.name
  }, [brand.name])

  useEffect(() => {
    const root = document.documentElement.style
    for (const theme of ["light", "dark"] as const) {
      const { color } = usableAccent(brand.accent, PAGE[theme])
      if (color) root.setProperty(`--brand-${theme}`, color)
      else root.removeProperty(`--brand-${theme}`)
    }
    return () => {
      root.removeProperty("--brand-light")
      root.removeProperty("--brand-dark")
    }
  }, [brand.accent])

  return <BrandContext value={brand}>{children}</BrandContext>
}

export function useBrand(): Brand {
  return useContext(BrandContext)
}

/** The deployment's logo, served by the instance and drawn as an image only, or today's mark, still. */
export function BrandMark({ size }: { size: number }) {
  const brand = useBrand()
  if (brand.logo) {
    return <img src="/api/instance/logo" alt="" width={size} height={size} className="block object-contain" style={{ width: size, height: size }} />
  }
  return (
    <span aria-hidden="true" className="inline-grid">
      <Mark size={size} />
    </span>
  )
}

/** The side this screen belongs to: a globe for the connected side, an unplugged plug for the air-gapped one. */
export function SideLabel({ side }: { side: "online" | "offline" }) {
  const brand = useBrand()
  const Icon = side === "online" ? Globe : Unplug
  return (
    <span className="inline-flex min-h-7 max-w-full min-w-0 items-center gap-1.5 rounded-full border border-rule-2 px-2.5 text-[13px] text-muted">
      <Icon aria-hidden="true" className="size-3.5 flex-none" />
      <span className="[overflow-wrap:anywhere]">{side === "online" ? brand.online : brand.offline}</span>
    </span>
  )
}

const HEX = /^#([0-9a-f]{6})$/i

function luminance(hex: string): number {
  const value = Number.parseInt(hex.slice(1), 16)
  const [r, g, b] = [value >> 16, (value >> 8) & 0xff, value & 0xff].map((c) => {
    const s = c / 255
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** The WCAG contrast ratio of two colours written #rrggbb, from 1 to 21. */
export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

/** The accent where it reaches 3:1 against the page, else null so the ink takes its place, with the ratio measured. */
export function usableAccent(accent: string | undefined, page: string): { color: string | null; ratio: number } {
  if (!accent || !HEX.test(accent)) return { color: null, ratio: 0 }
  const ratio = contrastRatio(accent, page)
  return { color: ratio >= 3 ? accent : null, ratio }
}

/** The last resort after a failure: who to see, from the brand's contact when it names one. It offers no action. */
export function ContactCard() {
  const brand = useBrand()
  return (
    <div className="mt-4 grid grid-cols-[40px_minmax(0,1fr)] items-center gap-3.5 rounded-xl border border-dashed border-rule px-3.5 py-3">
      <span className="grid size-10 place-items-center rounded-[10px] bg-hover text-ink-2">
        <Users aria-hidden="true" className="size-4.5" />
      </span>
      <div className="min-w-0">
        <p className="text-xs font-semibold text-muted">Still failing after a few tries?</p>
        <p className="font-semibold text-ink [overflow-wrap:anywhere]">{brand.contact?.label ?? "See your administrators"}</p>
      </div>
    </div>
  )
}
